"""SSL por API — certificado wildcard real vía Certbot + DNS-01 de Cloudflare.

Modo `certbot` del dominio de tenants: en vez de que Caddy emita un cert por
subdominio (HTTP-01), se pide UN cert wildcard (`<dominio>` + `*.<dominio>`)
con validación DNS-01. El plugin dns-cloudflare crea/borra el TXT temporal
usando el mismo token scoped guardado en settings (cifrado). Ventajas:

- Un solo registro DNS (el wildcard `*.<dominio>`) en vez de uno por tenant.
- Los tenants nuevos sirven HTTPS al instante (el cert ya los cubre).
- Funciona con proxy de Cloudflare (nube naranja) — HTTP-01 no.

Certbot NO se instala en la imagen del panel: se ejecuta con la imagen oficial
`certbot/dns-cloudflare` vía docker (el panel ya tiene el socket montado), con
`/opt/kumavpn/letsencrypt` como `/etc/letsencrypt`. Como el panel monta
`/opt/kumavpn` en el mismo path, puede escribir el `cloudflare.ini` (0600) y
ver los certs; el container Caddy monta ese dir en `/certs` (read-only) y el
Caddyfile referencia `/certs/live/<dominio>/fullchain.pem`.

Renovación: hilo diario (main.py startup) que corre `certbot renew` — no-op
salvo que falten <30 días — y recarga Caddy si hubo renovación.
"""
import logging
import subprocess
import threading
import time

import config
import settings_service

log = logging.getLogger(__name__)

LE_DIR = config.BASE_PATH / "letsencrypt"
CREDS_FILE = LE_DIR / "cloudflare.ini"
CERTBOT_IMAGE = "certbot/dns-cloudflare:latest"
# Path del dir de certs DENTRO del container Caddy (ver docker-compose / installers).
CADDY_CERTS_MOUNT = "/certs"

_RENEW_INTERVAL_S = 24 * 3600


def cert_name() -> str:
    """Lineage de certbot = dominio de tenants (cubre dominio + wildcard)."""
    return settings_service.get_network_config().get("tenants_domain", "").strip()


def cert_exists() -> bool:
    name = cert_name()
    return bool(name) and (LE_DIR / "live" / name / "fullchain.pem").exists()


def cert_paths_for_caddy() -> tuple:
    """(fullchain, privkey) como los ve el container Caddy (mount /certs)."""
    name = cert_name()
    base = f"{CADDY_CERTS_MOUNT}/live/{name}"
    return f"{base}/fullchain.pem", f"{base}/privkey.pem"


def status() -> dict:
    """Estado para la UI: existe el cert, cuándo se emitió/renovó."""
    name = cert_name()
    st = {"exists": False, "name": name, "issued_at": ""}
    if not name:
        return st
    fc = LE_DIR / "live" / name / "fullchain.pem"
    if fc.exists():
        st["exists"] = True
        st["issued_at"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(fc.stat().st_mtime))
    return st


def _write_creds(token: str) -> None:
    LE_DIR.mkdir(parents=True, exist_ok=True)
    CREDS_FILE.write_text(f"dns_cloudflare_api_token = {token}\n", encoding="utf-8")
    CREDS_FILE.chmod(0o600)


def _run_certbot(args: list, timeout: int = 600) -> tuple:
    """Corre certbot en su container oficial (one-shot). Devuelve (ok, output).
    El -v usa el path del HOST (= mismo path en el panel: /opt/kumavpn)."""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{LE_DIR}:/etc/letsencrypt",
        CERTBOT_IMAGE,
    ] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        return r.returncode == 0, out.strip()
    except subprocess.TimeoutExpired:
        return False, f"certbot excedió {timeout}s"
    except Exception as e:
        return False, f"no pude ejecutar certbot: {e}"


def issue() -> tuple:
    """Emite (o mantiene si aún es válido) el cert wildcard del dominio de tenants.
    Devuelve (ok, mensaje). Bloquea ~30-90s la primera vez (propagación DNS-01)."""
    domain = cert_name()
    if not domain:
        return False, "Configurá primero el dominio de tenants."
    token = settings_service.get_cloudflare_config()["token"]
    if not token:
        return False, "Falta el token de API de Cloudflare (lo usa el DNS-01)."
    email = settings_service.get_network_config().get("caddy_email", "").strip()
    _write_creds(token)
    args = [
        "certonly",
        "--dns-cloudflare",
        "--dns-cloudflare-credentials", "/etc/letsencrypt/cloudflare.ini",
        "--dns-cloudflare-propagation-seconds", "30",
        "-d", domain, "-d", f"*.{domain}",
        "--cert-name", domain,
        "--keep-until-expiring",
        "--non-interactive", "--agree-tos",
    ]
    args += ["-m", email] if email else ["--register-unsafely-without-email"]
    ok, out = _run_certbot(args)
    if ok:
        return True, f"Cert wildcard OK para {domain} + *.{domain}."
    # última línea útil del error para el flash
    tail = [l for l in out.splitlines() if l.strip()][-3:]
    return False, "certbot falló: " + " | ".join(tail)


def renew() -> tuple:
    """`certbot renew` — no-op salvo que el cert esté por vencer.
    Devuelve (renovado: bool, output)."""
    token = settings_service.get_cloudflare_config()["token"]
    if token:
        _write_creds(token)  # refrescar por si el token rotó
    ok, out = _run_certbot(["renew", "--non-interactive"], timeout=900)
    renewed = ok and ("Congratulations" in out or "renewed" in out.lower()) \
        and "No renewals were attempted" not in out
    if not ok:
        log.warning("certbot renew falló: %s", out[-400:])
    return renewed, out


def _renewal_loop():
    while True:
        time.sleep(_RENEW_INTERVAL_S)
        try:
            if settings_service.get_tenants_ssl_mode() != "certbot" or not cert_exists():
                continue
            renewed, _ = renew()
            if renewed:
                import caddy_service
                ok, msg = caddy_service.reload_caddy()
                log.info("cert renovado; caddy reload: %s (%s)", ok, msg)
        except Exception:
            log.exception("renewal loop")


def start_renewal_thread() -> None:
    threading.Thread(target=_renewal_loop, daemon=True, name="certbot-renew").start()
