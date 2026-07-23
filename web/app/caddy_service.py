"""Generación y aplicación automática del Caddyfile para dominios + TLS.

Caddy maneja automáticamente:
- Let's Encrypt para cert SSL del panel principal y de cada subdominio de tenant
- Reverse proxy de cada subdominio al puerto correcto del Uptime Kuma

El Caddyfile se escribe a /opt/kumavpn/caddy/Caddyfile (path montado como
volumen tanto en este container como en el container caddy-monitormaat).
Cuando algo cambia (config, tenants), llamamos `caddy reload` via docker exec.
"""
import subprocess
from pathlib import Path

import settings_service
import tenant_service as svc

CADDY_DIR = Path("/opt/kumavpn/caddy")
CADDYFILE = CADDY_DIR / "Caddyfile"
CADDY_CONTAINER = "caddy-monitormaat"


def is_configured() -> bool:
    """True si está configurado al menos uno de los dominios."""
    cfg = settings_service.get_network_config()
    return bool(cfg.get("panel_domain") or cfg.get("tenants_domain"))


def generate_caddyfile() -> str:
    """Genera el contenido completo del Caddyfile basado en config + tenants.

    El PANEL va siempre con cert automático de Caddy (HTTP-01). Los TENANTS
    dependen del modo:
    - caddy / cf_auto → cert automático por subdominio (HTTP-01)
    - certbot → cert wildcard emitido por certbot (DNS-01), referenciado con
      `tls` desde /certs (mount read-only de /opt/kumavpn/letsencrypt)
    - cf_origin → cert wildcard Cloudflare Origin CA, referenciado con `tls`
      desde /certs/origin (Cloudflare termina el TLS público en su borde)
    """
    cfg = settings_service.get_network_config()
    panel_domain = cfg.get("panel_domain", "").strip()
    tenants_domain = cfg.get("tenants_domain", "").strip()
    email = cfg.get("caddy_email", "").strip()
    ssl_mode = cfg.get("tenants_ssl_mode", "caddy")

    # tls con el cert wildcard (certbot o cf_origin) solo si el cert ya existe (si
    # no, Caddy no arrancaría apuntando a archivos inexistentes — fallback a HTTP-01).
    tls_line = ""
    if ssl_mode == "certbot":
        import certbot_service
        if certbot_service.cert_exists():
            fullchain, privkey = certbot_service.cert_paths_for_caddy()
            tls_line = f"    tls {fullchain} {privkey}"
    elif ssl_mode == "cf_origin":
        import cf_origin_service
        if cf_origin_service.cert_exists():
            cert, key = cf_origin_service.cert_paths_for_caddy()
            tls_line = f"    tls {cert} {key}"

    lines: list[str] = [
        "# Caddyfile generado automáticamente por MonitorMaat",
        "# NO EDITAR A MANO — se sobreescribe al cambiar config o tenants",
        "",
    ]

    # Bloque global con email de Let's Encrypt
    if email:
        lines.extend([
            "{",
            f"    email {email}",
            "}",
            "",
        ])

    # Panel principal (siempre cert automático de Caddy)
    if panel_domain:
        lines.extend([
            f"# Panel admin",
            f"{panel_domain} {{",
            f"    reverse_proxy kumavpn-web:8000",
            f"}}",
            "",
        ])

    # Bloques por tenant
    if tenants_domain:
        try:
            tenants = svc.list_tenants()
        except Exception:
            tenants = []
        for t in tenants:
            block = [
                f"# Tenant: {t['name']} (slot {t['slot']})",
                f"{t['name']}.{tenants_domain} {{",
            ]
            if tls_line:
                block.append(tls_line)
            block.extend([
                f"    reverse_proxy host.docker.internal:{t['kuma_port']}",
                f"}}",
                "",
            ])
            lines.extend(block)

    return "\n".join(lines)


def write_caddyfile() -> tuple[bool, str]:
    """Escribe el Caddyfile en disco. Devuelve (ok, mensaje)."""
    try:
        CADDY_DIR.mkdir(parents=True, exist_ok=True)
        content = generate_caddyfile()
        CADDYFILE.write_text(content, encoding="utf-8")
        return True, f"Caddyfile escrito: {len(content)} bytes"
    except Exception as e:
        return False, f"Error escribiendo Caddyfile: {e}"


def caddy_container_running() -> bool:
    """Verifica si el container caddy-monitormaat está corriendo."""
    try:
        r = subprocess.run(
            ["docker", "ps", "--filter", f"name={CADDY_CONTAINER}",
             "--filter", "status=running", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
        return CADDY_CONTAINER in r.stdout
    except Exception:
        return False


def reload_caddy() -> tuple[bool, str]:
    """Hace reload del Caddyfile en el container Caddy."""
    if not caddy_container_running():
        return False, f"Container '{CADDY_CONTAINER}' no está corriendo (instalar Caddy primero)."
    try:
        r = subprocess.run(
            ["docker", "exec", CADDY_CONTAINER,
             "caddy", "reload", "--config", "/etc/caddy/Caddyfile"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            return True, "Caddy recargado correctamente."
        return False, f"Error al reload: {r.stderr.strip() or r.stdout.strip()}"
    except Exception as e:
        return False, f"Error ejecutando docker exec: {e}"


def apply() -> tuple[bool, str]:
    """Genera + escribe + reload. Devuelve (ok_total, mensaje agregado)."""
    msgs = []
    ok_w, m_w = write_caddyfile()
    msgs.append(m_w)
    if not ok_w:
        return False, " · ".join(msgs)
    if caddy_container_running():
        ok_r, m_r = reload_caddy()
        msgs.append(m_r)
        return ok_r, " · ".join(msgs)
    msgs.append(f"⚠ Container '{CADDY_CONTAINER}' no detectado: archivo escrito pero no aplicado.")
    return True, " · ".join(msgs)
