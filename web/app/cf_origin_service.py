"""Origin CA (Cloudflare Full strict) — cert wildcard del ORIGEN.

Modo `cf_origin` del dominio de tenants: en vez de emitir certs con Let's Encrypt
(Caddy HTTP-01 o Certbot DNS-01), el TLS público lo termina **Cloudflare en su
borde** (Universal SSL, gratis y auto-renovable). Entre Cloudflare y este VPS se
usa un certificado **Cloudflare Origin CA** (wildcard `*.<dominio>`, válido ~15
años) que Caddy sirve vía `tls`. La zona queda en modo **Full (strict)**, así el
tráfico va cifrado y validado extremo a extremo.

A diferencia de certbot, el cert NO se renueva cada 60 días (dura 15 años) y no
depende de Let's Encrypt ni de sus rate-limits. Los registros de tenant van en
**nube naranja** (proxied) — Cloudflare esconde la IP del VPS y aporta su WAF/DDoS.

El cert lo genera el usuario una sola vez en el dashboard de Cloudflare
(SSL/TLS → Origin Server → Create Certificate, hostnames `<dominio>` + `*.<dominio>`)
y lo pega en el panel; acá se valida y se guarda en `/opt/kumavpn/letsencrypt/origin/`
(cert.pem 0644, key.pem 0600). El container Caddy monta ese dir en `/certs` (RO) y
el Caddyfile referencia `/certs/origin/cert.pem` + `/certs/origin/key.pem`.
"""
import time
from pathlib import Path

import config

ORIGIN_DIR = config.BASE_PATH / "letsencrypt" / "origin"
CERT_FILE = ORIGIN_DIR / "cert.pem"
KEY_FILE = ORIGIN_DIR / "key.pem"
# Path del dir de certs DENTRO del container Caddy (mount de /opt/kumavpn/letsencrypt).
CADDY_CERTS_MOUNT = "/certs"


def cert_exists() -> bool:
    return CERT_FILE.exists() and KEY_FILE.exists()


def cert_paths_for_caddy() -> tuple:
    """(cert, key) como los ve el container Caddy (mount /certs)."""
    return f"{CADDY_CERTS_MOUNT}/origin/cert.pem", f"{CADDY_CERTS_MOUNT}/origin/key.pem"


def _parse_cert(pem: str):
    """Devuelve el objeto x509.Certificate o lanza ValueError con mensaje claro."""
    from cryptography import x509
    try:
        return x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"El certificado no es un PEM válido: {e}")


def _parse_key(pem: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    try:
        return load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception as e:
        raise ValueError(f"La clave privada no es un PEM válido (o está cifrada): {e}")


def validate(cert_pem: str, key_pem: str) -> None:
    """Valida que cert y key sean PEM correctos y que la key corresponda al cert.
    Lanza ValueError con un mensaje entendible si algo no cuadra."""
    from cryptography.hazmat.primitives import serialization

    cert = _parse_cert(cert_pem)
    key = _parse_key(key_pem)
    # La clave pública del cert debe coincidir con la de la private key.
    def _pub_bytes(pub):
        return pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    if _pub_bytes(cert.public_key()) != _pub_bytes(key.public_key()):
        raise ValueError("La clave privada NO corresponde a este certificado.")


def save_cert(cert_pem: str, key_pem: str) -> tuple:
    """Valida y guarda el par cert/key del Origin CA. Devuelve (ok, mensaje)."""
    cert_pem = (cert_pem or "").strip() + "\n"
    key_pem = (key_pem or "").strip() + "\n"
    if not cert_pem.strip() or not key_pem.strip():
        return False, "Pegá el certificado Y la clave privada."
    try:
        validate(cert_pem, key_pem)
    except ValueError as e:
        return False, str(e)
    try:
        ORIGIN_DIR.mkdir(parents=True, exist_ok=True)
        CERT_FILE.write_text(cert_pem, encoding="utf-8")
        CERT_FILE.chmod(0o644)
        KEY_FILE.write_text(key_pem, encoding="utf-8")
        KEY_FILE.chmod(0o600)
    except Exception as e:
        return False, f"No pude escribir los archivos del cert: {e}"
    st = status()
    return True, f"Cert de origen guardado (vence {st.get('not_after', '?')})."


def status() -> dict:
    """Estado del cert de origen para la UI: existe, emisor, vencimiento."""
    st = {"exists": False, "not_after": "", "issuer": "", "hostnames": ""}
    if not cert_exists():
        return st
    st["exists"] = True
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(CERT_FILE.read_text(encoding="utf-8").encode())
        st["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        try:
            st["issuer"] = cert.issuer.rfc4514_string()
        except Exception:
            st["issuer"] = ""
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            st["hostnames"] = ", ".join(san.value.get_values_for_type(x509.DNSName))
        except Exception:
            st["hostnames"] = ""
    except Exception:
        # cert ilegible: reportar mtime como referencia mínima
        st["not_after"] = time.strftime("%Y-%m-%d", time.localtime(CERT_FILE.stat().st_mtime))
    return st
