import os
from pathlib import Path

BASE_PATH = Path(os.environ.get("KUMAVPN_BASE_PATH", "/opt/kumavpn"))
TENANTS_DIR = BASE_PATH / "tenants"
DB_PATH = BASE_PATH / "data" / "kumavpn.db"
TEMPLATES_DIR = Path(__file__).parent / "templates"
COMPOSE_TEMPLATE = Path(__file__).parent.parent.parent / "templates" / "tenant-compose.yml.j2"
# When running inside the container, the template lives at /app/compose-template.j2
# (copied by Dockerfile); fall back to that location.
if not COMPOSE_TEMPLATE.exists():
    COMPOSE_TEMPLATE = Path("/app/compose-template.j2")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-me-please-32chars-minimum")

# Interfaz donde se publica el puerto Kuma de cada tenant. Default 0.0.0.0 (compat);
# 127.0.0.1 lo cierra al reverse proxy local (evita exponer el wizard sin-auth).
KUMA_BIND = os.environ.get("KUMA_BIND", "0.0.0.0").strip() or "0.0.0.0"

PUBLIC_IP = os.environ.get("PUBLIC_IP", "").strip()

VPN_PORT_BASE = int(os.environ.get("VPN_PORT_BASE", "1193"))
KUMA_PORT_BASE = int(os.environ.get("KUMA_PORT_BASE", "3000"))
VPN_SUBNET_PREFIX = os.environ.get("VPN_SUBNET_PREFIX", "100.64")
DOCKER_SUBNET_PREFIX = os.environ.get("DOCKER_SUBNET_PREFIX", "172.30")

# --- WireGuard (segundo protocolo, mismo contenedor/netns que OpenVPN) ---
# Puerto UDP por tenant = WG_PORT_BASE + slot. Subred propia por tenant para no
# solaparse con la de OpenVPN (VPN_SUBNET_PREFIX).
WG_PORT_BASE = int(os.environ.get("WG_PORT_BASE", "51820"))
WG_SUBNET_PREFIX = os.environ.get("WG_SUBNET_PREFIX", "100.65")

MAX_TENANTS = 254

# --- SMTP (opcional; si SMTP_HOST está vacío, los emails se loguean en flash) ---
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587") or "587")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "kumavpn@localhost")
SMTP_TLS = os.environ.get("SMTP_TLS", "true").lower() in ("true", "1", "yes")
SMTP_SSL = os.environ.get("SMTP_SSL", "false").lower() in ("true", "1", "yes")

# URL pública del panel (para incluir en los emails). Si está vacía, usa http://PUBLIC_IP:ADMIN_PORT
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").strip()
