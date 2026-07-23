from typing import Optional

import config
import crypto
from db import connect


SECURITY_MODES = ("ssl", "tls", "none")


def get(key: str, default: Optional[str] = None) -> Optional[str]:
    with connect() as con:
        row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row and row["value"] is not None else default


def set_value(key: str, value: Optional[str]) -> None:
    with connect() as con:
        con.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def _env_default_security() -> str:
    """Inferir el modo de seguridad desde las flags antiguas del env."""
    if config.SMTP_SSL:
        return "ssl"
    if config.SMTP_TLS:
        return "tls"
    return "none"


def get_smtp_config() -> dict:
    """Devuelve la config SMTP combinando DB > env."""
    return {
        "host":     get("smtp_host",     config.SMTP_HOST),
        "port":     int(get("smtp_port", str(config.SMTP_PORT)) or 0),
        "user":     get("smtp_user",     config.SMTP_USER),
        "password": crypto.decrypt(get("smtp_password", config.SMTP_PASSWORD)),
        "from":     get("smtp_from",     config.SMTP_FROM),
        "security": get("smtp_security", _env_default_security()),
        "public_url": get("public_url",  config.PUBLIC_URL),
    }


def save_smtp_config(host: str, port: int, user: str, password: Optional[str],
                     sender: str, security: str, public_url: str = "") -> None:
    """Guarda config SMTP en DB. Si password es None/vacío, mantiene la anterior."""
    if security not in SECURITY_MODES:
        raise ValueError(f"Modo de seguridad inválido: {security}")
    set_value("smtp_host", host.strip())
    set_value("smtp_port", str(int(port)))
    set_value("smtp_user", user.strip())
    if password:
        set_value("smtp_password", crypto.encrypt(password))
    set_value("smtp_from", sender.strip())
    set_value("smtp_security", security)
    set_value("public_url", public_url.strip())


def get_telegram_config() -> dict:
    return {
        "bot_token": crypto.decrypt(get("telegram_bot_token", "")),
        "admin_chat_id": get("telegram_admin_chat_id", ""),
    }


def save_telegram_config(bot_token: Optional[str], admin_chat_id: str) -> None:
    if bot_token:
        set_value("telegram_bot_token", crypto.encrypt(bot_token.strip()))
    set_value("telegram_admin_chat_id", admin_chat_id.strip())


# Modos SSL/DNS para el dominio de los TENANTS (el panel es SIEMPRE Caddy simple):
#   caddy   — Caddy emite cert por subdominio (HTTP-01). DNS manual (wildcard o por-tenant).
#   cf_auto — el panel crea/borra el registro A de cada tenant vía API Cloudflare;
#             Caddy emite cert por subdominio (HTTP-01). Requiere nube GRIS.
#   certbot — SSL por API: cert wildcard real (*.dominio) vía Certbot DNS-01 con la
#             API de Cloudflare; un solo registro wildcard; tolera nube naranja.
#   cf_origin — Origin CA (Full strict): Cloudflare termina el TLS en su borde
#             (Universal SSL); Caddy sirve un cert wildcard Cloudflare Origin CA
#             (~15 años). Registros por-tenant en nube NARANJA (proxied). Usa el token.
TENANTS_SSL_MODES = ("caddy", "cf_auto", "certbot", "cf_origin")

_DOMAIN_RE_STR = r"^[a-z0-9.-]+\.[a-z]{2,}$"


def get_tenants_ssl_mode() -> str:
    """Modo SSL/DNS de los tenants. Migración: instalaciones que tenían el
    auto-DNS viejo activado (cf_dns_enabled=1) caen a 'cf_auto'."""
    mode = get("tenants_ssl_mode", "")
    if mode in TENANTS_SSL_MODES:
        return mode
    return "cf_auto" if get("cf_dns_enabled", "0") == "1" else "caddy"


def get_network_config() -> dict:
    """Configuración de red/dominios.
    - panel_domain: dominio del panel admin (ej. 'panel.midominio.com') — SIEMPRE
      servido por Caddy con HTTP-01; separado a propósito de los dominios de clientes.
    - tenants_domain: dominio raíz para los subdominios de tenants
      (ej. 'kuma.midominio.com', cada tenant queda en '<nombre>.kuma.midominio.com')
    - tenants_ssl_mode: caddy | cf_auto | certbot (ver TENANTS_SSL_MODES)
    - caddy_email: email para Let's Encrypt (recibe avisos de expiración)
    - use_https: si los URLs mostrados usan https (default true)

    Si tenants_domain está vacío, los tenants siguen mostrándose con IP:puerto.
    Instalaciones viejas guardaban la clave 'base_domain' — se lee como fallback
    pero ya no se escribe.
    """
    tenants_domain = get("tenants_domain", get("base_domain", ""))
    return {
        "panel_domain": get("panel_domain", ""),
        "tenants_domain": tenants_domain,
        "tenants_ssl_mode": get_tenants_ssl_mode(),
        "caddy_email": get("caddy_email", ""),
        "use_https": get("use_https", "1") == "1",
    }


def save_panel_config(panel_domain: str, caddy_email: str, use_https: bool) -> None:
    """Guarda la config del PANEL admin (dominio + email LE + https). El panel se
    sirve siempre por Caddy (HTTP-01) — solo necesita su registro A apuntando al VPS."""
    import re
    DOMAIN_RE = re.compile(_DOMAIN_RE_STR)
    EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    pd = (panel_domain or "").strip().lower()
    em = (caddy_email or "").strip()

    if pd and not DOMAIN_RE.match(pd):
        raise ValueError("Dominio del panel inválido. Formato 'panel.midominio.com'.")
    if em and not EMAIL_RE.match(em):
        raise ValueError("Email inválido para Let's Encrypt.")

    set_value("panel_domain", pd)
    set_value("caddy_email", em)
    set_value("use_https", "1" if use_https else "0")


def save_tenants_config(tenants_domain: str, ssl_mode: str) -> None:
    """Guarda la config de dominios de los TENANTS (clientes: Kuma + accesos)."""
    import re
    DOMAIN_RE = re.compile(_DOMAIN_RE_STR)

    td = (tenants_domain or "").strip().lower()
    if td and not DOMAIN_RE.match(td):
        raise ValueError("Dominio de tenants inválido. Formato 'kuma.midominio.com'.")
    if ssl_mode not in TENANTS_SSL_MODES:
        raise ValueError(f"Modo SSL inválido: {ssl_mode}")

    set_value("tenants_domain", td)
    set_value("tenants_ssl_mode", ssl_mode)
    # Mantener la flag vieja coherente para código/instalaciones que la lean
    # (cf_auto y cf_origin crean un registro A por tenant vía API).
    set_value("cf_dns_enabled", "1" if ssl_mode in ("cf_auto", "cf_origin") else "0")
    # cf_origin exige nube naranja: forzar el flag para que el proxied quede en 1.
    if ssl_mode == "cf_origin":
        set_value("cf_proxied", "1")


def get_billing_config() -> dict:
    """Configuración global de facturación. Por ahora solo la hora de suspensión:
    si paid_until = hoy, el cliente sigue activo hasta esa hora (Ecuador)."""
    return {
        "suspension_time": get("suspension_time", "23:59"),
    }


def save_billing_config(suspension_time: str) -> None:
    s = (suspension_time or "").strip()
    # Validar formato HH:MM
    if not s or len(s) != 5 or s[2] != ":":
        raise ValueError("Formato hora inválido (use HH:MM)")
    try:
        hh, mm = int(s[:2]), int(s[3:])
        if not (0 <= hh <= 23 and 0 <= mm <= 59):
            raise ValueError
    except ValueError:
        raise ValueError("Hora fuera de rango (00:00 a 23:59)")
    set_value("suspension_time", s)


def get_cloudflare_config() -> dict:
    """Config de la integración con la API de Cloudflare. El token se guarda cifrado.
    `enabled` = el modo de tenants gestiona registros por-tenant (cf_auto).
    El modo certbot también usa el token, pero solo para el wildcard + DNS-01."""
    tok = crypto.decrypt(get("cf_api_token", "")) or ""
    mode = get_tenants_ssl_mode()
    # cf_origin gestiona un registro A por tenant igual que cf_auto, pero SIEMPRE
    # proxied (nube naranja): sin proxy no hay Universal SSL de Cloudflare.
    return {
        "enabled": mode in ("cf_auto", "cf_origin"),
        "token": tok,
        "has_token": bool(tok),
        "proxied": get("cf_proxied", "0") == "1" or mode == "cf_origin",
    }


def save_cloudflare_token(
    token: Optional[str],
    proxied: bool = False,
    clear_token: bool = False,
) -> None:
    """Guarda token/proxied de Cloudflare. Si token es None/vacío mantiene el
    anterior. clear_token=True borra el token guardado."""
    if clear_token:
        set_value("cf_api_token", None)
    elif token:
        set_value("cf_api_token", crypto.encrypt(token.strip()))
    set_value("cf_proxied", "1" if proxied else "0")


def get_payphone_config() -> dict:
    return {
        "token": crypto.decrypt(get("payphone_token", "")),
        "store_id": get("payphone_store_id", ""),
        "api_url": get("payphone_api_url", "https://pay.payphonetodoesposible.com"),
        "public_url": get("public_url", ""),
    }


def save_payphone_config(
    token: Optional[str],
    store_id: str,
    api_url: str = "",
    public_url: str = "",
) -> None:
    """Guarda config PayPhone. Si token es None/vacío, mantiene el anterior."""
    if token:
        set_value("payphone_token", crypto.encrypt(token.strip()))
    set_value("payphone_store_id", store_id.strip())
    if api_url.strip():
        set_value("payphone_api_url", api_url.strip())
    if public_url.strip():
        set_value("public_url", public_url.strip())
