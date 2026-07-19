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


def get_network_config() -> dict:
    """Configuración de red/dominios.
    - panel_domain: dominio del panel principal (ej. 'panel.midominio.com')
    - tenants_domain: dominio raíz para los subdominios de tenants
      (ej. 'kuma.midominio.com', cada tenant queda en '<nombre>.kuma.midominio.com')
    - caddy_email: email para Let's Encrypt (recibe avisos de expiración)
    - use_https: si los URLs mostrados usan https (default true)

    Si tenants_domain está vacío, los tenants siguen mostrándose con IP:puerto.
    base_domain se mantiene como alias legacy de tenants_domain.
    """
    tenants_domain = get("tenants_domain", get("base_domain", ""))
    return {
        "panel_domain": get("panel_domain", ""),
        "tenants_domain": tenants_domain,
        "base_domain": tenants_domain,  # alias legacy
        "caddy_email": get("caddy_email", ""),
        "use_https": get("use_https", "1") == "1",
    }


def save_network_config(
    panel_domain: str,
    tenants_domain: str,
    caddy_email: str,
    use_https: bool,
) -> None:
    import re
    DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
    EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    pd = (panel_domain or "").strip().lower()
    td = (tenants_domain or "").strip().lower()
    em = (caddy_email or "").strip()

    if pd and not DOMAIN_RE.match(pd):
        raise ValueError("Dominio del panel inválido. Formato 'panel.midominio.com'.")
    if td and not DOMAIN_RE.match(td):
        raise ValueError("Dominio de tenants inválido. Formato 'kuma.midominio.com'.")
    if em and not EMAIL_RE.match(em):
        raise ValueError("Email inválido para Let's Encrypt.")

    set_value("panel_domain", pd)
    set_value("tenants_domain", td)
    set_value("base_domain", td)  # mantener alias para compat
    set_value("caddy_email", em)
    set_value("use_https", "1" if use_https else "0")


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
    """Config de la integración DNS con Cloudflare. El token se guarda cifrado."""
    tok = crypto.decrypt(get("cf_api_token", "")) or ""
    return {
        "enabled": get("cf_dns_enabled", "0") == "1",
        "token": tok,
        "has_token": bool(tok),
        "proxied": get("cf_proxied", "0") == "1",  # nube naranja (default gris)
    }


def save_cloudflare_config(
    token: Optional[str],
    enabled: bool,
    proxied: bool = False,
    clear_token: bool = False,
) -> None:
    """Guarda config Cloudflare. Si token es None/vacío mantiene el anterior.
    clear_token=True borra el token guardado."""
    if clear_token:
        set_value("cf_api_token", None)
    elif token:
        set_value("cf_api_token", crypto.encrypt(token.strip()))
    set_value("cf_dns_enabled", "1" if enabled else "0")
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
