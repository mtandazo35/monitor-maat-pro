from typing import Optional

import config
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
        "password": get("smtp_password", config.SMTP_PASSWORD),
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
        set_value("smtp_password", password)
    set_value("smtp_from", sender.strip())
    set_value("smtp_security", security)
    set_value("public_url", public_url.strip())


def get_telegram_config() -> dict:
    return {
        "bot_token": get("telegram_bot_token", ""),
        "admin_chat_id": get("telegram_admin_chat_id", ""),
    }


def save_telegram_config(bot_token: Optional[str], admin_chat_id: str) -> None:
    if bot_token:
        set_value("telegram_bot_token", bot_token.strip())
    set_value("telegram_admin_chat_id", admin_chat_id.strip())
