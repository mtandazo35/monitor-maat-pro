import smtplib
import ssl
from email.message import EmailMessage

import settings_service


class EmailNotConfigured(Exception):
    pass


def is_configured() -> bool:
    cfg = settings_service.get_smtp_config()
    return bool(cfg["host"])


def _login_url(cfg: dict) -> str:
    if cfg.get("public_url"):
        return cfg["public_url"].rstrip("/") + "/login"
    import config
    pub = config.PUBLIC_IP or "127.0.0.1"
    port = config.__dict__.get("ADMIN_PORT", 8000)
    import os
    port = int(os.environ.get("ADMIN_PORT", "8000") or "8000")
    return f"http://{pub}:{port}/login"


def _send(msg: EmailMessage, cfg: dict) -> None:
    host, port = cfg["host"], cfg["port"]
    user, password = cfg["user"], cfg["password"]
    sec = (cfg.get("security") or "tls").lower()

    if sec == "ssl":
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
            if user:
                s.login(user, password or "")
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=15) as s:
            if sec == "tls":
                ctx = ssl.create_default_context()
                s.starttls(context=ctx)
            if user:
                s.login(user, password or "")
            s.send_message(msg)


def send_user_welcome(to_email: str, username: str, password: str, company: str = "") -> None:
    cfg = settings_service.get_smtp_config()
    if not cfg["host"]:
        raise EmailNotConfigured("SMTP no configurado (Settings → SMTP)")

    url = _login_url(cfg)
    msg = EmailMessage()
    msg["Subject"] = "Tu cuenta MonitorMaat está lista"
    msg["From"] = cfg["from"] or cfg["user"]
    msg["To"] = to_email

    body_text = f"""Hola{(' ' + company) if company else ''},

Tu cuenta en MonitorMaat fue creada. Estos son tus accesos:

  URL:      {url}
  Usuario:  {username}
  Password: {password}

IMPORTANTE: por seguridad, al ingresar por primera vez se te va a pedir
cambiar la password. La nueva debe tener:

  - Mínimo 8 caracteres
  - Al menos una mayúscula
  - Al menos una minúscula
  - Al menos un número
  - Al menos un símbolo (! @ # $ % & * + - = ?)

Si no esperabas este correo, ignoralo.

— MonitorMaat
"""
    body_html = f"""<html><body style="font-family: -apple-system, sans-serif; max-width: 560px; padding: 20px;">
<h2 style="color:#0b5394">Tu cuenta MonitorMaat está lista</h2>
<p>Hola{(' <strong>' + company + '</strong>') if company else ''}, tu cuenta fue creada.</p>
<table style="background:#f4f6fa;padding:16px;border-radius:8px;font-family:monospace;font-size:14px">
  <tr><td>URL:</td><td><a href="{url}">{url}</a></td></tr>
  <tr><td>Usuario:</td><td><strong>{username}</strong></td></tr>
  <tr><td>Password:</td><td><strong>{password}</strong></td></tr>
</table>
<p style="color:#b00020"><strong>Importante:</strong> al ingresar por primera vez se te va a pedir
cambiar la password. La nueva debe tener:</p>
<ul>
  <li>Mínimo 8 caracteres</li>
  <li>Al menos una mayúscula, una minúscula, un número y un símbolo</li>
</ul>
<p style="color:#888;font-size:12px">Si no esperabas este correo, ignoralo.</p>
</body></html>
"""
    msg.set_content(body_text)
    msg.add_alternative(body_html, subtype="html")

    _send(msg, cfg)


def send_test(to_email: str) -> None:
    """Envía un email de prueba para validar la configuración SMTP."""
    cfg = settings_service.get_smtp_config()
    if not cfg["host"]:
        raise EmailNotConfigured("SMTP no configurado (Settings → SMTP)")

    msg = EmailMessage()
    msg["Subject"] = "Test SMTP — MonitorMaat"
    msg["From"] = cfg["from"] or cfg["user"]
    msg["To"] = to_email
    msg.set_content(
        f"""Test de configuración SMTP de MonitorMaat.

Si recibiste este mensaje, la configuración SMTP funciona correctamente.

Servidor: {cfg['host']}:{cfg['port']} ({cfg['security'].upper()})
From:     {cfg['from'] or cfg['user']}
"""
    )
    _send(msg, cfg)
