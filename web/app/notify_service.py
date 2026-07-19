"""Notificaciones via Telegram Bot API. Sin dependencias extra (urllib stdlib)."""
import json
import urllib.request
from typing import Optional

import crypto
import settings_service


class NotConfigured(Exception):
    pass


class TelegramError(Exception):
    pass


def is_configured() -> bool:
    return bool(settings_service.get_telegram_config().get("bot_token"))


def _api(method: str, payload: dict, token: Optional[str] = None, timeout: int = 8) -> dict:
    if not token:
        cfg = settings_service.get_telegram_config()
        token = cfg.get("bot_token")
    if not token:
        raise NotConfigured("Telegram bot token no configurado (Settings → Bot Telegram)")
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        raise TelegramError(f"Error llamando a Telegram: {e}") from e
    if not body.get("ok"):
        raise TelegramError(f"Telegram respondió error: {body.get('description', body)}")
    return body


def send_text(chat_id: str, text: str, parse_mode: str = "HTML", token: Optional[str] = None) -> dict:
    return _api(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        },
        token=token,
    )


def send_admin(text: str) -> bool:
    """Envía al chat admin si está configurado. Falla silencioso para no romper la operación principal."""
    cfg = settings_service.get_telegram_config()
    if not cfg.get("bot_token") or not cfg.get("admin_chat_id"):
        return False
    try:
        send_text(cfg["admin_chat_id"], text)
        return True
    except Exception:
        return False


EVENT_KEYS = (
    "tenant_created",
    "tenant_started",
    "tenant_stopped",
    "tenant_restarted",
    "tenant_deleted",
    "account_welcome",
    "account_password_reset",
    "payment_warning",
    "payment_received",
)


def _user_off_set(user: dict) -> set:
    raw = user.get("telegram_off") or ""
    return {s.strip() for s in raw.split(",") if s.strip()}


def send_user(user: Optional[dict], text: str, event_key: Optional[str] = None) -> bool:
    """Envía al usuario usando SU PROPIO bot (no usa global).
    Si el usuario no tiene token o chat_id, no se manda nada.
    Falla silencioso para no romper la operación principal."""
    if not user:
        return False
    chat_id = (user.get("telegram_chat_id") or "").strip()
    user_token = (crypto.decrypt(user.get("telegram_bot_token")) or "").strip()
    if not chat_id or not user_token:
        return False
    if event_key and event_key in _user_off_set(user):
        return False  # el usuario desactivó este tipo de notificación
    try:
        send_text(chat_id, text, token=user_token)
        return True
    except Exception:
        return False


def send_test(chat_id: str, token: Optional[str] = None) -> None:
    """Test del bot — esta sí lanza excepción para mostrar el error al usuario."""
    send_text(
        chat_id,
        "✅ <b>MonitorMaat</b>\n\nTest del bot. Si recibís este mensaje, "
        "la integración con Telegram funciona correctamente.",
        token=token,
    )
