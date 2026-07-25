import time
from typing import Optional

from fastapi import Request

import config
import user_service


def authenticate(username: str, password: str) -> Optional[dict]:
    return user_service.authenticate(username, password)


def start_session(request: Request, user_id: int) -> None:
    """Inicia sesión: guarda el usuario y los timestamps de control de vencimiento."""
    now = int(time.time())
    request.session["user_id"] = user_id
    request.session["login_at"] = now   # para el tope ABSOLUTO
    request.session["last_seen"] = now  # para el corte por inactividad


def session_user(request: Request) -> Optional[dict]:
    uid = request.session.get("user_id")
    if not uid:
        return None

    now = int(time.time())
    login_at = request.session.get("login_at")
    last_seen = request.session.get("last_seen")
    max_abs = config.SESSION_MAX_HOURS * 3600
    max_idle = config.SESSION_IDLE_MINUTES * 60

    # Sesiones viejas sin timestamps (pre-feature): sembramos ahora para no expulsar
    # de golpe, pero a partir de acá quedan sujetas a los límites.
    if login_at is None or last_seen is None:
        request.session["login_at"] = now
        request.session["last_seen"] = now
        login_at = last_seen = now

    # Tope absoluto: vence sí o sí pasadas SESSION_MAX_HOURS desde el login.
    if now - login_at > max_abs:
        request.session.clear()
        return None
    # Inactividad: sin requests por más de SESSION_IDLE_MINUTES.
    if now - last_seen > max_idle:
        request.session.clear()
        return None

    user = user_service.get_user(uid)
    if not user:
        request.session.clear()
        return None

    request.session["last_seen"] = now  # refrescar actividad
    return user


def is_admin(user: Optional[dict]) -> bool:
    return bool(user) and user.get("role") == "admin"
