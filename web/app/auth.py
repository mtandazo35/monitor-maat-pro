from typing import Optional

from fastapi import Request

import user_service


def authenticate(username: str, password: str) -> Optional[dict]:
    return user_service.authenticate(username, password)


def session_user(request: Request) -> Optional[dict]:
    uid = request.session.get("user_id")
    if not uid:
        return None
    user = user_service.get_user(uid)
    if not user:
        request.session.clear()
        return None
    return user


def is_admin(user: Optional[dict]) -> bool:
    return bool(user) and user.get("role") == "admin"
