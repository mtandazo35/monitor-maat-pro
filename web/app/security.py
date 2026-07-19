"""Endurecimiento de seguridad: headers globales, rate limit login, lockout.

- SecurityHeadersMiddleware: agrega headers que mitigan clickjacking, MIME
  sniffing, XSS. HSTS solo cuando se sirve por HTTPS.
- Login rate limiter: bloquea intentos brute force por IP y por username.
- Helpers para verificar si la request viene por HTTPS (mirando X-Forwarded-Proto
  porque el VPS puede estar detrás de Cloudflare).
"""
import os
from datetime import datetime, timedelta

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from db import connect, now_iso

# Ventana y umbrales para rate limit/lockout
LOCKOUT_WINDOW_MIN = 15           # ventana donde se cuentan los intentos
LOCKOUT_FAILS_PER_IP = 20         # >= N fallos por IP en ventana → bloqueo IP
LOCKOUT_FAILS_PER_USER = 5        # >= N fallos por username en ventana → bloqueo username
LOCKOUT_DURATION_MIN = 15         # duración del bloqueo


def is_https_request(request: Request) -> bool:
    """True si la request original era HTTPS (mirando proto del proxy si lo hay)."""
    proto = request.headers.get("x-forwarded-proto", "").lower()
    if proto == "https":
        return True
    return request.url.scheme == "https"


def secure_cookies_enabled() -> bool:
    """True si las cookies deben llevar Secure (sólo cuando vamos por HTTPS).
    Configurable vía env SECURE_COOKIES=1 para forzar."""
    val = os.environ.get("SECURE_COOKIES", "").strip().lower()
    return val in ("1", "true", "yes")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inyecta headers de seguridad en cada respuesta."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        # Anti-clickjacking
        response.headers.setdefault("X-Frame-Options", "DENY")
        # Bloquea MIME sniffing
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        # Solo enviar referer al mismo origen
        response.headers.setdefault("Referrer-Policy", "same-origin")
        # Limitar permisos de browser APIs sensibles
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()",
        )
        # CSP: 'unsafe-eval' es REQUERIDO porque Vue 3 con templates inline
        # usa new Function() para compilarlos en runtime. Sin esto los componentes
        # se quedan colgados en v-cloak y la pagina se ve en blanco.
        # Vue se sirve self-hosted desde /static (NO de CDN externo) → sin unpkg en
        # script-src: todo el JS es 'self', cerrando el riesgo de cadena de suministro.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "form-action 'self' https://pay.payphonetodoesposible.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'",
        )
        # HSTS solo si la request original era HTTPS
        if is_https_request(request):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response


# ---------------- LOGIN RATE LIMIT / LOCKOUT ----------------

def _ensure_table() -> None:
    with connect() as con:
        con.execute(
            """CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT,
                username TEXT,
                success INTEGER NOT NULL DEFAULT 0
            )"""
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_ts ON login_attempts(ts DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(username)")


def record_attempt(ip: str, username: str, success: bool) -> None:
    """Registra un intento de login. Llamar después del check de password."""
    try:
        _ensure_table()
        with connect() as con:
            con.execute(
                "INSERT INTO login_attempts (ts, ip, username, success) VALUES (?, ?, ?, ?)",
                (now_iso(), (ip or "")[:64], (username or "")[:64], 1 if success else 0),
            )
            # Limpiar registros viejos (>30 días) ocasionalmente
            con.execute(
                "DELETE FROM login_attempts WHERE ts < ?",
                ((datetime.utcnow() - timedelta(days=30)).isoformat() + "Z",),
            )
    except Exception:
        pass


def _fail_count(field: str, value: str, window_min: int) -> int:
    if not value:
        return 0
    since = (datetime.utcnow() - timedelta(minutes=window_min)).isoformat() + "Z"
    try:
        _ensure_table()
        with connect() as con:
            row = con.execute(
                f"SELECT COUNT(*) AS c FROM login_attempts "
                f"WHERE {field} = ? AND success = 0 AND ts >= ?",
                (value, since),
            ).fetchone()
        return row["c"] if row else 0
    except Exception:
        return 0


def is_locked(ip: str, username: str) -> tuple[bool, str]:
    """Verifica si una combinación IP/username está bloqueada por intentos
    fallidos recientes. Devuelve (bool bloqueado, mensaje)."""
    fails_ip = _fail_count("ip", ip or "", LOCKOUT_WINDOW_MIN)
    if fails_ip >= LOCKOUT_FAILS_PER_IP:
        return True, (
            f"Demasiados intentos fallidos desde tu IP. Probá en {LOCKOUT_DURATION_MIN} minutos."
        )
    fails_user = _fail_count("username", (username or "").lower(), LOCKOUT_WINDOW_MIN)
    if fails_user >= LOCKOUT_FAILS_PER_USER:
        return True, (
            "Demasiados intentos fallidos para este usuario. "
            f"Probá en {LOCKOUT_DURATION_MIN} minutos."
        )
    return False, ""


def reset_user_attempts(username: str) -> None:
    """Reset al login_attempts fallidos de un usuario (después de login exitoso)."""
    if not username:
        return
    try:
        with connect() as con:
            con.execute(
                "DELETE FROM login_attempts WHERE username = ? AND success = 0",
                (username.lower(),),
            )
    except Exception:
        pass


# ---------------- WEBHOOK RATE LIMIT (in-memory, simple) ----------------

import time as _time
import threading as _threading

_webhook_lock = _threading.Lock()
_webhook_hits: dict[str, list[float]] = {}  # ip -> [timestamp, ...]
WEBHOOK_LIMIT_PER_MIN = 30


def webhook_rate_limit(ip: str) -> bool:
    """Devuelve True si la IP excedió el límite. Self-cleaning."""
    if not ip:
        return False
    now = _time.time()
    cutoff = now - 60
    with _webhook_lock:
        hits = [t for t in _webhook_hits.get(ip, []) if t >= cutoff]
        hits.append(now)
        _webhook_hits[ip] = hits
        # Cleanup ocasional de IPs sin hits recientes
        if len(_webhook_hits) > 200:
            for k in list(_webhook_hits.keys()):
                if not _webhook_hits[k] or _webhook_hits[k][-1] < cutoff:
                    _webhook_hits.pop(k, None)
        return len(hits) > WEBHOOK_LIMIT_PER_MIN
