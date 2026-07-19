"""Cifrado simétrico en reposo para secretos de la DB (claves VPN, token Payphone,
password SMTP, tokens de Telegram).

Usa Fernet (AES-128-CBC + HMAC) con una clave persistida en el volumen de datos
(`<BASE_PATH>/data/.secret_key`, generada una vez, perms 600). Como la clave vive
en el mismo volumen que la DB, esto protege ante fugas del ARCHIVO de la DB (dumps,
backups parciales, copia de la .db) — no ante un compromiso total del server. Es
defensa en profundidad, complementa (no reemplaza) TLS y el hardening del host.

decrypt() tolera valores en texto plano legacy: si no puede descifrar, devuelve el
input tal cual (permite migración gradual e idempotente).
"""
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

import config

_KEY_FILE = Path(config.BASE_PATH) / "data" / ".secret_key"
_fernet = None


def _load_key() -> bytes:
    try:
        if _KEY_FILE.exists():
            data = _KEY_FILE.read_bytes().strip()
            if data:
                return data
    except Exception:
        pass
    key = Fernet.generate_key()
    try:
        _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _KEY_FILE.write_bytes(key)
        os.chmod(_KEY_FILE, 0o600)
    except Exception:
        pass
    return key


def _f() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt(plaintext):
    """Cifra un str. None→None, ''→'' (para no romper columnas)."""
    if plaintext is None or plaintext == "":
        return plaintext
    return _f().encrypt(str(plaintext).encode("utf-8")).decode("utf-8")


def decrypt(token):
    """Descifra. Si no es un token válido (texto plano legacy) devuelve el input."""
    if not token:
        return token
    try:
        return _f().decrypt(str(token).encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        return token


def session_secret_fallback() -> str:
    """Clave fuerte y persistida para SESSION_SECRET cuando el env es débil/ausente."""
    return _load_key().decode("utf-8")
