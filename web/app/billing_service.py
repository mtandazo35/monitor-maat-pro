"""Módulo independiente de facturación / cobros mensuales.

Responsable de:
- Calcular si un usuario está al día (is_paid)
- Días restantes hasta el vencimiento
- Registrar pagos (con monto, días, método, notas) y extender paid_until
- Listar historial de pagos
- Detectar usuarios próximos a vencer y mandar avisos (Telegram + email)
- Resumen del "plan" del usuario (último pago + total acumulado)

No conoce nada de la lógica de auth/CRUD de usuarios — usa la tabla `users`
solo para leer/actualizar `paid_until` y `payment_warning_sent_for`.
"""

from datetime import date, timedelta
from typing import Optional

from db import connect, now_iso, today_local

DEFAULT_TRIAL_DAYS = 30
DEFAULT_PAYMENT_DAYS = 30
WARNING_DAYS = (3, 0)  # días-antes a los que mandamos aviso


class BillingError(Exception):
    pass


# ---------------- ESTADO ----------------

def is_paid(user: dict) -> bool:
    """True si el usuario puede operar (admin siempre, user si paid_until >= hoy)."""
    if not user:
        return False
    if user.get("role") == "admin":
        return True
    pu = user.get("paid_until")
    if not pu:
        return False
    try:
        return date.fromisoformat(pu) >= today_local()
    except ValueError:
        return False


def days_until_due(user: dict) -> Optional[int]:
    """Días hasta el vencimiento. Negativo si ya venció. None si no aplica."""
    if not user or user.get("role") == "admin":
        return None
    pu = user.get("paid_until")
    if not pu:
        return None
    try:
        return (date.fromisoformat(pu) - today_local()).days
    except ValueError:
        return None


def initial_paid_until(role: str) -> Optional[str]:
    """Fecha (ISO) de paid_until al crear un usuario nuevo. Admin = None."""
    if role != "user":
        return None
    return (today_local() + timedelta(days=DEFAULT_TRIAL_DAYS)).isoformat()


# ---------------- MUTACIONES ----------------

def set_paid_until(user_id: int, new_date: date) -> None:
    with connect() as con:
        con.execute(
            "UPDATE users SET paid_until = ?, payment_warning_sent_for = NULL WHERE id = ?",
            (new_date.isoformat(), user_id),
        )


def register_payment(
    user_id: int,
    amount: float,
    days: int,
    currency: str = "USD",
    method: Optional[str] = None,
    notes: Optional[str] = None,
    registered_by: Optional[dict] = None,
) -> dict:
    """Registra un pago, extiende paid_until = max(actual, hoy) + días.
    Devuelve el row del pago insertado."""
    with connect() as con:
        user_row = con.execute(
            "SELECT id, role, paid_until FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if not user_row:
        raise BillingError("Usuario no encontrado.")
    if user_row["role"] == "admin":
        raise BillingError("Los administradores no requieren pagos.")
    if days <= 0:
        raise BillingError("Los días deben ser mayores a 0.")
    if amount < 0:
        raise BillingError("El monto no puede ser negativo.")

    today = today_local()
    current = None
    if user_row["paid_until"]:
        try:
            current = date.fromisoformat(user_row["paid_until"])
        except ValueError:
            current = None
    base = current if current and current > today else today
    new_until = base + timedelta(days=days)

    with connect() as con:
        cur = con.execute(
            """INSERT INTO payments
               (user_id, amount, currency, days, method, notes,
                paid_at, registered_by_id, registered_by_username, covers_until)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id, float(amount), (currency or "USD").strip().upper(),
                int(days),
                (method or "").strip() or None,
                (notes or "").strip() or None,
                now_iso(),
                registered_by["id"] if registered_by else None,
                registered_by["username"] if registered_by else None,
                new_until.isoformat(),
            ),
        )
        pid = cur.lastrowid
        con.execute(
            "UPDATE users SET paid_until = ?, payment_warning_sent_for = NULL WHERE id = ?",
            (new_until.isoformat(), user_id),
        )
        row = con.execute("SELECT * FROM payments WHERE id = ?", (pid,)).fetchone()
    return dict(row)


def mark_warning_sent(user_id: int, for_date: str) -> None:
    with connect() as con:
        con.execute(
            "UPDATE users SET payment_warning_sent_for = ? WHERE id = ?",
            (for_date, user_id),
        )


# ---------------- LECTURAS ----------------

def list_payments(user_id: int, limit: int = 100) -> list[dict]:
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM payments WHERE user_id = ? ORDER BY paid_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def last_payment(user_id: int) -> Optional[dict]:
    with connect() as con:
        row = con.execute(
            "SELECT * FROM payments WHERE user_id = ? AND amount > 0 "
            "ORDER BY paid_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def total_paid_by_currency(user_id: int) -> dict[str, float]:
    """Suma total pagada agrupada por moneda. Excluye pagos de monto 0 (cortesías)."""
    with connect() as con:
        rows = con.execute(
            "SELECT currency, SUM(amount) AS total FROM payments "
            "WHERE user_id = ? AND amount > 0 GROUP BY currency",
            (user_id,),
        ).fetchall()
    return {r["currency"]: r["total"] for r in rows}


def plan_summary(user: dict) -> dict:
    """Resumen del 'plan' del cliente para mostrar en su panel.

    Devuelve:
      - paid_until: ISO date (o None)
      - days_until_due: int (o None)
      - is_paid: bool
      - last_amount, last_currency, last_days, last_paid_at, last_covers_until: del último pago
      - total_by_currency: {currency: total}
      - has_payments: bool (False si solo tiene el trial inicial)
    """
    summary = {
        "paid_until": user.get("paid_until"),
        "days_until_due": days_until_due(user),
        "is_paid": is_paid(user),
        "has_payments": False,
        "last_amount": None,
        "last_currency": None,
        "last_days": None,
        "last_paid_at": None,
        "last_covers_until": None,
        "total_by_currency": {},
    }
    if not user or user.get("role") == "admin":
        return summary
    last = last_payment(user["id"])
    if last:
        summary.update({
            "has_payments": True,
            "last_amount": last["amount"],
            "last_currency": last["currency"],
            "last_days": last["days"],
            "last_paid_at": last["paid_at"],
            "last_covers_until": last["covers_until"],
        })
    summary["total_by_currency"] = total_paid_by_currency(user["id"])
    return summary


def list_due_users(within_days: int = 3) -> list[dict]:
    """Usuarios 'user' cuyo paid_until está en (hoy-1 .. hoy+within_days). Excluye admin."""
    today = today_local()
    until = (today + timedelta(days=within_days)).isoformat()
    yesterday = (today - timedelta(days=1)).isoformat()
    with connect() as con:
        rows = con.execute(
            """SELECT * FROM users
               WHERE role = 'user'
                 AND paid_until IS NOT NULL
                 AND paid_until >= ?
                 AND paid_until <= ?""",
            (yesterday, until),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------- AVISOS ----------------

def send_payment_reminders(notify_module, mail_module, login_url: Optional[str] = None) -> int:
    """Para cada user 'user' próximo a vencer (3, 2, 1, 0 días) o vencido (-1):
    si no se mandó aviso aún para esa fecha de paid_until, mandar Telegram + email
    y marcar payment_warning_sent_for = paid_until. Idempotente."""
    sent = 0
    today = today_local()
    for u in list_due_users(within_days=3):
        pu_str = u.get("paid_until")
        if not pu_str or u.get("payment_warning_sent_for") == pu_str:
            continue
        try:
            pu = date.fromisoformat(pu_str)
        except ValueError:
            continue
        diff = (pu - today).days
        if diff > 3 or diff < -1:
            continue

        if diff > 0:
            subject = f"Tu cuenta MonitorMaat vence en {diff} día{'s' if diff != 1 else ''}"
            body = (
                f"Tu cuenta vence el {pu_str}. "
                f"Contactá al administrador para renovar y evitar el corte."
            )
        elif diff == 0:
            subject = "Tu cuenta MonitorMaat vence hoy"
            body = (
                f"Tu cuenta vence hoy ({pu_str}). "
                f"Si no se renueva, mañana no podrás ingresar al panel."
            )
        else:
            subject = "Tu cuenta MonitorMaat está vencida"
            body = (
                f"Tu cuenta venció el {pu_str}. "
                f"No podés ingresar al panel hasta renovar."
            )

        try:
            notify_module.send_user(
                u, f"⚠ <b>{subject}</b>\n\n{body}", event_key="payment_warning"
            )
        except Exception:
            pass
        if u.get("email") and mail_module.is_configured():
            try:
                mail_module.send_payment_warning(
                    u["email"], u["username"], subject, body, login_url=login_url,
                )
            except Exception:
                pass
        try:
            notify_module.send_admin(
                f"💸 Aviso de pago enviado a <code>{u['username']}</code> "
                f"({diff} día{'s' if abs(diff) != 1 else ''} → {pu_str})"
            )
        except Exception:
            pass

        mark_warning_sent(u["id"], pu_str)
        sent += 1
    return sent
