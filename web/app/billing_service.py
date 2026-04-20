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

import json
from datetime import date, datetime, time, timedelta
from typing import Optional

from db import connect, now_iso, now_local, today_local

DEFAULT_SUSPENSION_TIME = "23:59"


def _suspension_time() -> time:
    """Devuelve la hora de suspensión configurada (o 23:59 default)."""
    try:
        # Import circular evitado: settings_service no importa billing
        import settings_service
        s = settings_service.get_billing_config().get("suspension_time", DEFAULT_SUSPENSION_TIME)
        hh, mm = int(s[:2]), int(s[3:])
        return time(hh, mm)
    except Exception:
        return time(23, 59)

DEFAULT_TRIAL_DAYS = 30
DEFAULT_PAYMENT_DAYS = 30
WARNING_DAYS = (3, 0)  # días-antes a los que mandamos aviso


class BillingError(Exception):
    pass


# ---------------- ESTADO ----------------

def is_paid(user: dict) -> bool:
    """True si el usuario puede operar.
    - Admin: siempre True
    - User: paid_until > hoy → True
            paid_until == hoy Y hora actual < hora_suspensión → True (sigue activo hoy)
            paid_until == hoy Y hora actual >= hora_suspensión → False (suspendido)
            paid_until < hoy → False
    """
    if not user:
        return False
    if user.get("role") == "admin":
        return True
    pu = user.get("paid_until")
    if not pu:
        return False
    try:
        pu_date = date.fromisoformat(pu)
    except ValueError:
        return False
    today = today_local()
    if pu_date > today:
        return True
    if pu_date < today:
        return False
    # pu_date == today: comparar hora actual con hora de suspensión
    return now_local().time() < _suspension_time()


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
    """Registra un pago/ajuste de cortesía.

    - Pagos reales (amount > 0): days debe ser > 0, paid_until = max(actual, hoy) + days
    - Cortesía positiva (amount = 0, days > 0): igual, extiende
    - Reducción/penalización (amount = 0, days < 0): paid_until + days (resta).
      Si la resta cae antes de hoy, se ajusta a hoy (no permitimos paid_until pasado por error).

    Pagos con monto positivo NUNCA pueden reducir días (sería contradictorio).
    """
    with connect() as con:
        user_row = con.execute(
            "SELECT id, role, paid_until FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if not user_row:
        raise BillingError("Usuario no encontrado.")
    if user_row["role"] == "admin":
        raise BillingError("Los administradores no requieren pagos.")
    if days == 0:
        raise BillingError("Los días no pueden ser 0.")
    if amount < 0:
        raise BillingError("El monto no puede ser negativo.")
    if amount > 0 and days < 0:
        raise BillingError("Un pago con monto no puede reducir días. Usá cortesía con monto 0.")

    today = today_local()
    current = None
    if user_row["paid_until"]:
        try:
            current = date.fromisoformat(user_row["paid_until"])
        except ValueError:
            current = None

    if days > 0:
        # Sumar: arranca desde la mayor entre hoy y paid_until actual
        base = current if current and current > today else today
        new_until = base + timedelta(days=days)
    else:
        # Restar: arranca desde paid_until actual (si no hay, desde hoy)
        base = current if current else today
        new_until = base + timedelta(days=days)
        # No permitimos retroceder más allá de hoy (deja al cliente vencido pero no en absurdo)
        if new_until < today:
            new_until = today

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

def list_payments(user_id: int, limit: int = 100, offset: int = 0) -> list[dict]:
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM payments WHERE user_id = ? ORDER BY paid_at DESC LIMIT ? OFFSET ?",
            (user_id, int(limit), int(offset)),
        ).fetchall()
    return [dict(r) for r in rows]


def count_payments(user_id: int) -> int:
    with connect() as con:
        return con.execute(
            "SELECT COUNT(*) AS c FROM payments WHERE user_id = ?", (user_id,)
        ).fetchone()["c"]


# ---------------- PLANES ----------------

def list_plans(active_only: bool = False) -> list[dict]:
    sql = "SELECT * FROM plans"
    params: list = []
    if active_only:
        sql += " WHERE is_active = 1"
    sql += " ORDER BY sort_order, price, id"
    with connect() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def _renumber_plans(con) -> None:
    """Reasigna sort_order a 1..N respetando el orden actual.
    Lo ejecutamos despues de crear/borrar/reordenar para que la columna
    'Orden' siempre se vea como 1, 2, 3... sin huecos."""
    rows = con.execute(
        "SELECT id FROM plans ORDER BY sort_order, price, id"
    ).fetchall()
    for i, r in enumerate(rows, start=1):
        con.execute("UPDATE plans SET sort_order = ? WHERE id = ?", (i, r["id"]))


def count_plan_associations(plan_id: int) -> dict:
    """Cuenta cuantos usuarios tienen este plan asignado y cuantos pagos lo
    referencian en su historial. Si total > 0, el plan esta 'en uso'."""
    with connect() as con:
        u = con.execute(
            "SELECT COUNT(*) AS c FROM users WHERE assigned_plan_id = ?", (plan_id,)
        ).fetchone()["c"]
        p = con.execute(
            "SELECT COUNT(*) AS c FROM payments WHERE plan_id = ?", (plan_id,)
        ).fetchone()["c"]
    return {"users": int(u), "payments": int(p), "total": int(u) + int(p)}


def get_plan(plan_id: int) -> Optional[dict]:
    with connect() as con:
        row = con.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
    return dict(row) if row else None


def create_plan(
    name: str,
    description: str,
    price: float,
    days: int,
    currency: str = "USD",
    is_active: bool = True,
    sort_order: int = 0,
) -> dict:
    name = (name or "").strip()
    if not name:
        raise BillingError("El nombre del plan es requerido.")
    if price < 0:
        raise BillingError("El precio no puede ser negativo.")
    if days <= 0:
        raise BillingError("Los días deben ser mayores a 0.")
    with connect() as con:
        # Siempre apendear al final: tomamos max(sort_order)+1.
        # El campo sort_order del form se ignora; renumeramos al final 1..N.
        max_so = con.execute(
            "SELECT COALESCE(MAX(sort_order), 0) AS m FROM plans"
        ).fetchone()["m"]
        cur = con.execute(
            """INSERT INTO plans (name, description, price, currency, days,
                                  is_active, sort_order, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, (description or "").strip() or None, float(price),
             (currency or "USD").strip().upper(), int(days),
             1 if is_active else 0, int(max_so) + 1, now_iso()),
        )
        pid = cur.lastrowid
        _renumber_plans(con)
        row = con.execute("SELECT * FROM plans WHERE id = ?", (pid,)).fetchone()
    return dict(row)


def update_plan(plan_id: int, **fields) -> dict:
    plan = get_plan(plan_id)
    if not plan:
        raise BillingError("Plan no encontrado.")
    # Si el plan esta en uso (clientes asignados o pagos), restringimos a los
    # campos seguros: precio, dias, nombre, descripcion. El resto (currency,
    # is_active, sort_order) queda bloqueado.
    assoc = count_plan_associations(plan_id)
    if assoc["total"] > 0:
        allowed = {"name", "description", "price", "days"}
    else:
        allowed = {"name", "description", "price", "currency", "days", "is_active", "sort_order"}
    sets = []
    params: list = []
    for k, v in fields.items():
        if k not in allowed or v is None:
            continue
        if k == "name":
            v = (v or "").strip()
            if not v:
                raise BillingError("El nombre del plan es requerido.")
        elif k == "price":
            v = float(v)
            if v < 0:
                raise BillingError("El precio no puede ser negativo.")
        elif k == "days":
            v = int(v)
            if v <= 0:
                raise BillingError("Los días deben ser mayores a 0.")
        elif k == "currency":
            v = (v or "USD").strip().upper()
        elif k == "is_active":
            v = 1 if v else 0
        elif k == "sort_order":
            v = int(v)
        elif k == "description":
            v = (v or "").strip() or None
        sets.append(f"{k} = ?")
        params.append(v)
    if not sets:
        return plan
    params.append(plan_id)
    reordered = "sort_order" in {k for k, v in fields.items() if v is not None and k in allowed}
    with connect() as con:
        con.execute(f"UPDATE plans SET {', '.join(sets)} WHERE id = ?", params)
        if reordered:
            _renumber_plans(con)
    return get_plan(plan_id)


def delete_plan(plan_id: int) -> None:
    plan = get_plan(plan_id)
    if not plan:
        raise BillingError("Plan no encontrado.")
    assoc = count_plan_associations(plan_id)
    if assoc["total"] > 0:
        parts = []
        if assoc["users"] > 0:
            parts.append(f"{assoc['users']} cliente{'s' if assoc['users'] != 1 else ''} con este plan asignado")
        if assoc["payments"] > 0:
            parts.append(f"{assoc['payments']} pago{'s' if assoc['payments'] != 1 else ''} en el historial")
        raise BillingError(
            "No se puede borrar el plan porque tiene " + " y ".join(parts) +
            ". Reasigna los clientes a otro plan antes de borrarlo."
        )
    with connect() as con:
        con.execute("DELETE FROM plans WHERE id = ?", (plan_id,))
        _renumber_plans(con)


# ---------------- ASIGNACION DE PLAN A USER ----------------

def assign_plan(user_id: int, plan_id: Optional[int]) -> None:
    """Asigna (o desasigna si plan_id=None) un plan al usuario.
    El plan asignado es el que el cliente vera y podra pagar en /me/billing."""
    if plan_id is not None:
        plan = get_plan(plan_id)
        if not plan:
            raise BillingError("Plan no encontrado.")
        if not plan["is_active"]:
            raise BillingError(f"El plan '{plan['name']}' está desactivado.")
    with connect() as con:
        con.execute(
            "UPDATE users SET assigned_plan_id = ? WHERE id = ?",
            (plan_id, user_id),
        )


def get_assigned_plan(user: dict) -> Optional[dict]:
    """Devuelve el dict del plan asignado al usuario, o None si no tiene."""
    pid = user.get("assigned_plan_id") if user else None
    if not pid:
        return None
    return get_plan(pid)


# ---------------- PAYPHONE INTEGRATION ----------------

def create_pending_payphone_payment(
    user_id: int,
    plan: dict,
    provider_tx_id: str,
    provider_id: str,
    raw_response: Optional[dict] = None,
) -> dict:
    """Crea un row PENDING en payments para un pago iniciado con PayPhone.
    Cuando llegue el callback, se actualiza con apply_payphone_confirmation()."""
    user_row = None
    with connect() as con:
        user_row = con.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row:
        raise BillingError("Usuario no encontrado.")
    if user_row["role"] == "admin":
        raise BillingError("Los administradores no requieren pagos.")
    with connect() as con:
        cur = con.execute(
            """INSERT INTO payments
               (user_id, amount, currency, days, method, notes, paid_at,
                covers_until, provider, provider_id, provider_status,
                provider_tx_id, raw_response, plan_id)
               VALUES (?, ?, ?, ?, 'payphone', ?, ?, '', 'payphone', ?, 'PENDING', ?, ?, ?)""",
            (
                user_id,
                float(plan["price"]),
                (plan.get("currency") or "USD").upper(),
                int(plan["days"]),
                f"Plan: {plan['name']}",
                now_iso(),
                provider_id,
                provider_tx_id,
                json.dumps(raw_response) if raw_response else None,
                plan["id"],
            ),
        )
        pid = cur.lastrowid
        row = con.execute("SELECT * FROM payments WHERE id = ?", (pid,)).fetchone()
    return dict(row)


def apply_payphone_confirmation(provider_tx_id: str, confirmation: dict) -> Optional[dict]:
    """Procesa la confirmación que vino del callback PayPhone.

    Si transactionStatus == 'Approved': actualiza el row + extiende paid_until.
    Si Denied/Cancelled/Expired: marca el row como tal, no extiende paid_until.
    Idempotente: si ya fue procesado (status != PENDING), no hace nada.
    Devuelve el row actualizado, o None si no se encontró.
    """
    status = confirmation.get("transactionStatus", "UNKNOWN")
    raw_json = json.dumps(confirmation)

    with connect() as con:
        row = con.execute(
            "SELECT * FROM payments WHERE provider_tx_id = ? AND provider = 'payphone'",
            (provider_tx_id,),
        ).fetchone()
        if not row:
            return None
        payment = dict(row)

        # Idempotencia: si ya fue procesado y no está PENDING, no re-aplicar
        if payment["provider_status"] not in (None, "", "PENDING"):
            return payment

        if status == "Approved":
            today = today_local()
            user_row = con.execute(
                "SELECT id, paid_until FROM users WHERE id = ?", (payment["user_id"],)
            ).fetchone()
            if not user_row:
                return None
            current = None
            if user_row["paid_until"]:
                try:
                    current = date.fromisoformat(user_row["paid_until"])
                except ValueError:
                    current = None
            base = current if current and current > today else today
            new_until = base + timedelta(days=int(payment["days"]))
            con.execute(
                """UPDATE payments SET
                       provider_status = ?, raw_response = ?, covers_until = ?,
                       paid_at = ?
                   WHERE id = ?""",
                (status, raw_json, new_until.isoformat(), now_iso(), payment["id"]),
            )
            con.execute(
                "UPDATE users SET paid_until = ?, payment_warning_sent_for = NULL WHERE id = ?",
                (new_until.isoformat(), payment["user_id"]),
            )
        else:
            con.execute(
                "UPDATE payments SET provider_status = ?, raw_response = ? WHERE id = ?",
                (status, raw_json, payment["id"]),
            )

        updated = con.execute("SELECT * FROM payments WHERE id = ?", (payment["id"],)).fetchone()
    return dict(updated) if updated else None


def get_payment_by_provider_tx(provider_tx_id: str) -> Optional[dict]:
    with connect() as con:
        row = con.execute(
            "SELECT * FROM payments WHERE provider_tx_id = ?", (provider_tx_id,)
        ).fetchone()
    return dict(row) if row else None


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
    susp = _suspension_time()
    summary = {
        "paid_until": user.get("paid_until"),
        "days_until_due": days_until_due(user),
        "is_paid": is_paid(user),
        "suspension_time": f"{susp.hour:02d}:{susp.minute:02d}",
        "has_payments": False,
        "last_amount": None,
        "last_currency": None,
        "last_days": None,
        "last_paid_at": None,
        "last_covers_until": None,
        "total_by_currency": {},
        "assigned_plan": None,
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
    summary["assigned_plan"] = get_assigned_plan(user)
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
