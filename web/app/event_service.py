"""Auditoría / log de eventos. Almacena cada acción significativa en la tabla `events`."""
from typing import Optional

from db import connect, now_iso

CATEGORIES = ("auth", "user", "tenant", "vpn_user", "network", "system", "settings")
SEVERITIES = ("info", "warn", "error")


def log(
    action: str,
    category: str = "system",
    actor: Optional[dict] = None,
    actor_username: Optional[str] = None,  # para login_fail con username inválido
    target_user: Optional[dict] = None,
    tenant: Optional[dict] = None,
    severity: str = "info",
    details: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Inserta un evento. Falla silencioso para no romper la operación principal."""
    try:
        actor_uid = actor["id"] if actor else None
        actor_uname = actor["username"] if actor else (actor_username or None)
        actor_role = actor["role"] if actor else (None if actor_username else "system")

        target_uid = target_user["id"] if target_user else None
        target_uname = target_user["username"] if target_user else None

        tenant_id = tenant["id"] if tenant else None
        tenant_name = tenant["name"] if tenant else None

        with connect() as con:
            con.execute(
                """INSERT INTO events
                   (ts, actor_user_id, actor_username, actor_role,
                    target_user_id, target_username,
                    tenant_id, tenant_name,
                    category, action, severity, details, ip)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    now_iso(),
                    actor_uid, actor_uname, actor_role,
                    target_uid, target_uname,
                    tenant_id, tenant_name,
                    category, action, severity, details, ip,
                ),
            )
    except Exception:
        pass


def _build_filters(
    actor_role: Optional[str],
    category: Optional[str],
    actor_user_id: Optional[int],
    tenant_id: Optional[int],
    search: Optional[str],
) -> tuple[str, list]:
    where = []
    params: list = []

    if actor_role == "system":
        where.append("(actor_role = 'system' OR actor_user_id IS NULL)")
    elif actor_role:
        where.append("actor_role = ?")
        params.append(actor_role)

    if category:
        where.append("category = ?")
        params.append(category)

    if actor_user_id is not None:
        where.append("actor_user_id = ?")
        params.append(actor_user_id)

    if tenant_id is not None:
        where.append("tenant_id = ?")
        params.append(tenant_id)

    if search:
        where.append(
            "(actor_username LIKE ? OR target_username LIKE ? OR tenant_name LIKE ? OR action LIKE ? OR details LIKE ?)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like, like])

    return (" WHERE " + " AND ".join(where)) if where else "", params


def list_events(
    actor_role: Optional[str] = None,   # 'admin' | 'user' | 'system' | None=todos
    category: Optional[str] = None,
    actor_user_id: Optional[int] = None,
    tenant_id: Optional[int] = None,
    search: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    where_sql, params = _build_filters(actor_role, category, actor_user_id, tenant_id, search)
    sql = "SELECT * FROM events" + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([int(limit), int(offset)])
    with connect() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def count_events(
    actor_role: Optional[str] = None,
    category: Optional[str] = None,
    actor_user_id: Optional[int] = None,
    tenant_id: Optional[int] = None,
    search: Optional[str] = None,
) -> int:
    where_sql, params = _build_filters(actor_role, category, actor_user_id, tenant_id, search)
    sql = "SELECT COUNT(*) AS c FROM events" + where_sql
    with connect() as con:
        return con.execute(sql, params).fetchone()["c"]


def list_events_for_user(user_id: int, limit: int = 200, offset: int = 0) -> list[dict]:
    """Eventos donde el usuario es actor o target o sobre sus tenants."""
    with connect() as con:
        rows = con.execute(
            """SELECT e.* FROM events e
               LEFT JOIN tenants t ON t.id = e.tenant_id
               WHERE e.actor_user_id = ?
                  OR e.target_user_id = ?
                  OR t.owner_id = ?
               ORDER BY e.id DESC LIMIT ? OFFSET ?""",
            (user_id, user_id, user_id, int(limit), int(offset)),
        ).fetchall()
    return [dict(r) for r in rows]


def count_events_for_user(user_id: int) -> int:
    with connect() as con:
        return con.execute(
            """SELECT COUNT(*) AS c FROM events e
               LEFT JOIN tenants t ON t.id = e.tenant_id
               WHERE e.actor_user_id = ? OR e.target_user_id = ? OR t.owner_id = ?""",
            (user_id, user_id, user_id),
        ).fetchone()["c"]
