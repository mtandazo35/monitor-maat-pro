import sqlite3
from contextlib import contextmanager
from datetime import datetime, date, timedelta

from config import DB_PATH


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                company_name TEXT,
                first_name TEXT,
                last_name TEXT,
                phone_cc TEXT,
                phone TEXT,
                email TEXT,
                telegram_chat_id TEXT,
                telegram_bot_token TEXT,
                telegram_off TEXT,
                tenant_quota INTEGER,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tenants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                slot INTEGER UNIQUE NOT NULL,
                vpn_port INTEGER NOT NULL,
                kuma_port INTEGER NOT NULL,
                vpn_subnet TEXT NOT NULL,
                vpn_mask TEXT NOT NULL,
                docker_subnet TEXT NOT NULL,
                public_ip TEXT,
                owner_id INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vpn_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                ip TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(tenant_id, username)
            );

            CREATE TABLE IF NOT EXISTS vpn_networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vpn_user_id INTEGER NOT NULL REFERENCES vpn_users(id) ON DELETE CASCADE,
                cidr TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(vpn_user_id, cidr)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor_user_id INTEGER,
                actor_username TEXT,
                actor_role TEXT,
                target_user_id INTEGER,
                target_username TEXT,
                tenant_id INTEGER,
                tenant_name TEXT,
                category TEXT NOT NULL,
                action TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                details TEXT,
                ip TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_user_id);
            CREATE INDEX IF NOT EXISTS idx_events_role ON events(actor_role);
            CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
            CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id);

            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                amount REAL NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'USD',
                days INTEGER NOT NULL,
                method TEXT,
                notes TEXT,
                paid_at TEXT NOT NULL,
                registered_by_id INTEGER REFERENCES users(id),
                registered_by_username TEXT,
                covers_until TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT 'manual',
                provider_id TEXT,
                provider_status TEXT,
                provider_tx_id TEXT,
                raw_response TEXT,
                plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
            CREATE INDEX IF NOT EXISTS idx_payments_paid_at ON payments(paid_at DESC);

            CREATE TABLE IF NOT EXISTS plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'USD',
                days INTEGER NOT NULL DEFAULT 30,
                is_active INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_plans_active ON plans(is_active, sort_order);
            """
        )

        # Migración: agregar owner_id a tenants existentes que no la tengan
        cols = [r[1] for r in con.execute("PRAGMA table_info(tenants)").fetchall()]
        if "owner_id" not in cols:
            con.execute("ALTER TABLE tenants ADD COLUMN owner_id INTEGER REFERENCES users(id)")

        # Migración: agregar email + must_change_password a users existentes
        ucols = [r[1] for r in con.execute("PRAGMA table_info(users)").fetchall()]
        if "email" not in ucols:
            con.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "must_change_password" not in ucols:
            con.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        for col in ("first_name", "last_name", "phone", "phone_cc", "telegram_chat_id", "telegram_bot_token", "telegram_off"):
            if col not in ucols:
                con.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
        # birth_date fue removido: si la columna existe la dropeamos (SQLite 3.35+)
        if "birth_date" in ucols:
            try:
                con.execute("ALTER TABLE users DROP COLUMN birth_date")
            except Exception:
                pass

        # Migración billing: agrega paid_until + payment_warning_sent_for
        ucols2 = [r[1] for r in con.execute("PRAGMA table_info(users)").fetchall()]
        if "paid_until" not in ucols2:
            con.execute("ALTER TABLE users ADD COLUMN paid_until TEXT")
            # Backfill: usuarios 'user' existentes obtienen 30 días gratis
            # para no quedar bloqueados al deployar el feature.
            trial = ((datetime.utcnow() + _EC_OFFSET).date() + timedelta(days=30)).isoformat()
            con.execute(
                "UPDATE users SET paid_until = ? WHERE role = 'user' AND paid_until IS NULL",
                (trial,),
            )
        if "payment_warning_sent_for" not in ucols2:
            con.execute("ALTER TABLE users ADD COLUMN payment_warning_sent_for TEXT")
        if "assigned_plan_id" not in ucols2:
            con.execute("ALTER TABLE users ADD COLUMN assigned_plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL")
        if "is_active" not in ucols2:
            con.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

        # Migración payments: columnas para tracking de provider (PayPhone)
        pcols = [r[1] for r in con.execute("PRAGMA table_info(payments)").fetchall()]
        for col, sql in [
            ("provider",        "ALTER TABLE payments ADD COLUMN provider TEXT NOT NULL DEFAULT 'manual'"),
            ("provider_id",     "ALTER TABLE payments ADD COLUMN provider_id TEXT"),
            ("provider_status", "ALTER TABLE payments ADD COLUMN provider_status TEXT"),
            ("provider_tx_id",  "ALTER TABLE payments ADD COLUMN provider_tx_id TEXT"),
            ("raw_response",    "ALTER TABLE payments ADD COLUMN raw_response TEXT"),
            ("plan_id",         "ALTER TABLE payments ADD COLUMN plan_id INTEGER"),
        ]:
            if col not in pcols:
                try:
                    con.execute(sql)
                except Exception:
                    pass
        try:
            con.execute("CREATE INDEX IF NOT EXISTS idx_payments_provider_tx ON payments(provider_tx_id)")
        except Exception:
            pass


@contextmanager
def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


# Ecuador no tiene DST, offset fijo UTC-5. Calculamos la fecha "hoy" de Ecuador
# sin depender de la TZ del container (que podría ser UTC en Docker).
_EC_OFFSET = timedelta(hours=-5)


def today_local() -> date:
    return (datetime.utcnow() + _EC_OFFSET).date()


def now_local() -> datetime:
    """Datetime local de Ecuador (UTC-5, sin DST). Naive datetime."""
    return datetime.utcnow() + _EC_OFFSET


def today_iso() -> str:
    return today_local().isoformat()
