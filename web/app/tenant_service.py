import ipaddress
import re
import secrets
import shutil
import string
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional

from jinja2 import Template

import config
import crypto
from db import connect, now_iso


TENANT_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


class ServiceError(Exception):
    pass


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, check=check, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        stdout = (e.stdout or "").strip()
        msg = stderr or stdout or f"exit code {e.returncode}"
        raise ServiceError(f"`{' '.join(cmd)}` falló: {msg}") from e


def _random_token(n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _resolve_public_ip() -> str:
    if config.PUBLIC_IP:
        return config.PUBLIC_IP
    try:
        with urllib.request.urlopen(
            "http://ip1.dynupdate.no-ip.com/", timeout=5
        ) as r:
            ip = r.read().decode().strip()
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
                return ip
    except Exception:
        pass
    return "YOUR_SERVER_IP"


def _allocate_slot() -> int:
    with connect() as con:
        used = {row["slot"] for row in con.execute("SELECT slot FROM tenants")}
    for s in range(1, config.MAX_TENANTS + 1):
        if s not in used:
            return s
    raise ServiceError("No hay slots disponibles (máx 254 tenants).")


def _tenant_dir(name: str) -> Path:
    return config.TENANTS_DIR / name


def _compose_file(name: str) -> Path:
    return _tenant_dir(name) / "docker-compose.yml"


def _render_compose(tenant: dict) -> str:
    template_text = config.COMPOSE_TEMPLATE.read_text(encoding="utf-8")
    template = Template(template_text, keep_trailing_newline=True)
    return template.render(
        tenant=tenant,
        base_path=str(config.BASE_PATH),
        kuma_bind=config.KUMA_BIND,
    )


def tenant_domain(tenant: dict) -> str:
    """Dominio asignado al tenant: <tenant>.<base_domain> si hay base_domain, si no "" """
    if not tenant:
        return ""
    try:
        import settings_service
        base = settings_service.get_network_config().get("base_domain", "").strip()
        if base:
            return f"{tenant['name']}.{base}"
    except Exception:
        pass
    return ""


def kuma_url(tenant: dict) -> str:
    """URL pública del Uptime Kuma de un tenant.
    Si hay base_domain configurado: https://<tenant>.<base_domain> (con HTTPS o HTTP).
    Si no: http://<public_ip>:<kuma_port> (default actual)."""
    if not tenant:
        return ""
    domain = tenant_domain(tenant)
    if domain:
        try:
            import settings_service
            scheme = "https" if settings_service.get_network_config().get("use_https", True) else "http"
        except Exception:
            scheme = "https"
        return f"{scheme}://{domain}"
    return f"http://{tenant['public_ip']}:{tenant['kuma_port']}"


def _tenants_filters(owner_id: Optional[int], search: Optional[str]) -> tuple[str, list]:
    where: list[str] = []
    params: list = []
    if owner_id is not None:
        where.append("t.owner_id = ?")
        params.append(owner_id)
    if search:
        where.append(
            "(t.name LIKE ? OR COALESCE(u.username,'') LIKE ? OR COALESCE(u.company_name,'') LIKE ?)"
        )
        like = f"%{search.strip()}%"
        params.extend([like, like, like])
    return (" WHERE " + " AND ".join(where)) if where else "", params


def list_tenants(
    owner_id: Optional[int] = None,
    search: Optional[str] = None,
    limit: Optional[int] = None,
    offset: int = 0,
) -> list[dict]:
    where_sql, params = _tenants_filters(owner_id, search)
    sql = (
        "SELECT t.*, u.username AS owner_username, u.company_name AS owner_company "
        "FROM tenants t LEFT JOIN users u ON u.id = t.owner_id"
        + where_sql + " ORDER BY t.slot"
    )
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])
    with connect() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def count_tenants(owner_id: Optional[int] = None, search: Optional[str] = None) -> int:
    where_sql, params = _tenants_filters(owner_id, search)
    sql = "SELECT COUNT(*) AS c FROM tenants t LEFT JOIN users u ON u.id = t.owner_id" + where_sql
    with connect() as con:
        return con.execute(sql, params).fetchone()["c"]


def get_tenant(name: str) -> Optional[dict]:
    with connect() as con:
        row = con.execute(
            """SELECT t.*, u.username AS owner_username, u.company_name AS owner_company
               FROM tenants t LEFT JOIN users u ON u.id = t.owner_id
               WHERE t.name = ?""",
            (name,),
        ).fetchone()
    return dict(row) if row else None


def create_tenant(name: str, owner: dict) -> dict:
    if not TENANT_NAME_RE.match(name):
        raise ServiceError(
            "Nombre inválido. Solo minúsculas, números y guiones; inicia con letra; 2-31 caracteres."
        )
    if get_tenant(name):
        raise ServiceError(f"Ya existe un tenant llamado '{name}'.")

    # Quota check (admin = ilimitado)
    if owner["role"] != "admin":
        quota = owner.get("tenant_quota")
        if quota is not None and quota > 0:
            with connect() as con:
                used = con.execute(
                    "SELECT COUNT(*) AS c FROM tenants WHERE owner_id = ?", (owner["id"],)
                ).fetchone()["c"]
            if used >= quota:
                raise ServiceError(f"Llegaste a tu quota de {quota} tenant(s). Pedile al admin que la suba.")
        elif quota == 0 or quota is None:
            raise ServiceError("Tu quota es 0. Pedile al admin que te asigne un cupo.")

    slot = _allocate_slot()
    public_ip = _resolve_public_ip()

    tenant = {
        "name": name,
        "slot": slot,
        "vpn_port": config.VPN_PORT_BASE + slot,
        "kuma_port": config.KUMA_PORT_BASE + slot,
        "vpn_subnet": f"{config.VPN_SUBNET_PREFIX}.{slot}.0",
        "vpn_mask": "255.255.255.0",
        "docker_subnet": f"{config.DOCKER_SUBNET_PREFIX}.{slot}.0/24",
        "public_ip": public_ip,
        "created_at": now_iso(),
    }

    tdir = _tenant_dir(name)
    (tdir / "openvpn").mkdir(parents=True, exist_ok=True)
    (tdir / "kuma").mkdir(parents=True, exist_ok=True)

    compose_text = _render_compose(tenant)
    _compose_file(name).write_text(compose_text, encoding="utf-8")

    with connect() as con:
        con.execute(
            """
            INSERT INTO tenants
            (name, slot, vpn_port, kuma_port, vpn_subnet, vpn_mask,
             docker_subnet, public_ip, owner_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant["name"], tenant["slot"], tenant["vpn_port"],
                tenant["kuma_port"], tenant["vpn_subnet"], tenant["vpn_mask"],
                tenant["docker_subnet"], tenant["public_ip"], owner["id"], tenant["created_at"],
            ),
        )

    compose_up(name)
    return get_tenant(name)


def compose_up(name: str) -> None:
    _run(
        ["docker", "compose", "-f", str(_compose_file(name)), "up", "-d"],
    )


def compose_down(name: str, remove_volumes: bool = False) -> None:
    cmd = ["docker", "compose", "-f", str(_compose_file(name)), "down"]
    if remove_volumes:
        cmd.append("-v")
    _run(cmd, check=False)


def compose_restart(name: str, service: Optional[str] = None) -> None:
    f = str(_compose_file(name))
    if service == "openvpn":
        # openvpn comparte netns con kuma (network_mode: service:openvpn).
        # Al reiniciar openvpn su netns se destruye; kuma queda apuntando al
        # netns viejo y pierde red. Hay que reiniciar ambos.
        _run(["docker", "compose", "-f", f, "restart", "openvpn"])
        _run(["docker", "compose", "-f", f, "restart", "kuma"])
    elif service:
        _run(["docker", "compose", "-f", f, "restart", service])
    else:
        _run(["docker", "compose", "-f", f, "restart"])


def container_status(container_name: str) -> str:
    r = _run(
        ["docker", "inspect", "-f", "{{.State.Status}}", container_name],
        check=False,
    )
    if r.returncode != 0:
        return "missing"
    return r.stdout.strip()


def container_statuses_bulk() -> dict:
    """Devuelve {container_name: state} en una sola llamada a docker ps -a."""
    r = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}"],
        capture_output=True, text=True, check=False,
    )
    out = {}
    if r.returncode != 0:
        return out
    for line in r.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) == 2:
            out[parts[0]] = parts[1]
    return out


def delete_tenant(name: str) -> None:
    tenant = get_tenant(name)
    if not tenant:
        raise ServiceError("Tenant no encontrado.")
    compose_down(name, remove_volumes=True)

    tdir = _tenant_dir(name)
    if tdir.exists():
        shutil.rmtree(tdir, ignore_errors=True)

    with connect() as con:
        con.execute("DELETE FROM tenants WHERE id = ?", (tenant["id"],))


# -------- VPN USERS --------

def _ovpn_container(tenant_name: str) -> str:
    return f"openvpn-{tenant_name}"


def _docker_exec(container: str, cmd: list[str], input_data: Optional[str] = None) -> subprocess.CompletedProcess:
    full = ["docker", "exec", "-i", container] + cmd
    return subprocess.run(
        full,
        input=input_data,
        capture_output=True,
        text=True,
    )


def _persist_pam(container: str) -> None:
    """Copia los archivos de auth del FS efímero al volumen persistente.
    Necesario después de adduser/chpasswd/deluser para sobrevivir recreaciones."""
    _docker_exec(container, ["sh", "-c",
        "mkdir -p /etc/openvpn/auth && "
        "cp /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/openvpn/auth/"])


def list_vpn_users(tenant_id: int) -> list[dict]:
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM vpn_users WHERE tenant_id = ? ORDER BY id",
            (tenant_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["password"] = crypto.decrypt(d.get("password"))  # cifrada en reposo
        out.append(d)
    return out


def _next_vpn_ip(tenant: dict) -> str:
    with connect() as con:
        used = {
            r["ip"]
            for r in con.execute(
                "SELECT ip FROM vpn_users WHERE tenant_id = ?",
                (tenant["id"],),
            )
        }
    net = ipaddress.IPv4Network(f"{tenant['vpn_subnet']}/24", strict=False)
    server_ip = str(net.network_address + 1)  # OpenVPN topology subnet reserva .1
    for host in net.hosts():
        ip = str(host)
        if ip == server_ip or ip in used:
            continue
        return ip
    raise ServiceError("No quedan IPs libres en el rango VPN del tenant.")


def add_vpn_user(tenant: dict) -> dict:
    container = _ovpn_container(tenant["name"])
    if container_status(container) != "running":
        raise ServiceError(
            f"El contenedor {container} no está corriendo. Iniciá el tenant primero."
        )

    username = _random_token(12)
    password = _random_token(12)
    ip = _next_vpn_ip(tenant)

    r = _docker_exec(
        container,
        [
            "adduser", username,
            "--gecos", f"{username},RoomNumber,WorkPhone,HomePhone",
            "--disabled-password",
            "--force-badname",
            "--no-create-home",
        ],
    )
    if r.returncode != 0:
        raise ServiceError(f"adduser falló: {r.stderr or r.stdout}")

    r = _docker_exec(container, ["chpasswd"], input_data=f"{username}:{password}\n")
    if r.returncode != 0:
        raise ServiceError(f"chpasswd falló: {r.stderr or r.stdout}")

    _persist_pam(container)

    ccd = _tenant_dir(tenant["name"]) / "openvpn" / "UptimeKuma" / username
    ccd.parent.mkdir(parents=True, exist_ok=True)
    ccd.write_text(f"ifconfig-push {ip} {tenant['vpn_mask']}\n", encoding="utf-8")

    with connect() as con:
        cur = con.execute(
            """
            INSERT INTO vpn_users (tenant_id, username, password, ip, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (tenant["id"], username, crypto.encrypt(password), ip, now_iso()),
        )
        user_id = cur.lastrowid
        row = con.execute("SELECT * FROM vpn_users WHERE id = ?", (user_id,)).fetchone()
    d = dict(row)
    d["password"] = password  # devolver la plana (para el flash/snippet al crear)
    return d


def get_vpn_user(user_id: int) -> Optional[dict]:
    with connect() as con:
        row = con.execute(
            "SELECT * FROM vpn_users WHERE id = ?", (user_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["password"] = crypto.decrypt(d.get("password"))  # cifrada en reposo
    return d


def delete_vpn_user(tenant: dict, user_id: int) -> None:
    user = get_vpn_user(user_id)
    if not user or user["tenant_id"] != tenant["id"]:
        raise ServiceError("Usuario no encontrado.")

    container = _ovpn_container(tenant["name"])
    if container_status(container) == "running":
        _docker_exec(container, ["deluser", "--quiet", user["username"]])
        _persist_pam(container)

    ccd = _tenant_dir(tenant["name"]) / "openvpn" / "UptimeKuma" / user["username"]
    if ccd.exists():
        ccd.unlink()

    with connect() as con:
        con.execute("DELETE FROM vpn_users WHERE id = ?", (user_id,))


# -------- NETWORKS --------

def list_networks(vpn_user_id: int) -> list[dict]:
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM vpn_networks WHERE vpn_user_id = ? ORDER BY id",
            (vpn_user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_network(network_id: int) -> Optional[dict]:
    with connect() as con:
        row = con.execute(
            "SELECT * FROM vpn_networks WHERE id = ?", (network_id,)
        ).fetchone()
    return dict(row) if row else None


def _rebuild_user_ccd(tenant: dict, user: dict) -> None:
    """Regenera el CCD del usuario desde la DB (ifconfig-push + iroutes)."""
    ccd = _tenant_dir(tenant["name"]) / "openvpn" / "UptimeKuma" / user["username"]
    lines = [f"ifconfig-push {user['ip']} {tenant['vpn_mask']}\n"]
    with connect() as con:
        rows = con.execute(
            "SELECT cidr FROM vpn_networks WHERE vpn_user_id = ? ORDER BY id",
            (user["id"],),
        ).fetchall()
    for r in rows:
        net = ipaddress.IPv4Network(r["cidr"], strict=False)
        lines.append(f"iroute {net.network_address} {net.netmask}\n")
    ccd.write_text("".join(lines), encoding="utf-8")


def _rebuild_rutas(tenant: dict) -> None:
    """Regenera rutas.sh del tenant desde la DB (todas las redes de todos los users)."""
    ccd_dir = _tenant_dir(tenant["name"]) / "openvpn" / "UptimeKuma"
    ccd_dir.mkdir(parents=True, exist_ok=True)
    rutas = ccd_dir / "rutas.sh"
    lines = ["#!/bin/sh\n"]
    with connect() as con:
        rows = con.execute(
            """SELECT n.cidr, u.ip FROM vpn_networks n
               JOIN vpn_users u ON u.id = n.vpn_user_id
               WHERE u.tenant_id = ? ORDER BY n.id""",
            (tenant["id"],),
        ).fetchall()
    for r in rows:
        lines.append(f"ip route replace {r['cidr']} via {r['ip']}\n")
    rutas.write_text("".join(lines), encoding="utf-8")
    rutas.chmod(0o755)


def add_network(tenant: dict, user_id: int, cidr: str) -> dict:
    user = get_vpn_user(user_id)
    if not user or user["tenant_id"] != tenant["id"]:
        raise ServiceError("Usuario no encontrado.")

    container = _ovpn_container(tenant["name"])
    if container_status(container) != "running":
        raise ServiceError(
            f"El contenedor {container} no está corriendo. Iniciá el tenant primero."
        )

    try:
        parsed = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as e:
        raise ServiceError(f"CIDR inválido: {e}")

    net = str(parsed.network_address)
    mask = str(parsed.netmask)
    normalized = str(parsed)

    with connect() as con:
        exists = con.execute(
            "SELECT 1 FROM vpn_networks WHERE vpn_user_id = ? AND cidr = ?",
            (user_id, normalized),
        ).fetchone()
        if exists:
            raise ServiceError("Esa red ya está agregada para este usuario.")

    with connect() as con:
        cur = con.execute(
            "INSERT INTO vpn_networks (vpn_user_id, cidr, created_at) VALUES (?, ?, ?)",
            (user_id, normalized, now_iso()),
        )
        nid = cur.lastrowid
        row = con.execute("SELECT * FROM vpn_networks WHERE id = ?", (nid,)).fetchone()

    _rebuild_user_ccd(tenant, user)
    _rebuild_rutas(tenant)

    # SIGHUP recarga config + re-ejecuta rutas.sh + relee CCD sin destruir el netns.
    # Kuma no se entera; los Mikrotik clients hacen reconnect breve.
    _docker_exec(container, ["sh", "-c", "kill -HUP 1"])

    return dict(row)


def delete_network(tenant: dict, user_id: int, network_id: int) -> None:
    user = get_vpn_user(user_id)
    if not user or user["tenant_id"] != tenant["id"]:
        raise ServiceError("Usuario no encontrado.")

    network = get_network(network_id)
    if not network or network["vpn_user_id"] != user_id:
        raise ServiceError("Red no encontrada.")

    container = _ovpn_container(tenant["name"])
    if container_status(container) != "running":
        raise ServiceError(
            f"El contenedor {container} no está corriendo. Iniciá el tenant primero."
        )

    with connect() as con:
        con.execute("DELETE FROM vpn_networks WHERE id = ?", (network_id,))

    _rebuild_user_ccd(tenant, user)
    _rebuild_rutas(tenant)

    # ip route replace en rutas.sh no quita rutas eliminadas. Hay que borrarla viva del kernel.
    _docker_exec(container, ["ip", "route", "del", network["cidr"]])
    _docker_exec(container, ["sh", "-c", "kill -HUP 1"])


def mikrotik_snippet(tenant: dict, user: dict) -> dict:
    ip = tenant["public_ip"]
    port = tenant["vpn_port"]
    name = tenant["name"]
    pwd = user["password"]
    usr = user["username"]
    common = f"add connect-to={ip} port={port}"
    suffix = f"auth=sha1 certificate=none disabled=no name=vpn-{name} password={pwd} user={usr}"
    return {
        "v6": (
            "/interface ovpn-client\n"
            f"{common} cipher=aes256 {suffix}"
        ),
        "v7": (
            "/interface ovpn-client\n"
            f"{common} protocol=tcp cipher=aes256-cbc {suffix}"
        ),
    }
