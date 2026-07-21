import ipaddress
import re
import secrets
import shutil
import sqlite3
import string
import subprocess
import time
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
    """Dominio asignado al tenant: <tenant>.<tenants_domain> si hay dominio, si no "" """
    if not tenant:
        return ""
    try:
        import settings_service
        base = settings_service.get_network_config().get("tenants_domain", "").strip()
        if base:
            return f"{tenant['name']}.{base}"
    except Exception:
        pass
    return ""


def kuma_url(tenant: dict) -> str:
    """URL pública del Uptime Kuma de un tenant.
    Si hay tenants_domain configurado: https://<tenant>.<tenants_domain> (con HTTPS o HTTP).
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

    public_ip = _resolve_public_ip()

    # Reservar slot + fila PRIMERO. El UNIQUE(slot) evita que dos create_tenant
    # concurrentes tomen el mismo slot; si choca, se reintenta con otro slot y así
    # NO quedan directorios/compose huérfanos (se crean recién tras reservar).
    tenant = None
    last_err = None
    for _attempt in range(5):
        slot = _allocate_slot()
        cand = {
            "name": name,
            "slot": slot,
            "vpn_port": config.VPN_PORT_BASE + slot,
            "kuma_port": config.KUMA_PORT_BASE + slot,
            "vpn_subnet": f"{config.VPN_SUBNET_PREFIX}.{slot}.0",
            "vpn_mask": "255.255.255.0",
            "docker_subnet": f"{config.DOCKER_SUBNET_PREFIX}.{slot}.0/24",
            "wg_port": config.WG_PORT_BASE + slot,
            "wg_subnet": f"{config.WG_SUBNET_PREFIX}.{slot}.0",
            "public_ip": public_ip,
            "created_at": now_iso(),
        }
        try:
            with connect() as con:
                con.execute(
                    """
                    INSERT INTO tenants
                    (name, slot, vpn_port, kuma_port, vpn_subnet, vpn_mask,
                     docker_subnet, wg_port, wg_subnet, public_ip, owner_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cand["name"], cand["slot"], cand["vpn_port"],
                        cand["kuma_port"], cand["vpn_subnet"], cand["vpn_mask"],
                        cand["docker_subnet"], cand["wg_port"], cand["wg_subnet"],
                        cand["public_ip"], owner["id"], cand["created_at"],
                    ),
                )
            tenant = cand
            break
        except sqlite3.IntegrityError as e:
            last_err = e  # slot (o name) lo tomó otro create concurrente → reintentar
    if tenant is None:
        raise ServiceError(f"No se pudo asignar slot para el tenant: {last_err}")

    # A partir de acá el tenant ya está en DB: si crear archivos o levantar los
    # contenedores falla, se hace ROLLBACK (borrar fila + directorio) para no dejar
    # el tenant a medias.
    try:
        tdir = _tenant_dir(name)
        (tdir / "openvpn").mkdir(parents=True, exist_ok=True)
        (tdir / "kuma").mkdir(parents=True, exist_ok=True)
        compose_text = _render_compose(tenant)
        _compose_file(name).write_text(compose_text, encoding="utf-8")
        compose_up(name)
    except Exception:
        try:
            with connect() as con:
                con.execute("DELETE FROM tenants WHERE name = ?", (name,))
        except Exception:
            pass
        shutil.rmtree(_tenant_dir(name), ignore_errors=True)
        raise

    return get_tenant(name)


def compose_up(name: str) -> None:
    _run(
        ["docker", "compose", "-f", str(_compose_file(name)), "up", "-d"],
    )


def ensure_compose_current(name: str) -> bool:
    """Re-renderiza el docker-compose.yml del tenant y, si cambió respecto al que
    está en disco, recrea los contenedores.

    Hace falta porque el compose se escribe una sola vez al crear el tenant: los
    tenants creados antes de WireGuard no publican el puerto UDP ni reciben las
    variables WG_*. Devuelve True si hubo recreación.

    Recrear `openvpn` destruye su netns y kuma (network_mode: service:openvpn)
    quedaría apuntando al viejo → hay que recrear kuma también, no basta restart.
    """
    tenant = get_tenant(name)
    if not tenant:
        raise ServiceError("Tenant no encontrado.")
    desired = _render_compose(tenant)
    path = _compose_file(name)
    try:
        current = path.read_text(encoding="utf-8")
    except OSError:
        current = ""
    if current == desired:
        return False
    path.write_text(desired, encoding="utf-8")
    f = str(path)
    _run(["docker", "compose", "-f", f, "up", "-d", "openvpn"])

    # Kuma no puede entrar al netns de openvpn mientras éste no esté corriendo
    # ("cannot join network namespace of container ... is restarting"): esperamos.
    ovpn = _ovpn_container(name)
    for _ in range(30):
        if container_status(ovpn) == "running":
            break
        time.sleep(1)
    else:
        raise ServiceError(
            f"El contenedor {ovpn} no llegó a estado running tras actualizar el "
            f"compose. Revisá `docker logs {ovpn}`."
        )

    _run(["docker", "compose", "-f", f, "up", "-d", "--force-recreate", "kuma"])
    return True


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
    Necesario después de adduser/chpasswd/deluser para sobrevivir recreaciones.
    Si el cp falla, se PROPAGA el error: de lo contrario la operación reporta éxito
    pero los usuarios PAM se pierden al recrear el contenedor (dejan de autenticar)."""
    r = _docker_exec(container, ["sh", "-c",
        "mkdir -p /etc/openvpn/auth && "
        "cp /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/openvpn/auth/"])
    if r.returncode != 0:
        raise ServiceError(f"No se pudieron persistir los usuarios PAM: {r.stderr or r.stdout}")


def _decrypt_user(d: dict) -> dict:
    """Descifra los secretos de un usuario VPN (cifrados en reposo)."""
    d["password"] = crypto.decrypt(d.get("password"))
    for k in ("wg_priv", "wg_psk"):
        if d.get(k):
            d[k] = crypto.decrypt(d[k])
    return d


def list_vpn_users(tenant_id: int) -> list[dict]:
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM vpn_users WHERE tenant_id = ? ORDER BY id",
            (tenant_id,),
        ).fetchall()
    return [_decrypt_user(dict(r)) for r in rows]


def _user_subnet(tenant: dict, proto: str) -> str:
    """Subred del tenant según protocolo. WireGuard usa una propia para no
    solaparse con la de OpenVPN (que rutea con topology subnet sobre tun0)."""
    if proto == "wireguard":
        base = tenant.get("wg_subnet") or f"{config.WG_SUBNET_PREFIX}.{tenant['slot']}.0"
        return base
    return tenant["vpn_subnet"]


def _next_vpn_ip(tenant: dict, proto: str = "openvpn") -> str:
    with connect() as con:
        used = {
            r["ip"]
            for r in con.execute(
                "SELECT ip FROM vpn_users WHERE tenant_id = ?",
                (tenant["id"],),
            )
        }
    net = ipaddress.IPv4Network(f"{_user_subnet(tenant, proto)}/24", strict=False)
    server_ip = str(net.network_address + 1)  # .1 = servidor (OpenVPN topology subnet / wg0)
    for host in net.hosts():
        ip = str(host)
        if ip == server_ip or ip in used:
            continue
        return ip
    raise ServiceError("No quedan IPs libres en el rango VPN del tenant.")


def add_vpn_user(tenant: dict, proto: str = "openvpn") -> dict:
    if proto not in ("openvpn", "wireguard"):
        raise ServiceError(f"Protocolo desconocido: {proto}")
    if proto == "wireguard":
        return _add_wg_user(tenant)

    container = _ovpn_container(tenant["name"])
    if container_status(container) != "running":
        raise ServiceError(
            f"El contenedor {container} no está corriendo. Iniciá el tenant primero."
        )

    username = _random_token(12)
    password = _random_token(12)

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

    # Selección de IP + INSERT con reintento: el UNIQUE(tenant_id, ip) hace que dos
    # add_vpn_user concurrentes no compartan IP (antes ambos elegían la misma y los
    # dos INSERT pasaban → CCD con ifconfig-push duplicado → ruteo roto). Si choca,
    # se recalcula la IP libre (ya excluyendo la que tomó el otro) y se reintenta.
    user_id = None
    last_err = None
    for _attempt in range(10):
        ip = _next_vpn_ip(tenant)
        ccd = _tenant_dir(tenant["name"]) / "openvpn" / "UptimeKuma" / username
        ccd.parent.mkdir(parents=True, exist_ok=True)
        ccd.write_text(f"ifconfig-push {ip} {tenant['vpn_mask']}\n", encoding="utf-8")
        try:
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
            break
        except sqlite3.IntegrityError as e:
            last_err = e  # IP (o username) tomada por un insert concurrente → reintentar
    if user_id is None:
        raise ServiceError(f"No se pudo asignar IP VPN al usuario: {last_err}")
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
    return _decrypt_user(dict(row))


def delete_vpn_user(tenant: dict, user_id: int) -> None:
    user = get_vpn_user(user_id)
    if not user or user["tenant_id"] != tenant["id"]:
        raise ServiceError("Usuario no encontrado.")

    container = _ovpn_container(tenant["name"])
    running = container_status(container) == "running"

    # Las redes del usuario se borran en cascada (FK ON DELETE CASCADE), pero las
    # rutas vivas del kernel no: hay que sacarlas a mano antes de perder los CIDR.
    cidrs = [n["cidr"] for n in list_networks(user_id)]

    if user.get("proto") == "wireguard":
        with connect() as con:
            con.execute("DELETE FROM vpn_users WHERE id = ?", (user_id,))
        if running:
            for cidr in cidrs:
                _docker_exec(container, ["ip", "route", "del", cidr])
            _rebuild_wg(tenant)
        return

    if running:
        _docker_exec(container, ["deluser", "--quiet", user["username"]])
        _persist_pam(container)

    ccd = _tenant_dir(tenant["name"]) / "openvpn" / "UptimeKuma" / user["username"]
    if ccd.exists():
        ccd.unlink()

    with connect() as con:
        con.execute("DELETE FROM vpn_users WHERE id = ?", (user_id,))

    # rutas.sh se regenera desde la DB: si no, las rutas del usuario borrado
    # seguirían reapareciendo en cada arranque del contenedor.
    _rebuild_rutas(tenant)
    if running:
        for cidr in cidrs:
            _docker_exec(container, ["ip", "route", "del", cidr])


# -------- WIREGUARD --------
# WireGuard corre en el MISMO contenedor y netns que OpenVPN, así Uptime Kuma
# alcanza por igual a peers WG y clientes OVPN. La config de wg0 se genera siempre
# desde la DB y se aplica en caliente con `wg syncconf` (no corta a los demás peers).

def _wg_dir(tenant_name: str) -> Path:
    return _tenant_dir(tenant_name) / "openvpn" / "wg"


def _wg_server_key(tenant: dict, which: str) -> str:
    """Clave del servidor WG del tenant, leída del bind-mount ('server.key'/'server.pub').
    Las genera el entrypoint en el primer arranque; vacío si aún no existen."""
    try:
        return (_wg_dir(tenant["name"]) / which).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _wg_port(tenant: dict) -> int:
    return int(tenant.get("wg_port") or (config.WG_PORT_BASE + tenant["slot"]))


def _wg_users(tenant_id: int) -> list[dict]:
    return [u for u in list_vpn_users(tenant_id) if u.get("proto") == "wireguard"]


def _rebuild_wg(tenant: dict) -> None:
    """Regenera wg0.conf desde la DB y lo aplica en caliente.

    Formato `wg setconf` (sin Address/PostUp): la IP de wg0 y las rutas las pone el
    entrypoint. AllowedIPs del peer = su IP /32 + las LAN que tenga registradas, que
    es el equivalente WireGuard del iroute de OpenVPN.
    """
    priv = _wg_server_key(tenant, "server.key")
    if not priv:
        raise ServiceError(
            "Las claves WireGuard del tenant aún no existen. Esperá a que el "
            "contenedor termine de arrancar y reintentá."
        )

    lines = ["[Interface]\n", f"PrivateKey = {priv}\n", f"ListenPort = {_wg_port(tenant)}\n"]
    routes: list[str] = []
    for u in _wg_users(tenant["id"]):
        if not u.get("wg_pub"):
            continue
        allowed = [f"{u['ip']}/32"]
        for n in list_networks(u["id"]):
            allowed.append(n["cidr"])
            routes.append(n["cidr"])
        lines.append("\n[Peer]\n")
        lines.append(f"# {u['username']}\n")
        lines.append(f"PublicKey = {u['wg_pub']}\n")
        if u.get("wg_psk"):
            lines.append(f"PresharedKey = {u['wg_psk']}\n")
        lines.append(f"AllowedIPs = {', '.join(allowed)}\n")

    wg_dir = _wg_dir(tenant["name"])
    wg_dir.mkdir(parents=True, exist_ok=True)
    conf = wg_dir / "wg0.conf"
    conf.write_text("".join(lines), encoding="utf-8")
    conf.chmod(0o600)

    container = _ovpn_container(tenant["name"])
    if container_status(container) != "running":
        return  # al arrancar, el entrypoint aplica el conf que acabamos de escribir

    r = _docker_exec(container, ["wg", "syncconf", "wg0", "/etc/openvpn/wg/wg0.conf"])
    if r.returncode != 0:
        raise ServiceError(f"No se pudo aplicar la config WireGuard: {r.stderr or r.stdout}")
    for cidr in routes:
        _docker_exec(container, ["ip", "route", "replace", cidr, "dev", "wg0"])


def _add_wg_user(tenant: dict) -> dict:
    # El compose de tenants creados antes de WireGuard no publica el puerto UDP ni
    # pasa las WG_*: se reconcilia acá, la primera vez que hace falta.
    ensure_compose_current(tenant["name"])

    container = _ovpn_container(tenant["name"])
    if container_status(container) != "running":
        raise ServiceError(
            f"El contenedor {container} no está corriendo. Iniciá el tenant primero."
        )

    def _wg(cmd: list[str], stdin: Optional[str] = None) -> str:
        r = _docker_exec(container, cmd, input_data=stdin)
        if r.returncode != 0 or not r.stdout.strip():
            raise ServiceError(f"`wg {' '.join(cmd[1:])}` falló: {r.stderr or r.stdout}")
        return r.stdout.strip()

    priv = _wg(["wg", "genkey"])
    pub = _wg(["wg", "pubkey"], stdin=priv + "\n")
    psk = _wg(["wg", "genpsk"])

    username = _random_token(12)
    user_id = None
    last_err = None
    for _attempt in range(10):
        ip = _next_vpn_ip(tenant, "wireguard")
        try:
            with connect() as con:
                cur = con.execute(
                    """
                    INSERT INTO vpn_users
                    (tenant_id, username, password, ip, proto, wg_priv, wg_pub, wg_psk, created_at)
                    VALUES (?, ?, '', ?, 'wireguard', ?, ?, ?, ?)
                    """,
                    (
                        tenant["id"], username, ip,
                        crypto.encrypt(priv), pub, crypto.encrypt(psk), now_iso(),
                    ),
                )
                user_id = cur.lastrowid
                row = con.execute("SELECT * FROM vpn_users WHERE id = ?", (user_id,)).fetchone()
            break
        except sqlite3.IntegrityError as e:
            last_err = e  # IP tomada por un insert concurrente → reintentar
    if user_id is None:
        raise ServiceError(f"No se pudo asignar IP WireGuard al usuario: {last_err}")

    _rebuild_wg(tenant)

    d = _decrypt_user(dict(row))
    d["password"] = ""  # WireGuard autentica por claves, no por usuario/contraseña
    return d


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
    """Regenera rutas.sh del tenant desde la DB (redes de los usuarios OpenVPN).

    Solo OpenVPN: la IP de un peer WireGuard no es alcanzable como next-hop por tun0,
    y sus rutas ya las maneja wg0 vía AllowedIPs.
    """
    ccd_dir = _tenant_dir(tenant["name"]) / "openvpn" / "UptimeKuma"
    ccd_dir.mkdir(parents=True, exist_ok=True)
    rutas = ccd_dir / "rutas.sh"
    lines = ["#!/bin/sh\n"]
    with connect() as con:
        rows = con.execute(
            """SELECT n.cidr, u.ip FROM vpn_networks n
               JOIN vpn_users u ON u.id = n.vpn_user_id
               WHERE u.tenant_id = ? AND u.proto = 'openvpn' ORDER BY n.id""",
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

    if user.get("proto") == "wireguard":
        # En WireGuard la red del cliente es un AllowedIPs más en su peer.
        _rebuild_wg(tenant)
        return dict(row)

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

    if user.get("proto") == "wireguard":
        _rebuild_wg(tenant)
        # syncconf saca el AllowedIPs, pero la ruta viva del kernel queda.
        _docker_exec(container, ["ip", "route", "del", network["cidr"]])
        return

    _rebuild_user_ccd(tenant, user)
    _rebuild_rutas(tenant)

    # ip route replace en rutas.sh no quita rutas eliminadas. Hay que borrarla viva del kernel.
    _docker_exec(container, ["ip", "route", "del", network["cidr"]])
    _docker_exec(container, ["sh", "-c", "kill -HUP 1"])


def _tenant_ca(tenant: dict) -> str:
    """CA del tenant, leída directo del bind-mount del contenedor OpenVPN
    ({BASE_PATH}/tenants/<name>/openvpn/server/ca.crt). Vacío si aún no existe."""
    ca_path = config.TENANTS_DIR / tenant["name"] / "openvpn" / "server" / "ca.crt"
    try:
        return ca_path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _wg_client_allowed(tenant: dict, user: dict) -> str:
    """AllowedIPs del lado cliente: qué manda al túnel. Incluye las dos subredes del
    hub (WireGuard y OpenVPN) más las LAN registradas de los demás usuarios, para que
    un peer WG alcance lo mismo que alcanza un cliente OpenVPN."""
    nets = [
        f"{_user_subnet(tenant, 'wireguard')}/24",
        f"{tenant['vpn_subnet']}/24",
    ]
    own = {n["cidr"] for n in list_networks(user["id"])}
    with connect() as con:
        rows = con.execute(
            """SELECT DISTINCT n.cidr FROM vpn_networks n
               JOIN vpn_users u ON u.id = n.vpn_user_id
               WHERE u.tenant_id = ? ORDER BY n.cidr""",
            (tenant["id"],),
        ).fetchall()
    nets.extend(r["cidr"] for r in rows if r["cidr"] not in own)
    return ", ".join(nets)


def wireguard_conf(tenant: dict, user: dict) -> str:
    """Config wg-quick lista para el cliente (Linux, Windows, móvil)."""
    server_pub = _wg_server_key(tenant, "server.pub")
    if not server_pub:
        return ""
    psk = f"PresharedKey = {user['wg_psk']}\n" if user.get("wg_psk") else ""
    return (
        "[Interface]\n"
        f"PrivateKey = {user['wg_priv']}\n"
        f"Address = {user['ip']}/24\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"{psk}"
        f"Endpoint = {tenant['public_ip']}:{_wg_port(tenant)}\n"
        f"AllowedIPs = {_wg_client_allowed(tenant, user)}\n"
        "PersistentKeepalive = 25\n"
    )


def _debian_wg_snippet(tenant: dict, user: dict) -> str:
    conf = wireguard_conf(tenant, user)
    if not conf:
        return ("# Las claves WireGuard del tenant aún no están disponibles — esperá a "
                "que el contenedor termine de arrancar y recargá la página.")
    name = f"vpn-{tenant['name']}"
    return f"""# ===== Conectar este equipo Debian/Ubuntu por WireGuard — pegar TODO como root =====
apt-get update && apt-get install -y wireguard
cat > /etc/wireguard/{name}.conf <<'MAATEOF'
{conf.rstrip()}
MAATEOF
chmod 600 /etc/wireguard/{name}.conf
systemctl enable --now wg-quick@{name}
sleep 2 && wg show {name}
# ===== Listo: arranca solo al boot; WireGuard reconecta solo ====="""


def _mikrotik_wg_snippet(tenant: dict, user: dict) -> dict:
    server_pub = _wg_server_key(tenant, "server.pub")
    if not server_pub:
        return {}
    iface = f"wg-{tenant['name']}"
    psk = f' preshared-key="{user["wg_psk"]}"' if user.get("wg_psk") else ""
    return {
        # RouterOS v6 NO tiene WireGuard: esos equipos van por OpenVPN.
        "v7": (
            "/interface/wireguard\n"
            f'add name={iface} private-key="{user["wg_priv"]}" listen-port={_wg_port(tenant)}\n'
            "/ip/address\n"
            f"add address={user['ip']}/24 interface={iface}\n"
            "/interface/wireguard/peers\n"
            f'add interface={iface} public-key="{server_pub}"{psk} '
            f"endpoint-address={tenant['public_ip']} endpoint-port={_wg_port(tenant)} "
            f"allowed-address={_wg_client_allowed(tenant, user).replace(', ', ',')} "
            "persistent-keepalive=25s"
        ),
    }


def debian_snippet(tenant: dict, user: dict) -> str:
    """Instalador copy-paste para un equipo Debian/Ubuntu: instala OpenVPN,
    escribe config + credenciales (600), deja el servicio con auto-restart y
    habilitado al arranque (systemd). Un solo paste como root y queda conectado."""
    if user.get("proto") == "wireguard":
        return _debian_wg_snippet(tenant, user)
    ca = _tenant_ca(tenant)
    if not ca:
        return ("# La CA del tenant aún no está disponible — esperá a que el "
                "contenedor OpenVPN termine de arrancar y recargá la página.")
    name = f"vpn-{tenant['name']}"
    return f"""# ===== Conectar este equipo Debian/Ubuntu a la VPN — pegar TODO como root =====
apt-get update && apt-get install -y openvpn
mkdir -p /etc/openvpn/client
cat > /etc/openvpn/client/{name}.conf <<'MAATEOF'
client
dev tun
proto tcp
remote {tenant['public_ip']} {tenant['vpn_port']}
resolv-retry infinite
nobind
persist-key
persist-tun
auth SHA1
data-ciphers AES-256-CBC
data-ciphers-fallback AES-256-CBC
auth-user-pass /etc/openvpn/client/{name}.auth
verb 3
<ca>
{ca}
</ca>
MAATEOF
cat > /etc/openvpn/client/{name}.auth <<'MAATEOF'
{user['username']}
{user['password']}
MAATEOF
chmod 600 /etc/openvpn/client/{name}.conf /etc/openvpn/client/{name}.auth
mkdir -p /etc/systemd/system/openvpn-client@{name}.service.d
printf '[Service]\\nRestart=always\\nRestartSec=10\\n' > /etc/systemd/system/openvpn-client@{name}.service.d/restart.conf
systemctl daemon-reload
systemctl enable --now openvpn-client@{name}
sleep 3 && systemctl --no-pager status openvpn-client@{name} | head -3 && ip -4 addr show tun0 | grep inet
# ===== Listo: arranca solo al boot y se reconecta solo si se cae ====="""


def mikrotik_snippet(tenant: dict, user: dict) -> dict:
    if user.get("proto") == "wireguard":
        return _mikrotik_wg_snippet(tenant, user)
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
