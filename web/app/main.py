import subprocess
import threading
import time

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import config
import auth
import crypto
import db
import tenant_service as svc

# SESSION_SECRET fuerte: si el env está ausente o quedó en el placeholder débil,
# usamos una clave aleatoria persistida en el volumen (evita firmar cookies con un
# secreto predecible = auth-bypass como admin).
_SESSION_SECRET = config.SESSION_SECRET
if (not _SESSION_SECRET) or _SESSION_SECRET == "change-me-please-32chars-minimum":
    _SESSION_SECRET = crypto.session_secret_fallback()

# Tamaños de página permitidos para listados
ALLOWED_PAGE_SIZES = (10, 15, 20, 50, 100)
DEFAULT_PAGE_SIZE = 20


def _paginate(page: int, page_size: int) -> tuple[int, int, int]:
    """Normaliza page (>=1) y page_size (whitelist). Devuelve (page, page_size, offset)."""
    if page_size not in ALLOWED_PAGE_SIZES:
        page_size = DEFAULT_PAGE_SIZE
    if page < 1:
        page = 1
    return page, page_size, (page - 1) * page_size

import user_service as usr
import billing_service as billing
import payphone_service as payphone
import caddy_service as caddy
import certbot_service as certbot
import cf_origin_service as cf_origin
import cloudflare_service as cloudflare
import email_service as mail
import settings_service as settings
import notify_service as notify
import event_service as events
import system_stats
import favicon_gen
import security


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return fwd or (request.client.host if request.client else "")


def _tenant_owner(tenant: dict):
    """Devuelve el dict del usuario dueño del tenant, o None."""
    if not tenant or not tenant.get("owner_id"):
        return None
    return usr.get_user(tenant["owner_id"])


def _prewarm_images() -> None:
    try:
        subprocess.run(
            ["docker", "pull", settings.kuma_image()],
            capture_output=True,
            timeout=600,
        )
    except Exception:
        pass


def _payment_reminder_loop() -> None:
    """Cada hora barre usuarios con paid_until cerca de vencer y manda aviso
    Telegram + email. Idempotente vía payment_warning_sent_for."""
    while True:
        try:
            billing.send_payment_reminders(notify, mail)
        except Exception as e:
            print(f"[payment-reminder] error: {e}")
        time.sleep(3600)


app = FastAPI(title="KumaVPN Admin")
# Headers de seguridad globales (X-Frame-Options, CSP, HSTS condicional, etc.)
app.add_middleware(security.SecurityHeadersMiddleware)
# Cookie session: SameSite=strict mitiga CSRF en forms POST.
# Secure flag se activa cuando SECURE_COOKIES=1 en env (HTTPS atrás).
app.add_middleware(
    SessionMiddleware,
    secret_key=_SESSION_SECRET,
    https_only=security.secure_cookies_enabled(),
    # 'lax' (no 'strict'): permite enviar cookie en navigation top-level
    # GET incluyendo después del 303 redirect post-login (que con 'strict'
    # algunos browsers omitían, dejando al user en loop de login).
    # Igual de seguro contra CSRF: POST cross-site no envía cookie con lax.
    same_site="lax",
    max_age=60 * 60 * 24 * 7,  # 7 días
)

templates = Jinja2Templates(directory=str(config.TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(config.TEMPLATES_DIR.parent / "static")), name="static")


@app.on_event("startup")
def _startup():
    config.BASE_PATH.mkdir(parents=True, exist_ok=True)
    config.TENANTS_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db()
    seeded = usr.seed_initial_admin(config.ADMIN_USER, config.ADMIN_PASSWORD_HASH)
    if seeded:
        print(f"[startup] admin inicial creado desde env: {seeded['username']}")
    favicon_gen.ensure_favicons(config.TEMPLATES_DIR.parent / "static")
    threading.Thread(target=_prewarm_images, daemon=True).start()
    threading.Thread(target=_payment_reminder_loop, daemon=True).start()
    certbot.start_renewal_thread()


def _flash(request: Request, msg: str, level: str = "info"):
    request.session["flash"] = {"msg": msg, "level": level}


def _pop_flash(request: Request):
    return request.session.pop("flash", None)


class AuthRequired(Exception):
    pass


class Forbidden(Exception):
    pass


@app.exception_handler(AuthRequired)
async def _auth_required_handler(request: Request, exc: AuthRequired):
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(Forbidden)
async def _forbidden_handler(request: Request, exc: Forbidden):
    _flash(request, "No tenés permiso para esa acción.", "error")
    return RedirectResponse("/", status_code=303)


class MustChangePassword(Exception):
    pass


class PaymentRequired(Exception):
    pass


@app.exception_handler(MustChangePassword)
async def _must_change_handler(request: Request, exc: MustChangePassword):
    return RedirectResponse("/change-password", status_code=303)


@app.exception_handler(PaymentRequired)
async def _payment_required_handler(request: Request, exc: PaymentRequired):
    # No cierra sesión: el cliente sigue logueado para poder ir a pagar.
    return RedirectResponse("/me/billing", status_code=303)


def current_user(request: Request) -> dict:
    user = auth.session_user(request)
    if not user:
        raise AuthRequired()
    # Bloqueo si esta desactivado: cierra sesion + redirige a login
    if not usr.is_active(user):
        request.session.clear()
        _flash(request, "Tu cuenta fue desactivada. Contactá al administrador.", "error")
        raise AuthRequired()
    # Si tiene flag, redirigir a /change-password (excepto si ya está en esa ruta o haciendo logout)
    path = request.url.path
    if user.get("must_change_password") and path not in ("/change-password", "/logout"):
        raise MustChangePassword()
    return user


def require_paid(request: Request, user: dict) -> None:
    """Bloquea operaciones que requieren cuenta al día Y plan asignado.
    Admin siempre puede. Cliente: requiere is_paid + assigned_plan_id."""
    if user["role"] == "admin":
        return
    # Sin plan asignado: bloqueado independientemente de paid_until
    if not user.get("assigned_plan_id"):
        _flash(
            request,
            "Tu cuenta aún no tiene un plan asignado. Contactá al administrador para que te asigne uno.",
            "error",
        )
        raise PaymentRequired()
    if not billing.is_paid(user):
        _flash(
            request,
            "Tu cuenta no está al día. Renová tu suscripción para crear tenants.",
            "error",
        )
        raise PaymentRequired()


def current_admin(request: Request) -> dict:
    user = current_user(request)
    if user["role"] != "admin":
        raise Forbidden()
    return user


def _require_tenant_access(user: dict, tenant: dict) -> None:
    if user["role"] == "admin":
        return
    if tenant.get("owner_id") != user["id"]:
        raise Forbidden()


# -------- AUTH --------

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if auth.session_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "user": None, "flash": _pop_flash(request)},
    )


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = _client_ip(request)
    uname = username.strip().lower()

    # Rate limit / lockout antes de procesar (evita brute force con bcrypt costoso)
    locked, msg = security.is_locked(ip, uname)
    if locked:
        events.log(
            "login_locked", "auth",
            actor_username=uname, severity="warn",
            details=msg, ip=ip,
        )
        _flash(request, msg, "error")
        return RedirectResponse("/login", status_code=303)

    user = auth.authenticate(uname, password)
    security.record_attempt(ip, uname, success=bool(user))

    if user:
        if not usr.is_active(user):
            events.log(
                "login_blocked_inactive", "auth",
                actor=user, severity="warn",
                details="cuenta desactivada por admin", ip=ip,
            )
            _flash(request, "Tu cuenta está desactivada. Contactá al administrador.", "error")
            return RedirectResponse("/login", status_code=303)
        security.reset_user_attempts(uname)
        request.session["user_id"] = user["id"]
        events.log("login_success", "auth", actor=user, ip=ip)
        return RedirectResponse("/", status_code=303)

    events.log(
        "login_fail", "auth",
        actor_username=uname,
        severity="warn",
        details="contraseña inválida o usuario inexistente",
        ip=ip,
    )
    _flash(request, "Credenciales inválidas.", "error")
    return RedirectResponse("/login", status_code=303)


@app.post("/logout")
def logout(request: Request):
    user = auth.session_user(request)
    if user:
        events.log("logout", "auth", actor=user, ip=_client_ip(request))
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# -------- CHANGE PASSWORD (cualquier user logueado) --------

@app.get("/change-password", response_class=HTMLResponse)
def change_password_form(request: Request, user: dict = Depends(current_user)):
    return templates.TemplateResponse(
        "change_password.html",
        {"request": request, "user": user, "flash": _pop_flash(request)},
    )


@app.post("/change-password")
def change_password_submit(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: dict = Depends(current_user),
):
    if not usr.verify_password(current_password, user["password_hash"]):
        _flash(request, "La password actual no es correcta.", "error")
        return RedirectResponse("/change-password", status_code=303)
    if new_password != confirm_password:
        _flash(request, "La nueva password y la confirmación no coinciden.", "error")
        return RedirectResponse("/change-password", status_code=303)
    if new_password == current_password:
        _flash(request, "La nueva password no puede ser igual a la actual.", "error")
        return RedirectResponse("/change-password", status_code=303)
    try:
        usr.update_user(
            user["id"],
            new_password=new_password,
            enforce_complexity=True,
            clear_must_change=True,
        )
    except usr.UserError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/change-password", status_code=303)
    events.log("password_changed", "auth", actor=user, ip=_client_ip(request))
    _flash(request, "Password actualizada correctamente.", "success")
    return RedirectResponse("/", status_code=303)


# -------- DASHBOARD / TENANTS --------

def _compute_dashboard_stats(user: dict) -> tuple[list[dict], dict]:
    if user["role"] == "admin":
        tenants = svc.list_tenants()
    else:
        tenants = svc.list_tenants(owner_id=user["id"])

    statuses = svc.container_statuses_bulk()
    services_total = 0
    services_running = 0
    for t in tenants:
        ovpn = statuses.get(f"openvpn-{t['name']}", "missing")
        kuma = statuses.get(f"kuma-{t['name']}", "missing")
        t["ovpn_status"] = ovpn
        t["kuma_status"] = kuma
        services_total += 2
        if ovpn == "running": services_running += 1
        if kuma == "running": services_running += 1

    if user["role"] == "admin":
        all_users = usr.list_users()
        clientes_count = sum(1 for u in all_users if u["role"] == "user")
    else:
        clientes_count = None

    stats = {
        "clientes": clientes_count,
        "tenants": len(tenants),
        "services_total": services_total,
        "running": services_running,
        "stopped": services_total - services_running,
    }
    return tenants, stats


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: dict = Depends(current_user)):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "flash": _pop_flash(request),
        },
    )


@app.get("/api/stats")
def api_stats(user: dict = Depends(current_user)):
    _, stats = _compute_dashboard_stats(user)
    payload: dict = {
        "stats": stats,
        "me": {
            "paid_until": user.get("paid_until"),
            "days_until_due": billing.days_until_due(user),
            "is_paid": billing.is_paid(user),
        },
    }
    if user["role"] == "admin":
        payload["sys"] = system_stats.host_stats()
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


@app.get("/tenants", response_class=HTMLResponse)
def tenants_list(request: Request, q: str = "", user: dict = Depends(current_user)):
    return templates.TemplateResponse(
        "tenants.html",
        {
            "request": request,
            "user": user,
            "q": q,
            "flash": _pop_flash(request),
        },
    )


@app.get("/api/tenants")
def api_tenants(
    q: str = "",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    user: dict = Depends(current_user),
):
    page, page_size, offset = _paginate(page, page_size)
    owner_id = None if user["role"] == "admin" else user["id"]
    tenants = svc.list_tenants(owner_id=owner_id, search=q or None,
                                limit=page_size, offset=offset)
    total = svc.count_tenants(owner_id=owner_id, search=q or None)

    statuses = svc.container_statuses_bulk()
    for t in tenants:
        t["ovpn_status"] = statuses.get(f"openvpn-{t['name']}", "missing")
        t["kuma_status"] = statuses.get(f"kuma-{t['name']}", "missing")
        t["kuma_url"] = svc.kuma_url(t)
        t["domain"] = svc.tenant_domain(t)

    quota_info = None
    if user["role"] == "user":
        quota_info = {
            "used": usr.count_user_tenants(user["id"]),
            "total": user.get("tenant_quota") or 0,
        }
    return JSONResponse(
        {
            "tenants": tenants, "quota": quota_info, "q": q,
            "page": page, "page_size": page_size, "total": total,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        },
        headers={"Cache-Control": "no-store"},
    )


@app.get("/tenants/new", response_class=HTMLResponse)
def new_tenant_form(request: Request, user: dict = Depends(current_user)):
    require_paid(request, user)
    return templates.TemplateResponse(
        "new_tenant.html",
        {"request": request, "user": user, "flash": _pop_flash(request),
         "kuma_default": settings.get_kuma_tag()},
    )


@app.post("/tenants/new")
def new_tenant_submit(
    request: Request,
    name: str = Form(...),
    kuma_tag: str = Form(""),
    user: dict = Depends(current_user),
):
    require_paid(request, user)
    name = name.strip().lower()
    try:
        svc.create_tenant(name, owner=user, kuma_tag=kuma_tag or None)
    except svc.ServiceError as e:
        notify.send_admin(f"⚠️ <b>Error creando tenant</b>\nNombre: <code>{name}</code>\nUsuario: {user['username']}\nError: {e}")
        _flash(request, str(e), "error")
        return RedirectResponse("/tenants/new", status_code=303)
    except Exception as e:
        notify.send_admin(f"❌ <b>Error inesperado creando tenant</b>\nNombre: <code>{name}</code>\nError: {e}")
        _flash(request, f"Error inesperado: {e}", "error")
        return RedirectResponse("/tenants/new", status_code=303)

    t = svc.get_tenant(name)
    # Cloudflare: dar la orden de crear el registro DNS del subdominio del tenant
    # apuntando a la IP del VPS (best-effort; si falla, el tenant igual queda creado).
    dns_note = ""
    try:
        nc = settings.get_network_config()
        if nc.get("tenants_domain"):
            cloudflare.create_record(f"{name}.{nc['tenants_domain']}", t["public_ip"])
    except cloudflare.CloudflareError as e:
        dns_note = f" ⚠ DNS Cloudflare falló: {e}"
        notify.send_admin(f"⚠️ Cloudflare DNS falló creando <code>{name}</code>: {e}")
    except Exception:
        pass
    # Auto-regenerar Caddyfile + reload (silencioso si Caddy no esta o no configurado)
    try:
        if caddy.is_configured():
            caddy.apply()
    except Exception:
        pass
    events.log("tenant_created", "tenant", actor=user, tenant=t, ip=_client_ip(request))
    notify.send_admin(
        f"🆕 <b>Tenant creado</b>\nNombre: <code>{name}</code>\n"
        f"Dueño: {user['username']} ({user.get('company_name') or '—'})\n"
        f"VPN: <code>{t['public_ip']}:{t['vpn_port']}/tcp</code>\n"
        f"Kuma: http://{t['public_ip']}:{t['kuma_port']}"
    )
    notify.send_user(
        user,
        f"🆕 <b>Tu tenant {name} está activo</b>\n\n"
        f"OpenVPN: <code>{t['public_ip']}:{t['vpn_port']}/tcp</code>\n"
        f"Kuma:    http://{t['public_ip']}:{t['kuma_port']}\n"
        f"Subred:  {t['vpn_subnet']}/24",
        event_key="tenant_created",
    )
    _flash(request, f"Tenant '{name}' creado y levantado.{dns_note}", "success")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.get("/tenants/{name}", response_class=HTMLResponse)
def tenant_detail(request: Request, name: str, user: dict = Depends(current_user)):
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    return templates.TemplateResponse(
        "tenant.html",
        {
            "request": request,
            "tenant_name": tenant["name"],
            "user": user,
            "flash": _pop_flash(request),
            "is_admin": user.get("role") == "admin",
            "kuma_tag": svc.tenant_kuma_tag(tenant),
            "kuma_image": svc.tenant_kuma_image(tenant),
        },
    )


@app.get("/api/tenants/{name}")
def api_tenant_detail(name: str, user: dict = Depends(current_user)):
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    users_list = svc.list_vpn_users(tenant["id"])
    conn = svc.connection_status(tenant, users_list)
    for u in users_list:
        u["connected"] = conn.get(u["id"], False)
        u["networks"] = svc.list_networks(u["id"])
        u["mikrotik"] = svc.mikrotik_snippet(tenant, u)
        u["debian"] = svc.debian_snippet(tenant, u)
        if u.get("proto") == "wireguard":
            u["wg_conf"] = svc.wireguard_conf(tenant, u)
        # La clave privada ya viaja dentro de los snippets (el cliente la necesita);
        # no hace falta duplicarla suelta en el JSON.
        u.pop("wg_priv", None)
        u.pop("wg_psk", None)
    tenant["ovpn_status"] = svc.container_status(f"openvpn-{tenant['name']}")
    tenant["kuma_status"] = svc.container_status(f"kuma-{tenant['name']}")
    tenant["kuma_url"] = svc.kuma_url(tenant)
    tenant["domain"] = svc.tenant_domain(tenant)
    return JSONResponse(
        {"tenant": tenant, "users": users_list},
        headers={"Cache-Control": "no-store"},
    )


@app.post("/tenants/{name}/users/new")
def add_user(
    request: Request,
    name: str,
    proto: str = Form("openvpn"),
    user: dict = Depends(current_user),
):
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    try:
        created = svc.add_vpn_user(tenant, proto)
        events.log("vpn_user_created", "vpn_user", actor=user, tenant=tenant,
                   details=f"username={created['username']} ip={created['ip']} proto={proto}",
                   ip=_client_ip(request))
        if created.get("proto") == "wireguard":
            msg = (f"Peer WireGuard creado: {created['username']} (IP {created['ip']}). "
                   "Copiá la config desde la columna Conectar.")
        else:
            msg = (f"Usuario VPN creado: {created['username']} / {created['password']} "
                   f"(IP {created['ip']}).")
        _flash(request, msg, "success")
    except svc.ServiceError as e:
        _flash(request, str(e), "error")
    except Exception as e:
        events.log("vpn_user_create_fail", "vpn_user", actor=user, tenant=tenant, severity="error", details=str(e))
        _flash(request, f"Error inesperado: {e}", "error")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.post("/tenants/{name}/users/{user_id}/delete")
def delete_user(request: Request, name: str, user_id: int, user: dict = Depends(current_user)):
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    try:
        svc.delete_vpn_user(tenant, user_id)
        events.log("vpn_user_deleted", "vpn_user", actor=user, tenant=tenant,
                   severity="warn", details=f"vpn_user_id={user_id}", ip=_client_ip(request))
        _flash(request, "Usuario VPN eliminado.", "success")
    except svc.ServiceError as e:
        _flash(request, str(e), "error")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.post("/tenants/{name}/users/{user_id}/networks/new")
def add_network(
    request: Request,
    name: str,
    user_id: int,
    cidr: list[str] = Form(...),
    user: dict = Depends(current_user),
):
    """Agrega una o VARIAS redes de cliente al usuario (el modal manda varios campos
    `cidr`). Best-effort: agrega las válidas y reporta las que fallen."""
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    # dedup preservando orden, ignorando vacíos
    cidrs = list(dict.fromkeys(c.strip() for c in cidr if c and c.strip()))
    if not cidrs:
        _flash(request, "Ingresá al menos un segmento (CIDR).", "error")
        return RedirectResponse(f"/tenants/{name}", status_code=303)
    added, errors = [], []
    for c in cidrs:
        try:
            svc.add_network(tenant, user_id, c)
            added.append(c)
        except svc.ServiceError as e:
            errors.append(f"{c}: {e}")
    if added:
        events.log("network_added", "network", actor=user, tenant=tenant,
                   details=f"cidrs={','.join(added)} vpn_user_id={user_id}", ip=_client_ip(request))
    msg = ""
    if added:
        msg += f"{len(added)} red(es) agregada(s): {', '.join(added)}."
    if errors:
        msg += (" " if msg else "") + "No se agregaron: " + "; ".join(errors[:4])
    _flash(request, msg or "Nada que agregar.", "success" if added and not errors else "info")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.post("/tenants/{name}/users/{user_id}/networks/{net_id}/delete")
def delete_network(
    request: Request,
    name: str,
    user_id: int,
    net_id: int,
    user: dict = Depends(current_user),
):
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    try:
        svc.delete_network(tenant, user_id, net_id)
        events.log("network_deleted", "network", actor=user, tenant=tenant,
                   severity="warn", details=f"net_id={net_id}", ip=_client_ip(request))
        _flash(request, "Red eliminada.", "success")
    except svc.ServiceError as e:
        _flash(request, str(e), "error")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.post("/tenants/{name}/restart")
def restart_tenant(request: Request, name: str, user: dict = Depends(current_user)):
    tenant = svc.get_tenant(name)
    if not tenant: raise HTTPException(404)
    _require_tenant_access(user, tenant)
    try:
        svc.compose_restart(name)
        events.log("tenant_restarted", "tenant", actor=user, tenant=tenant, ip=_client_ip(request))
        notify.send_user(_tenant_owner(tenant), f"🔄 Tenant <b>{name}</b> reiniciado por {user['username']}", event_key="tenant_restarted")
        _flash(request, "Tenant reiniciado.", "success")
    except Exception as e:
        events.log("tenant_restart_fail", "tenant", actor=user, tenant=tenant, severity="error", details=str(e))
        notify.send_admin(f"❌ Error reiniciando tenant <b>{name}</b>: {e}")
        _flash(request, f"Error reiniciando: {e}", "error")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.post("/tenants/{name}/kuma-version")
def kuma_version_tenant(
    request: Request,
    name: str,
    kuma_tag: str = Form(...),
    user: dict = Depends(current_admin),
):
    """Cambia la versión de Kuma de ESTE tenant (subir o bajar), uno a uno. Respalda
    los datos antes; al bajar restaura el respaldo de la versión destino. No toca
    openvpn → no corta el VPN. Admin-only (una subida migra la DB del Kuma)."""
    tenant = svc.get_tenant(name)
    if not tenant: raise HTTPException(404)
    try:
        ok, msg = svc.set_tenant_kuma_tag(name, kuma_tag)
        events.log("kuma_version_changed", "tenant", actor=user, tenant=tenant,
                   details=msg[:200], severity="info" if ok else "error", ip=_client_ip(request))
        _flash(request, msg, "success" if ok else "error")
    except Exception as e:
        events.log("kuma_version_fail", "tenant", actor=user, tenant=tenant,
                   severity="error", details=str(e))
        _flash(request, f"Error cambiando versión de Kuma de {name}: {e}", "error")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.post("/tenants/{name}/stop")
def stop_tenant(request: Request, name: str, user: dict = Depends(current_user)):
    tenant = svc.get_tenant(name)
    if not tenant: raise HTTPException(404)
    _require_tenant_access(user, tenant)
    try:
        svc.compose_down(name, remove_volumes=False)
        events.log("tenant_stopped", "tenant", actor=user, tenant=tenant, ip=_client_ip(request))
        notify.send_user(_tenant_owner(tenant), f"⏸️ Tenant <b>{name}</b> detenido por {user['username']}", event_key="tenant_stopped")
        _flash(request, "Tenant detenido.", "success")
    except Exception as e:
        events.log("tenant_stop_fail", "tenant", actor=user, tenant=tenant, severity="error", details=str(e))
        notify.send_admin(f"❌ Error deteniendo tenant <b>{name}</b>: {e}")
        _flash(request, f"Error deteniendo: {e}", "error")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.post("/tenants/{name}/start")
def start_tenant(request: Request, name: str, user: dict = Depends(current_user)):
    tenant = svc.get_tenant(name)
    if not tenant: raise HTTPException(404)
    _require_tenant_access(user, tenant)
    try:
        svc.compose_up(name)
        events.log("tenant_started", "tenant", actor=user, tenant=tenant, ip=_client_ip(request))
        notify.send_user(_tenant_owner(tenant), f"▶️ Tenant <b>{name}</b> iniciado por {user['username']}", event_key="tenant_started")
        _flash(request, "Tenant iniciado.", "success")
    except Exception as e:
        events.log("tenant_start_fail", "tenant", actor=user, tenant=tenant, severity="error", details=str(e))
        notify.send_admin(f"❌ Error iniciando tenant <b>{name}</b>: {e}")
        _flash(request, f"Error iniciando: {e}", "error")
    return RedirectResponse(f"/tenants/{name}", status_code=303)


@app.post("/tenants/{name}/delete")
def delete_tenant(
    request: Request,
    name: str,
    confirm: str = Form(""),
    user: dict = Depends(current_user),
):
    tenant = svc.get_tenant(name)
    if not tenant: raise HTTPException(404)
    _require_tenant_access(user, tenant)
    if confirm != name:
        _flash(request, "Confirmación no coincide. Escribí el nombre exacto del tenant.", "error")
        return RedirectResponse(f"/tenants/{name}", status_code=303)
    owner = _tenant_owner(tenant)
    try:
        svc.delete_tenant(name)
        # Cloudflare: borrar el registro DNS del subdominio del tenant (best-effort).
        try:
            nc = settings.get_network_config()
            if nc.get("tenants_domain"):
                cloudflare.delete_record(f"{name}.{nc['tenants_domain']}")
        except Exception:
            pass
        # Auto-regenerar Caddyfile + reload (silencioso si Caddy no esta o no configurado)
        try:
            if caddy.is_configured():
                caddy.apply()
        except Exception:
            pass
        events.log("tenant_deleted", "tenant", actor=user, tenant=tenant, severity="warn", ip=_client_ip(request))
        notify.send_admin(f"🗑️ Tenant <b>{name}</b> eliminado por {user['username']}")
        notify.send_user(owner, f"🗑️ Tu tenant <b>{name}</b> fue eliminado", event_key="tenant_deleted")
        _flash(request, f"Tenant '{name}' eliminado.", "success")
    except svc.ServiceError as e:
        events.log("tenant_delete_fail", "tenant", actor=user, tenant=tenant, severity="error", details=str(e))
        notify.send_admin(f"❌ Error eliminando tenant <b>{name}</b>: {e}")
        _flash(request, str(e), "error")
        return RedirectResponse(f"/tenants/{name}", status_code=303)
    return RedirectResponse("/", status_code=303)


# -------- USUARIOS (ADMIN ONLY) --------

_USER_PUBLIC_FIELDS = (
    "id", "username", "first_name", "last_name", "company_name",
    "email", "phone", "phone_cc", "role", "tenant_count", "tenant_quota",
    "created_at", "must_change_password", "paid_until", "assigned_plan_id",
    "is_active",
)


def _user_public(u: dict) -> dict:
    out = {k: u.get(k) for k in _USER_PUBLIC_FIELDS}
    out["days_until_due"] = billing.days_until_due(u)
    out["is_paid"] = billing.is_paid(u)
    plan = billing.get_assigned_plan(u)
    out["assigned_plan"] = (
        {"id": plan["id"], "name": plan["name"], "price": plan["price"],
         "currency": plan["currency"], "days": plan["days"]}
        if plan else None
    )
    return out


@app.get("/users", response_class=HTMLResponse)
def users_list(request: Request, q: str = "", user: dict = Depends(current_admin)):
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "user": user,
            "q": q,
            "flash": _pop_flash(request),
        },
    )


@app.get("/api/users")
def api_users(q: str = "", user: dict = Depends(current_admin)):
    rows = usr.list_users(search=q or None)
    safe = [_user_public(r) for r in rows]
    return JSONResponse({"users": safe, "q": q}, headers={"Cache-Control": "no-store"})


@app.get("/api/users/{user_id}")
def api_user_detail(user_id: int, user: dict = Depends(current_admin)):
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    target["tenant_count"] = usr.count_user_tenants(user_id)
    return JSONResponse(
        {"user": _user_public(target), "payments": billing.list_payments(user_id)},
        headers={"Cache-Control": "no-store"},
    )


# -------- BILLING (módulo independiente — admin) --------

@app.get("/billing", response_class=HTMLResponse)
def billing_index(request: Request, q: str = "", user: dict = Depends(current_admin)):
    return templates.TemplateResponse(
        "billing.html",
        {
            "request": request, "user": user, "q": q,
            "flash": _pop_flash(request),
        },
    )


@app.get("/billing/{user_id}", response_class=HTMLResponse)
def billing_detail(request: Request, user_id: int, user: dict = Depends(current_admin)):
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    if target["role"] == "admin":
        _flash(request, "Los administradores no requieren facturación.", "info")
        return RedirectResponse("/billing", status_code=303)
    return templates.TemplateResponse(
        "billing_detail.html",
        {
            "request": request, "user": user,
            "target_id": target["id"],
            "target_username": target["username"],
            "flash": _pop_flash(request),
        },
    )


@app.get("/api/billing")
def api_billing(q: str = "", user: dict = Depends(current_admin)):
    """Listado de clientes (rol user) con resumen de facturación."""
    rows = usr.list_users(search=q or None)
    out = []
    for r in rows:
        if r.get("role") == "admin":
            continue
        public = _user_public(r)
        plan = billing.plan_summary(r)
        public["last_amount"] = plan["last_amount"]
        public["last_currency"] = plan["last_currency"]
        public["last_days"] = plan["last_days"]
        public["has_payments"] = plan["has_payments"]
        public["total_by_currency"] = plan["total_by_currency"]
        out.append(public)
    return JSONResponse({"clients": out, "q": q}, headers={"Cache-Control": "no-store"})


@app.get("/api/billing/{user_id}")
def api_billing_detail(
    user_id: int,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    user: dict = Depends(current_admin),
):
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    if target["role"] == "admin":
        raise HTTPException(404)
    target["tenant_count"] = usr.count_user_tenants(user_id)
    page, page_size, offset = _paginate(page, page_size)
    total = billing.count_payments(user_id)
    return JSONResponse(
        {
            "user": _user_public(target),
            "plan": billing.plan_summary(target),
            "payments": billing.list_payments(user_id, limit=page_size, offset=offset),
            "available_plans": billing.list_plans(active_only=True),
            "page": page, "page_size": page_size, "total": total,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        },
        headers={"Cache-Control": "no-store"},
    )


@app.post("/users/{user_id}/payments")
def user_register_payment(
    request: Request,
    user_id: int,
    amount: str = Form("0"),
    days: str = Form("30"),
    currency: str = Form("USD"),
    method: str = Form(""),
    notes: str = Form(""),
    user: dict = Depends(current_admin),
):
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    try:
        amount_f = float(amount.replace(",", "."))
        days_i = int(days)
    except ValueError:
        _flash(request, "Monto o días inválidos.", "error")
        return RedirectResponse(f"/billing/{user_id}", status_code=303)
    try:
        payment = billing.register_payment(
            user_id, amount=amount_f, days=days_i,
            currency=currency, method=method, notes=notes,
            registered_by=user,
        )
    except billing.BillingError as e:
        _flash(request, str(e), "error")
        return RedirectResponse(f"/billing/{user_id}", status_code=303)

    fresh = usr.get_user(user_id)
    events.log(
        "payment_registered", "user",
        actor=user, target_user=target,
        details=(
            f"monto={amount_f} {payment['currency']} "
            f"días={days_i} cubre_hasta={payment['covers_until']}"
        ),
        ip=_client_ip(request),
    )
    notify.send_admin(
        f"💸 <b>Pago registrado</b> para <code>{target['username']}</code>\n"
        f"Monto: {amount_f} {payment['currency']} · Días: {days_i}\n"
        f"Cubre hasta: <b>{payment['covers_until']}</b>"
    )
    notify.send_user(
        fresh,
        f"✅ <b>Pago recibido</b>\n\n"
        f"Tu cuenta queda al día hasta el <b>{payment['covers_until']}</b>.\n"
        f"Monto: {amount_f} {payment['currency']} · {days_i} días.",
        event_key="payment_received",
    )
    _flash(
        request,
        f"Pago registrado. Cuenta cubierta hasta {payment['covers_until']}.",
        "success",
    )
    return RedirectResponse(f"/billing/{user_id}", status_code=303)


@app.post("/users/{user_id}/assign-plan")
def user_assign_plan(
    request: Request,
    user_id: int,
    plan_id: str = Form(""),
    user: dict = Depends(current_admin),
):
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    pid = None
    if plan_id.strip():
        try:
            pid = int(plan_id)
        except ValueError:
            _flash(request, "Plan inválido.", "error")
            return RedirectResponse(f"/billing/{user_id}", status_code=303)
    try:
        billing.assign_plan(user_id, pid)
        plan = billing.get_plan(pid) if pid else None
        msg = (f"Plan '{plan['name']}' asignado a {target['username']}."
               if plan else f"Plan desasignado de {target['username']}.")
        events.log("plan_assigned", "user", actor=user, target_user=target,
                   details=msg, ip=_client_ip(request))
        _flash(request, msg, "success")
    except billing.BillingError as e:
        _flash(request, str(e), "error")
    return RedirectResponse(f"/billing/{user_id}", status_code=303)


@app.post("/users/{user_id}/extend")
def user_quick_extend(
    request: Request,
    user_id: int,
    days: str = Form("30"),
    user: dict = Depends(current_admin),
):
    """Cortesía: ajusta paid_until sumando o restando días (positivo o negativo).
    days > 0 → extiende suscripción (regalo).
    days < 0 → reduce suscripción (penalización / corrección manual).
    days = 0 → error."""
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    try:
        days_i = int(days)
    except ValueError:
        _flash(request, "Días inválidos.", "error")
        return RedirectResponse("/billing", status_code=303)
    try:
        notes = "Extensión sin pago" if days_i > 0 else "Reducción manual"
        payment = billing.register_payment(
            user_id, amount=0.0, days=days_i,
            method="cortesía", notes=notes,
            registered_by=user,
        )
    except billing.BillingError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/billing", status_code=303)

    fresh = usr.get_user(user_id)
    accion = "extendida" if days_i > 0 else "reducida"
    abs_days = abs(days_i)
    events.log(
        f"payment_{'extended' if days_i > 0 else 'reduced'}", "user",
        actor=user, target_user=target,
        details=f"días={days_i} cubre_hasta={payment['covers_until']}",
        severity="warn" if days_i < 0 else "info",
        ip=_client_ip(request),
    )
    if days_i > 0:
        notify.send_user(
            fresh,
            f"✅ <b>Cuenta extendida</b>\n\n"
            f"Tu cuenta queda al día hasta el <b>{payment['covers_until']}</b> "
            f"({days_i} días de cortesía).",
            event_key="payment_received",
        )
    # Sin notificación al cliente cuando reducimos — admin puede comunicarlo manualmente.
    _flash(
        request,
        f"Cuenta de '{target['username']}' {accion} {abs_days} días "
        f"(ahora cubre hasta {payment['covers_until']}).",
        "success",
    )
    return RedirectResponse("/billing", status_code=303)


@app.get("/users/new", response_class=HTMLResponse)
def user_new_form(request: Request, user: dict = Depends(current_admin)):
    return templates.TemplateResponse(
        "user_form.html",
        {
            "request": request, "user": user,
            "edit": None, "flash": _pop_flash(request),
            "assignable_tenants": svc.list_assignable_tenants(),
            "plans": billing.list_plans(active_only=True),
        },
    )


@app.post("/users/new")
def user_new_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(""),
    role: str = Form("user"),
    company_name: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    phone_cc: str = Form(""),
    phone: str = Form(""),
    email: str = Form(""),
    telegram_chat_id: str = Form(""),
    plan_id: str = Form(""),
    assign_tenants: list[str] = Form([]),
    user: dict = Depends(current_admin),
):
    try:
        new_user, plain_pwd, autogen = usr.create_user(
            username.strip().lower(),
            password=password or None,
            role=role,
            company_name=company_name,
            first_name=first_name,
            last_name=last_name,
            phone_cc=phone_cc,
            phone=phone,
            email=email,
            telegram_chat_id=telegram_chat_id,
            tenant_quota=None,  # la quota la define el plan asignado (abajo)
        )
    except usr.UserError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/users/new", status_code=303)

    # Asignar plan (define quota de tenants + precio + días). Solo rol cliente.
    if new_user["role"] == "user" and plan_id.strip():
        try:
            billing.assign_plan(new_user["id"], int(plan_id))
            new_user = usr.get_user(new_user["id"])  # refrescar con la quota del plan
        except (billing.BillingError, ValueError) as e:
            _flash(request, f"Usuario creado, pero el plan no se asignó: {e}", "info")

    events.log(
        "user_created", "user",
        actor=user, target_user=new_user,
        details=f"rol={new_user['role']}, empresa={new_user.get('company_name') or '—'}",
        ip=_client_ip(request),
    )

    # Asignar tenants ya existentes al cliente nuevo (los que creó un admin y el
    # cliente pasa a gestionar). Solo para rol 'user' y solo tenants asignables
    # (sin dueño o de un admin), validado en servidor por seguridad.
    assigned = []
    if new_user["role"] == "user" and assign_tenants:
        allowed = {t["name"] for t in svc.list_assignable_tenants()}
        for tname in assign_tenants:
            tname = (tname or "").strip()
            if tname in allowed:
                svc.set_owner(tname, new_user["id"])
                assigned.append(tname)
        if assigned:
            events.log("tenants_assigned", "user", actor=user, target_user=new_user,
                       details=f"tenants={','.join(assigned)}", ip=_client_ip(request))

    # Notificaciones Telegram
    notify.send_admin(
        f"👤 <b>Usuario nuevo</b>\nLogin: <code>{new_user['username']}</code>\n"
        f"Rol: {new_user['role']}\nEmpresa: {new_user.get('company_name') or '—'}\n"
        f"Creado por: {user['username']}"
    )
    if autogen and new_user.get("telegram_chat_id"):
        notify.send_user(
            new_user,
            f"👋 <b>Bienvenido a MonitorMaat</b>\n\n"
            f"Tu cuenta fue creada. Estos son tus accesos:\n"
            f"Usuario: <code>{new_user['username']}</code>\n"
            f"Password: <code>{plain_pwd}</code>\n\n"
            f"Al primer login se te va a pedir cambiarla.",
            event_key="account_welcome",
        )

    msg_parts = [f"Usuario '{new_user['username']}' creado."]
    if assigned:
        msg_parts.append(f"{len(assigned)} tenant(s) asignado(s): {', '.join(assigned)}.")

    if autogen:
        if new_user.get("email") and mail.is_configured():
            try:
                mail.send_user_welcome(
                    new_user["email"],
                    new_user["username"],
                    plain_pwd,
                    company=new_user.get("company_name") or "",
                )
                msg_parts.append(f"Email enviado a {new_user['email']}.")
            except Exception as e:
                msg_parts.append(
                    f"⚠ Error enviando email ({e}). Password generada: {plain_pwd}"
                )
        else:
            reason = "sin email configurado" if not new_user.get("email") else "SMTP no configurado"
            msg_parts.append(
                f"({reason}) Password generada: {plain_pwd} — guardala, no se vuelve a mostrar."
            )
        msg_parts.append("Al primer login se le va a pedir cambiarla.")

    _flash(request, " ".join(msg_parts), "success")
    return RedirectResponse("/users", status_code=303)


@app.get("/users/{user_id}/edit", response_class=HTMLResponse)
def user_edit_form(request: Request, user_id: int, user: dict = Depends(current_admin)):
    edit = usr.get_user(user_id)
    if not edit:
        raise HTTPException(404)
    plans = billing.list_plans(active_only=True)
    # Incluir el plan ya asignado aunque esté inactivo, para no desasignarlo sin querer.
    if edit.get("assigned_plan_id") and not any(p["id"] == edit["assigned_plan_id"] for p in plans):
        cur = billing.get_plan(edit["assigned_plan_id"])
        if cur:
            plans = plans + [cur]
    return templates.TemplateResponse(
        "user_form.html",
        {
            "request": request, "user": user,
            "edit": edit, "flash": _pop_flash(request),
            "plans": plans,
        },
    )


@app.post("/users/{user_id}/edit")
def user_edit_submit(
    request: Request,
    user_id: int,
    role: str = Form(...),
    company_name: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    phone_cc: str = Form(""),
    phone: str = Form(""),
    email: str = Form(""),
    telegram_chat_id: str = Form(""),
    plan_id: str = Form(""),
    new_password: str = Form(""),
    user: dict = Depends(current_admin),
):
    target = usr.get_user(user_id)
    try:
        # La quota la define el plan (no se pasa tenant_quota → update_user no la toca).
        usr.update_user(
            user_id,
            company_name=company_name,
            first_name=first_name,
            last_name=last_name,
            phone_cc=phone_cc,
            phone=phone,
            email=email,
            telegram_chat_id=telegram_chat_id,
            role=role,
            new_password=new_password or None,
        )
        # Asignar/actualizar plan (define quota+precio+días). Solo rol cliente; para
        # admin no aplica (ve todo). '— sin plan —' desasigna y deja quota en 0.
        if role == "user":
            try:
                billing.assign_plan(user_id, int(plan_id) if plan_id.strip() else None)
            except (billing.BillingError, ValueError) as e:
                _flash(request, f"Usuario actualizado, pero el plan no se asignó: {e}", "info")
                return RedirectResponse("/users", status_code=303)
        events.log("user_updated", "user", actor=user, target_user=target, ip=_client_ip(request))
        _flash(request, "Usuario actualizado.", "success")
        return RedirectResponse("/users", status_code=303)
    except usr.UserError as e:
        _flash(request, str(e), "error")
        return RedirectResponse(f"/users/{user_id}/edit", status_code=303)


@app.post("/users/{user_id}/reset-password")
def user_reset_password(request: Request, user_id: int, user: dict = Depends(current_admin)):
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    try:
        new_pwd = usr.reset_password(user_id)
        events.log("password_reset", "user", actor=user, target_user=target, severity="warn", ip=_client_ip(request))
    except usr.UserError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/users", status_code=303)

    msg = [f"Password de '{target['username']}' regenerada."]
    if target.get("email") and mail.is_configured():
        try:
            mail.send_user_welcome(
                target["email"], target["username"], new_pwd,
                company=target.get("company_name") or "",
            )
            msg.append(f"Email enviado a {target['email']}.")
        except Exception as e:
            msg.append(f"⚠ Email falló ({e}). Password: {new_pwd}")
    else:
        msg.append(f"Password: {new_pwd} — guardala.")
    msg.append("Al próximo login se le va a pedir cambiarla.")
    _flash(request, " ".join(msg), "success")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/toggle-active")
def user_toggle_active(request: Request, user_id: int, user: dict = Depends(current_admin)):
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    if target["id"] == user["id"]:
        _flash(request, "No podés desactivarte a vos mismo.", "error")
        return RedirectResponse("/users", status_code=303)
    new_state = not usr.is_active(target)
    try:
        updated = usr.set_active(user_id, new_state)
    except usr.UserError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/users", status_code=303)
    label = "activado" if new_state else "desactivado"
    events.log(
        "user_toggled_active", "user",
        actor=user, target_user=target,
        details=f"is_active={1 if new_state else 0}",
        severity="warn" if not new_state else "info",
        ip=_client_ip(request),
    )
    _flash(request, f"Usuario '{target['username']}' {label}.", "success")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/delete")
def user_delete(request: Request, user_id: int, user: dict = Depends(current_admin)):
    target = usr.get_user(user_id)
    try:
        usr.delete_user(user_id)
        events.log("user_deleted", "user", actor=user, target_user=target, severity="warn", ip=_client_ip(request))
        _flash(request, "Usuario eliminado.", "success")
    except usr.UserError as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/users", status_code=303)


# -------- SETTINGS / SMTP (ADMIN ONLY) --------

@app.get("/settings/smtp", response_class=HTMLResponse)
def smtp_settings_form(request: Request, user: dict = Depends(current_admin)):
    cfg = settings.get_smtp_config()
    cfg["password_set"] = bool(cfg["password"])
    cfg["password"] = ""  # nunca enviarla al HTML
    return templates.TemplateResponse(
        "smtp_settings.html",
        {"request": request, "user": user, "cfg": cfg, "flash": _pop_flash(request)},
    )


@app.post("/settings/smtp")
def smtp_settings_save(
    request: Request,
    smtp_host: str = Form(""),
    smtp_port: str = Form("587"),
    smtp_user: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
    smtp_security: str = Form("tls"),
    public_url: str = Form(""),
    user: dict = Depends(current_admin),
):
    try:
        port = int(smtp_port) if smtp_port.strip() else 587
        settings.save_smtp_config(
            host=smtp_host, port=port, user=smtp_user, password=smtp_password or None,
            sender=smtp_from, security=smtp_security, public_url=public_url,
        )
        _flash(request, "Configuración SMTP guardada.", "success")
    except Exception as e:
        _flash(request, f"Error guardando: {e}", "error")
    return RedirectResponse("/settings/smtp", status_code=303)


@app.post("/settings/smtp/test")
def smtp_settings_test(
    request: Request,
    test_to: str = Form(...),
    user: dict = Depends(current_admin),
):
    try:
        mail.send_test(test_to.strip())
        events.log("smtp_test_ok", "settings", actor=user, details=f"to={test_to}", ip=_client_ip(request))
        _flash(request, f"Email de test enviado a {test_to}. Revisá la bandeja.", "success")
    except mail.EmailNotConfigured as e:
        _flash(request, str(e), "error")
    except Exception as e:
        events.log("smtp_test_fail", "settings", actor=user, severity="error", details=f"to={test_to}: {e}", ip=_client_ip(request))
        notify.send_admin(f"⚠️ <b>SMTP test falló</b>\nDestino: {test_to}\nError: {e}")
        _flash(request, f"Error enviando test: {e}", "error")
    return RedirectResponse("/settings/smtp", status_code=303)


# -------- TELEGRAM SETTINGS (admin) --------

@app.get("/settings/telegram", response_class=HTMLResponse)
def telegram_settings_form(request: Request, user: dict = Depends(current_admin)):
    cfg = settings.get_telegram_config()
    cfg["token_set"] = bool(cfg["bot_token"])
    cfg["bot_token"] = ""  # nunca enviar al HTML
    return templates.TemplateResponse(
        "telegram_settings.html",
        {"request": request, "user": user, "cfg": cfg, "flash": _pop_flash(request)},
    )


@app.post("/settings/telegram")
def telegram_settings_save(
    request: Request,
    bot_token: str = Form(""),
    admin_chat_id: str = Form(""),
    user: dict = Depends(current_admin),
):
    try:
        settings.save_telegram_config(bot_token=bot_token or None, admin_chat_id=admin_chat_id)
        _flash(request, "Configuración de Telegram guardada.", "success")
    except Exception as e:
        _flash(request, f"Error guardando: {e}", "error")
    return RedirectResponse("/settings/telegram", status_code=303)


@app.post("/settings/telegram/test")
def telegram_settings_test(
    request: Request,
    test_chat_id: str = Form(""),
    user: dict = Depends(current_admin),
):
    chat = test_chat_id.strip() or settings.get_telegram_config().get("admin_chat_id", "")
    if not chat:
        _flash(request, "Cargá un chat_id para el test (o seteá el del admin primero).", "error")
        return RedirectResponse("/settings/telegram", status_code=303)
    try:
        notify.send_test(chat)
        events.log("telegram_test_ok", "settings", actor=user, details=f"chat={chat}", ip=_client_ip(request))
        _flash(request, f"Mensaje de test enviado al chat {chat}. Revisalo.", "success")
    except notify.NotConfigured as e:
        _flash(request, str(e), "error")
    except Exception as e:
        events.log("telegram_test_fail", "settings", actor=user, severity="error", details=f"chat={chat}: {e}", ip=_client_ip(request))
        _flash(request, f"Error enviando test: {e}", "error")
    return RedirectResponse("/settings/telegram", status_code=303)


# -------- PAYPHONE SETTINGS (admin) --------

@app.get("/settings/payphone", response_class=HTMLResponse)
def payphone_settings_form(request: Request, user: dict = Depends(current_admin)):
    cfg = settings.get_payphone_config()
    cfg["token_set"] = bool(cfg["token"])
    cfg["token"] = ""  # nunca enviar al HTML
    return templates.TemplateResponse(
        "payphone_settings.html",
        {"request": request, "user": user, "cfg": cfg, "flash": _pop_flash(request)},
    )


@app.post("/settings/payphone")
def payphone_settings_save(
    request: Request,
    payphone_token: str = Form(""),
    payphone_store_id: str = Form(...),
    payphone_api_url: str = Form(""),
    public_url: str = Form(""),
    user: dict = Depends(current_admin),
):
    settings.save_payphone_config(
        token=payphone_token or None,
        store_id=payphone_store_id,
        api_url=payphone_api_url,
        public_url=public_url,
    )
    events.log("payphone_settings_saved", "settings", actor=user, ip=_client_ip(request))
    _flash(request, "Configuración PayPhone guardada.", "success")
    return RedirectResponse("/settings/payphone", status_code=303)


# -------- PLANES (admin) --------

@app.get("/settings/plans", response_class=HTMLResponse)
def plans_settings(request: Request, user: dict = Depends(current_admin)):
    plans = billing.list_plans(active_only=False)
    for p in plans:
        p["associations"] = billing.count_plan_associations(p["id"])
        p["locked"] = p["associations"]["total"] > 0
    return templates.TemplateResponse(
        "plans_settings.html",
        {
            "request": request, "user": user,
            "plans": plans,
            "billing_cfg": settings.get_billing_config(),
            "flash": _pop_flash(request),
        },
    )


def _apply_network_stack() -> tuple[bool, str]:
    """Pipeline único post-guardado, según el modo SSL de los tenants:
    1. DNS por API si aplica (cf_auto → un A por tenant; certbot → wildcard único)
    2. Cert wildcard vía certbot (solo modo certbot; bloquea ~30-90s la 1.ª vez)
    3. Caddy apply (al final, para que el Caddyfile ya vea el cert emitido)
    El panel NO pasa por DNS API ni certbot: siempre Caddy + registro A manual."""
    msgs = []
    ok = True
    nc = settings.get_network_config()
    mode = nc.get("tenants_ssl_mode", "caddy")

    res = cloudflare.sync_all(
        nc.get("tenants_domain", ""), config.PUBLIC_IP or "",
        [t["name"] for t in svc.list_tenants()],
    )
    if isinstance(res, dict):
        if res.get("errors"):
            ok = False
            msgs.append("DNS Cloudflare con errores: " + "; ".join(res["errors"][:3]))
        elif res.get("ok"):
            msgs.append(f"DNS OK: {', '.join(res['ok'][:4])}")

    if mode == "certbot" and nc.get("tenants_domain"):
        c_ok, c_msg = certbot.issue()
        msgs.append(c_msg)
        ok = ok and c_ok

    if mode == "cf_origin" and nc.get("tenants_domain"):
        # SSL de la zona: 'strict' solo si ya está el cert de origen; si falta,
        # 'full' (no strict) para que el cert actual siga validando detrás del proxy
        # y NO haya downtime (con strict, un cert no-Origin-CA daría error 526).
        has_cert = cf_origin.cert_exists()
        ssl_value = "strict" if has_cert else "full"
        try:
            cloudflare.set_zone_ssl_mode(nc["tenants_domain"], ssl_value)
            msgs.append(f"Zona en Full{' (strict)' if has_cert else ''}.")
        except cloudflare.CloudflareError as e:
            msgs.append(f"⚠ No pude fijar el SSL de la zona ({e}); ponela en Full{' strict' if has_cert else ''} a mano.")
        if not has_cert:
            msgs.append("⚠ Falta el cert de origen: pegá el Origin CA abajo (ahí la zona pasa a strict).")

    a_ok, a_msg = caddy.apply()
    msgs.append(a_msg)
    return ok and a_ok, " · ".join(msgs)


@app.get("/settings/network", response_class=HTMLResponse)
def network_settings_form(request: Request, user: dict = Depends(current_admin)):
    return templates.TemplateResponse(
        "network_settings.html",
        {
            "request": request, "user": user,
            "cfg": settings.get_network_config(),
            "cf": {k: v for k, v in settings.get_cloudflare_config().items() if k != "token"},
            "certbot_status": certbot.status(),
            "origin_status": cf_origin.status(),
            "kuma_tag": settings.get_kuma_tag(),
            "kuma_image": settings.kuma_image(),
            "tenants": svc.list_tenants(),
            "public_ip": config.PUBLIC_IP or "",
            "caddy_running": caddy.caddy_container_running(),
            "caddyfile_preview": caddy.generate_caddyfile() if caddy.is_configured() else "",
            "flash": _pop_flash(request),
        },
    )


@app.post("/settings/network")
def panel_settings_save(
    request: Request,
    panel_domain: str = Form(""),
    caddy_email: str = Form(""),
    use_https: str = Form(""),
    user: dict = Depends(current_admin),
):
    """Form del PANEL admin: dominio + email LE + https. Siempre Caddy (HTTP-01)."""
    try:
        settings.save_panel_config(
            panel_domain=panel_domain,
            caddy_email=caddy_email,
            use_https=bool(use_https),
        )
        events.log("panel_domain_saved", "settings", actor=user,
                   details=f"panel={panel_domain}", ip=_client_ip(request))
        ok, msg = _apply_network_stack()
        if ok:
            _flash(request, f"Panel guardado. {msg}", "success")
        else:
            _flash(request, f"Panel guardado con avisos: {msg}", "info")
    except ValueError as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/settings/network", status_code=303)


@app.post("/settings/network/tenants")
def tenants_settings_save(
    request: Request,
    tenants_domain: str = Form(""),
    ssl_mode: str = Form("caddy"),
    cf_api_token: str = Form(""),
    cf_proxied: str = Form(""),
    cf_clear: str = Form(""),
    user: dict = Depends(current_admin),
):
    """Form de dominios de TENANTS (clientes: Kuma + accesos): dominio raíz +
    modo SSL (caddy | cf_auto | certbot | cf_origin) + token de Cloudflare para
    los modos que lo usan. Separado a propósito del form del panel."""
    # cf_origin exige nube naranja (sin proxy no hay Universal SSL de Cloudflare).
    proxied = bool(cf_proxied) or ssl_mode == "cf_origin"
    clear = bool(cf_clear)
    # Si mandó un token nuevo, validarlo contra Cloudflare antes de guardarlo
    if cf_api_token.strip() and not clear:
        v = cloudflare.verify_token(cf_api_token)
        if not v["ok"]:
            _flash(request, f"Token de Cloudflare inválido: {v['msg']}", "error")
            return RedirectResponse("/settings/network", status_code=303)
    try:
        settings.save_tenants_config(tenants_domain=tenants_domain, ssl_mode=ssl_mode)
    except ValueError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/settings/network", status_code=303)
    settings.save_cloudflare_token(
        token=cf_api_token or None, proxied=proxied, clear_token=clear,
    )
    events.log("tenants_domain_saved", "settings", actor=user,
               details=f"tenants={tenants_domain} ssl_mode={ssl_mode} clear_token={clear}",
               ip=_client_ip(request))
    cf_cfg = settings.get_cloudflare_config()
    if ssl_mode in ("cf_auto", "certbot", "cf_origin") and not cf_cfg["has_token"]:
        _flash(request, "Guardado, pero el modo elegido necesita el token de API de "
                        "Cloudflare — pegalo y volvé a guardar.", "info")
        return RedirectResponse("/settings/network", status_code=303)
    ok, msg = _apply_network_stack()
    _flash(request, f"Dominio de tenants guardado. {msg}", "success" if ok else "info")
    return RedirectResponse("/settings/network", status_code=303)


@app.post("/settings/network/apply")
def network_apply_caddy(request: Request, user: dict = Depends(current_admin)):
    """Reaplicar manualmente Caddyfile + sync DNS (útil si se cambió algo fuera)."""
    ok, msg = _apply_network_stack()
    events.log("caddy_apply", "settings", actor=user, details=msg[:200],
               severity="info" if ok else "warn", ip=_client_ip(request))
    _flash(request, msg, "success" if ok else "error")
    return RedirectResponse("/settings/network", status_code=303)


@app.post("/settings/network/origin-cert")
def origin_cert_save(
    request: Request,
    origin_cert: str = Form(""),
    origin_key: str = Form(""),
    user: dict = Depends(current_admin),
):
    """Guarda el par cert/key del Cloudflare Origin CA (modo cf_origin) y reaplica
    Caddy para que empiece a servirlo. El cert lo genera el usuario en el dashboard
    de Cloudflare (SSL/TLS → Origin Server) y lo pega acá; se valida antes de guardar."""
    ok, msg = cf_origin.save_cert(origin_cert, origin_key)
    if not ok:
        _flash(request, f"Cert de origen rechazado: {msg}", "error")
        return RedirectResponse("/settings/network", status_code=303)
    events.log("origin_cert_saved", "settings", actor=user, details=msg[:200],
               ip=_client_ip(request))
    a_ok, a_msg = caddy.apply()
    # Con el cert ya cargado, subir la zona a Full (strict) — validación extremo a
    # extremo. Best-effort: si el token no puede, se avisa para hacerlo a mano.
    extra = ""
    td = settings.get_network_config().get("tenants_domain", "")
    if td:
        try:
            cloudflare.set_zone_ssl_mode(td, "strict")
            extra = " · zona en Full (strict)"
        except cloudflare.CloudflareError as e:
            extra = f" · ⚠ poné la zona en Full strict a mano ({e})"
    _flash(request, f"{msg} · {a_msg}{extra}", "success" if a_ok else "info")
    return RedirectResponse("/settings/network", status_code=303)


@app.post("/settings/update-kuma")
def update_kuma_all(
    request: Request,
    kuma_tag: str = Form(""),
    user: dict = Depends(current_admin),
):
    """Actualiza Uptime Kuma en todos los tenants: fija el tag (1|2), hace pull de la
    imagen y recrea SOLO el kuma de cada tenant (no corta el VPN)."""
    try:
        if kuma_tag:
            settings.set_kuma_tag(kuma_tag)
    except ValueError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/settings/network", status_code=303)
    res = svc.update_all_kuma()  # usa el default global recién fijado
    parts = [f"Default para tenants nuevos: {res['image']}"]
    if res["ok"]:
        parts.append(f"{len(res['ok'])} tenant(s) llevado(s) a v{res['tag']}")
    if res["errors"]:
        parts.append("errores: " + "; ".join(res["errors"][:3]))
    if not res["ok"] and not res["errors"]:
        parts.append("sin tenants existentes (los nuevos se crean ya con esta versión)")
    msg = " · ".join(parts)
    events.log("kuma_updated", "settings", actor=user, details=msg[:200],
               severity="info" if not res["errors"] else "warn", ip=_client_ip(request))
    _flash(request, msg, "success" if not res["errors"] else "info")
    return RedirectResponse("/settings/network", status_code=303)


@app.get("/settings/network/caddyfile", response_class=HTMLResponse)
def network_caddyfile(request: Request, user: dict = Depends(current_admin)):
    """Descarga el Caddyfile REAL (el mismo que caddy_service escribe y aplica).
    Antes este endpoint generaba una variante propia bare-metal (127.0.0.1 +
    wildcard) que no coincidía con lo que corre en el container — ahora hay una
    sola fuente de verdad."""
    from fastapi.responses import PlainTextResponse
    if not caddy.is_configured():
        return PlainTextResponse(
            "# Configurá primero los dominios en /settings/network\n",
            status_code=400,
        )
    return PlainTextResponse(
        caddy.generate_caddyfile(),
        headers={
            "Content-Disposition": 'attachment; filename="Caddyfile"',
            "Content-Type": "text/plain; charset=utf-8",
        },
    )


@app.post("/settings/billing")
def billing_settings_save(
    request: Request,
    suspension_time: str = Form(...),
    user: dict = Depends(current_admin),
):
    try:
        settings.save_billing_config(suspension_time=suspension_time)
        events.log("billing_settings_saved", "settings", actor=user,
                   details=f"suspension_time={suspension_time}", ip=_client_ip(request))
        _flash(request, f"Hora de suspensión guardada: {suspension_time}", "success")
    except ValueError as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/settings/plans", status_code=303)


@app.post("/settings/plans/new")
def plans_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    price: str = Form(...),
    currency: str = Form("USD"),
    days: str = Form(...),
    is_active: str = Form(""),
    tenant_quota: str = Form(""),
    user: dict = Depends(current_admin),
):
    try:
        # sort_order se asigna automáticamente (siempre al final, luego renumer a 1..N)
        plan = billing.create_plan(
            name=name, description=description,
            price=float(price.replace(",", ".")), days=int(days),
            currency=currency, is_active=bool(is_active),
            tenant_quota=(int(tenant_quota) if tenant_quota.strip() else None),
        )
        events.log("plan_created", "settings", actor=user,
                   details=f"plan={plan['name']} ${plan['price']}", ip=_client_ip(request))
        _flash(request, f"Plan '{plan['name']}' creado.", "success")
    except (billing.BillingError, ValueError) as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/settings/plans", status_code=303)


@app.post("/settings/plans/{plan_id}/edit")
def plans_update(
    request: Request,
    plan_id: int,
    name: str = Form(...),
    description: str = Form(""),
    price: str = Form(...),
    currency: str = Form("USD"),
    days: str = Form(...),
    is_active: str = Form(""),
    sort_order: str = Form(""),
    tenant_quota: str = Form(""),
    user: dict = Depends(current_admin),
):
    try:
        assoc = billing.count_plan_associations(plan_id)
        fields = {
            "name": name,
            "description": description,
            "price": float(price.replace(",", ".")),
            "days": int(days),
        }
        if tenant_quota.strip():
            fields["tenant_quota"] = int(tenant_quota)
        if assoc["total"] == 0:
            # Plan no está en uso: admitir cambios estructurales también
            fields["currency"] = currency
            fields["is_active"] = bool(is_active)
            if sort_order.strip():
                fields["sort_order"] = int(sort_order)
        billing.update_plan(plan_id, **fields)
        events.log("plan_updated", "settings", actor=user,
                   details=f"plan_id={plan_id}", ip=_client_ip(request))
        _flash(request, "Plan actualizado.", "success")
    except (billing.BillingError, ValueError) as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/settings/plans", status_code=303)


@app.post("/settings/plans/{plan_id}/delete")
def plans_delete(
    request: Request,
    plan_id: int,
    user: dict = Depends(current_admin),
):
    try:
        billing.delete_plan(plan_id)
        events.log("plan_deleted", "settings", actor=user,
                   details=f"plan_id={plan_id}", severity="warn",
                   ip=_client_ip(request))
        _flash(request, "Plan eliminado.", "success")
    except billing.BillingError as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/settings/plans", status_code=303)


# -------- MI SUSCRIPCIÓN / PAGO (cliente) --------

@app.get("/me/billing", response_class=HTMLResponse)
def me_billing(
    request: Request,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    user: dict = Depends(current_user),
):
    if user["role"] == "admin":
        _flash(request, "Los administradores no requieren suscripción.", "info")
        return RedirectResponse("/", status_code=303)
    page, page_size, offset = _paginate(page, page_size)
    total = billing.count_payments(user["id"])
    total_pages = max(1, (total + page_size - 1) // page_size)
    return templates.TemplateResponse(
        "me_billing.html",
        {
            "request": request, "user": user,
            "plan_summary": billing.plan_summary(user),
            "assigned_plan": billing.get_assigned_plan(user),
            "payments": billing.list_payments(user["id"], limit=page_size, offset=offset),
            "payphone_ready": payphone.is_configured(),
            "flash": _pop_flash(request),
            "pagination": {
                "page": page, "page_size": page_size,
                "total": total, "total_pages": total_pages,
                "page_sizes": list(ALLOWED_PAGE_SIZES),
                "base_url": "/me/billing",
            },
        },
    )


@app.post("/me/pay")
def me_pay_start(
    request: Request,
    user: dict = Depends(current_user),
):
    """El cliente paga por su plan asignado (no elige). El admin debe haberle
    asignado un plan via /users/{id}/assign-plan antes."""
    if user["role"] == "admin":
        _flash(request, "Los administradores no realizan pagos.", "info")
        return RedirectResponse("/", status_code=303)
    if not payphone.is_configured():
        _flash(request, "El método de pago no está disponible. Contactá al administrador.", "error")
        return RedirectResponse("/me/billing", status_code=303)
    plan = billing.get_assigned_plan(user)
    if not plan:
        _flash(request, "Aún no tenés un plan asignado. Contactá al administrador.", "error")
        return RedirectResponse("/me/billing", status_code=303)
    if not plan["is_active"]:
        _flash(request, f"Tu plan '{plan['name']}' fue desactivado. Contactá al administrador.", "error")
        return RedirectResponse("/me/billing", status_code=303)

    cfg = settings.get_payphone_config()
    base_url = (cfg.get("public_url") or "").rstrip("/")
    if not base_url:
        _flash(request, "El administrador debe configurar la URL pública en Settings → PayPhone.", "error")
        return RedirectResponse("/me/billing", status_code=303)

    client_tx_id = payphone.generate_client_tx_id(prefix=f"MM-{user['id']}")
    response_url = f"{base_url}/api/payments/callback"
    cancellation_url = f"{base_url}/payment-cancelled?tx={client_tx_id}"
    customer_email = (user.get("email") or "").strip() or f"user-{user['id']}@monitormaat.local"

    try:
        result = payphone.create_payment(
            amount_usd=float(plan["price"]),
            client_tx_id=client_tx_id,
            customer_email=customer_email,
            response_url=response_url,
            cancellation_url=cancellation_url,
            reference=f"MonitorMaat — {plan['name']}",
            metadata={"plan_id": plan["id"], "user_id": user["id"], "username": user["username"]},
        )
    except payphone.NotConfigured as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/me/billing", status_code=303)
    except payphone.PayphoneError as e:
        events.log("payphone_create_fail", "user", actor=user, severity="error",
                   details=str(e)[:300], ip=_client_ip(request))
        _flash(request, f"No pudimos iniciar el pago: {e}", "error")
        return RedirectResponse("/me/billing", status_code=303)

    billing.create_pending_payphone_payment(
        user_id=user["id"], plan=plan,
        provider_tx_id=client_tx_id,
        provider_id=result["payment_id"],
        raw_response=result["raw"],
    )
    events.log("payphone_payment_started", "user", actor=user,
               details=f"plan={plan['name']} tx={client_tx_id}", ip=_client_ip(request))
    return RedirectResponse(result["payment_url"], status_code=303)


# -------- WEBHOOK + PANTALLAS RESULTADO (públicos, sin auth) --------

@app.get("/api/payments/callback")
def payphone_callback(request: Request, id: str = "", clientTransactionId: str = ""):
    """Webhook de PayPhone. Se llama después del pago, redirige al usuario al resultado."""
    ip = _client_ip(request)
    if security.webhook_rate_limit(ip):
        events.log("webhook_rate_limited", "system", severity="warn",
                   details=f"ip={ip}", ip=ip)
        raise HTTPException(429, "Too Many Requests")
    if not id or not clientTransactionId:
        return RedirectResponse("/payment-failed?error=missing_params", status_code=303)
    # Validación básica del formato esperado del tx_id (anti-fuzzing)
    if not clientTransactionId.startswith("MM-") or len(clientTransactionId) > 80:
        events.log("webhook_invalid_tx", "system", severity="warn",
                   details=f"tx={clientTransactionId[:80]} ip={ip}", ip=ip)
        return RedirectResponse("/payment-failed?error=invalid_tx", status_code=303)
    try:
        confirmation = payphone.confirm_transaction(id, clientTransactionId)
    except Exception as e:
        events.log("payphone_callback_fail", "user", severity="error",
                   details=f"tx={clientTransactionId}: {e}", ip=_client_ip(request))
        return RedirectResponse(
            f"/payment-failed?tx={clientTransactionId}&error=confirm_failed",
            status_code=303,
        )

    payment = billing.apply_payphone_confirmation(clientTransactionId, confirmation)
    status = (confirmation.get("transactionStatus") or "UNKNOWN").lower()

    if payment and payment["provider_status"] == "Approved":
        # Notificaciones
        u = usr.get_user(payment["user_id"])
        events.log("payphone_payment_approved", "user", actor=u,
                   details=f"tx={clientTransactionId} ${payment['amount']} cubre_hasta={payment['covers_until']}",
                   ip=_client_ip(request))
        try:
            notify.send_admin(
                f"💳 <b>Pago PayPhone aprobado</b>\n"
                f"Cliente: <code>{u['username']}</code>\n"
                f"Monto: {payment['amount']} {payment['currency']}\n"
                f"Cubre hasta: <b>{payment['covers_until']}</b>"
            )
        except Exception:
            pass
        try:
            notify.send_user(
                u,
                f"✅ <b>Pago aprobado</b>\n\nTu suscripción quedó al día hasta el "
                f"<b>{payment['covers_until']}</b>.\n"
                f"Monto: {payment['amount']} {payment['currency']}.",
                event_key="payment_received",
            )
        except Exception:
            pass
        return RedirectResponse(f"/payment-success?tx={clientTransactionId}", status_code=303)

    events.log("payphone_payment_failed", "user", severity="warn",
               details=f"tx={clientTransactionId} status={status}", ip=_client_ip(request))
    return RedirectResponse(
        f"/payment-failed?tx={clientTransactionId}&status={status}",
        status_code=303,
    )


@app.get("/payment-success", response_class=HTMLResponse)
def payment_success_page(request: Request, tx: str = ""):
    payment = billing.get_payment_by_provider_tx(tx) if tx else None
    return templates.TemplateResponse(
        "payment_success.html",
        {"request": request, "user": auth.session_user(request),
         "payment": payment, "tx": tx, "flash": _pop_flash(request)},
    )


@app.get("/payment-failed", response_class=HTMLResponse)
def payment_failed_page(request: Request, tx: str = "", status: str = "", error: str = ""):
    return templates.TemplateResponse(
        "payment_failed.html",
        {"request": request, "user": auth.session_user(request),
         "tx": tx, "status": status, "error": error, "flash": _pop_flash(request)},
    )


@app.get("/payment-cancelled", response_class=HTMLResponse)
def payment_cancelled_page(request: Request, tx: str = ""):
    return templates.TemplateResponse(
        "payment_cancelled.html",
        {"request": request, "user": auth.session_user(request),
         "tx": tx, "flash": _pop_flash(request)},
    )


@app.get("/me/telegram", response_class=HTMLResponse)
def me_telegram_form(request: Request, user: dict = Depends(current_user)):
    return templates.TemplateResponse(
        "telegram_my.html",
        {
            "request": request, "user": user,
            "user_has_own_token": bool((user.get("telegram_bot_token") or "").strip()),
            "flash": _pop_flash(request),
        },
    )


@app.post("/me/telegram")
def me_telegram_save(
    request: Request,
    telegram_chat_id: str = Form(""),
    telegram_bot_token: str = Form(""),
    user: dict = Depends(current_user),
):
    try:
        kwargs = {"telegram_chat_id": telegram_chat_id}
        # Si dejó vacío el token, NO sobrescribimos (mantenemos el actual).
        if telegram_bot_token.strip():
            kwargs["telegram_bot_token"] = telegram_bot_token
        usr.update_user(user["id"], **kwargs)
        events.log("telegram_settings_saved", "settings", actor=user, ip=_client_ip(request))
        _flash(request, "Configuración de Telegram actualizada.", "success")
    except usr.UserError as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/me/telegram", status_code=303)




@app.post("/me/username")
def me_username_save(
    request: Request,
    new_username: str = Form(...),
    user: dict = Depends(current_user),
):
    new_username = new_username.strip().lower()
    if new_username == user["username"]:
        return RedirectResponse("/change-password", status_code=303)
    try:
        usr.update_username(user["id"], new_username)
        events.log("username_changed", "auth", actor=user,
                   details=f"{user['username']} -> {new_username}", ip=_client_ip(request))
        _flash(request, f"Nombre de usuario actualizado a '{new_username}'.", "success")
    except usr.UserError as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/change-password", status_code=303)


@app.post("/me/telegram/preferences")
async def me_telegram_prefs(
    request: Request,
    user: dict = Depends(current_user),
):
    """Guarda qué notificaciones quiere recibir (opt-out por evento)."""
    form = await request.form()
    enabled = set(form.getlist("pref"))  # los checkeados
    all_keys = set(notify.EVENT_KEYS)
    disabled = all_keys - enabled
    off_csv = ",".join(sorted(disabled))
    try:
        usr.update_user(user["id"], telegram_off=off_csv)
        events.log("telegram_prefs_updated", "settings", actor=user, ip=_client_ip(request))
        _flash(request, "Preferencias de notificaciones guardadas.", "success")
    except usr.UserError as e:
        _flash(request, str(e), "error")
    return RedirectResponse("/me/telegram", status_code=303)


@app.post("/me/telegram/test")
def me_telegram_test(request: Request, user: dict = Depends(current_user)):
    chat_id = (user.get("telegram_chat_id") or "").strip()
    user_token = (crypto.decrypt(user.get("telegram_bot_token")) or "").strip()
    if not chat_id or not user_token:
        _flash(request, "Cargá tu bot token Y tu chat_id y guardá antes de testear.", "error")
        return RedirectResponse("/me/telegram", status_code=303)
    try:
        notify.send_test(chat_id, token=user_token)
        _flash(request, "Mensaje de test enviado a tu Telegram. Revisalo.", "success")
    except Exception as e:
        _flash(request, f"Error enviando test: {e}", "error")
    return RedirectResponse("/me/telegram", status_code=303)


# -------- LOGS --------

@app.get("/logs", response_class=HTMLResponse)
def logs_admin(
    request: Request,
    source: str = "",
    category: str = "",
    q: str = "",
    user: dict = Depends(current_admin),
):
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request, "user": user,
            "filters": {"source": source, "category": category, "q": q},
            "categories": list(events.CATEGORIES),
            "flash": _pop_flash(request),
        },
    )


@app.get("/api/logs")
def api_logs(
    source: str = "",
    category: str = "",
    q: str = "",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    user: dict = Depends(current_admin),
):
    page, page_size, offset = _paginate(page, page_size)
    rows = events.list_events(
        actor_role=source or None,
        category=category or None,
        search=q or None,
        limit=page_size, offset=offset,
    )
    total = events.count_events(
        actor_role=source or None,
        category=category or None,
        search=q or None,
    )
    return JSONResponse(
        {
            "events": rows,
            "filters": {"source": source, "category": category, "q": q},
            "page": page, "page_size": page_size, "total": total,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        },
        headers={"Cache-Control": "no-store"},
    )


@app.get("/me/logs", response_class=HTMLResponse)
def logs_me(request: Request, user: dict = Depends(current_user)):
    return templates.TemplateResponse(
        "me_logs.html",
        {
            "request": request, "user": user,
            "flash": _pop_flash(request),
        },
    )


@app.get("/api/me/logs")
def api_logs_me(
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    user: dict = Depends(current_user),
):
    page, page_size, offset = _paginate(page, page_size)
    rows = events.list_events_for_user(user["id"], limit=page_size, offset=offset)
    total = events.count_events_for_user(user["id"])
    return JSONResponse(
        {
            "events": rows,
            "page": page, "page_size": page_size, "total": total,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        },
        headers={"Cache-Control": "no-store"},
    )


# -------- MANUALES (HELP) --------

@app.get("/help", response_class=HTMLResponse)
def admin_help(request: Request, user: dict = Depends(current_admin)):
    return templates.TemplateResponse(
        "admin_help.html",
        {"request": request, "user": user, "flash": _pop_flash(request)},
    )


@app.get("/me/help", response_class=HTMLResponse)
def user_help(request: Request, user: dict = Depends(current_user)):
    if user["role"] == "admin":
        return RedirectResponse("/help", status_code=303)
    return templates.TemplateResponse(
        "user_help.html",
        {"request": request, "user": user, "flash": _pop_flash(request)},
    )
