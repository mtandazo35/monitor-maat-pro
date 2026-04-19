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
import db
import tenant_service as svc
import user_service as usr
import email_service as mail
import settings_service as settings
import notify_service as notify
import event_service as events
import system_stats
import favicon_gen


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
            ["docker", "pull", "louislam/uptime-kuma:1"],
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
            usr.send_payment_reminders(notify, mail)
        except Exception as e:
            print(f"[payment-reminder] error: {e}")
        time.sleep(3600)


app = FastAPI(title="KumaVPN Admin")
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET, https_only=False)

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
    request.session.clear()
    _flash(request, "Tu cuenta está impaga. Contactá al administrador para renovar.", "error")
    return RedirectResponse("/login", status_code=303)


def current_user(request: Request) -> dict:
    user = auth.session_user(request)
    if not user:
        raise AuthRequired()
    # Bloqueo por impago: corta la sesión y redirige a login con mensaje.
    if not usr.is_paid(user):
        raise PaymentRequired()
    # Si tiene flag, redirigir a /change-password (excepto si ya está en esa ruta o haciendo logout)
    path = request.url.path
    if user.get("must_change_password") and path not in ("/change-password", "/logout"):
        raise MustChangePassword()
    return user


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
    user = auth.authenticate(username.strip(), password)
    if user:
        if not usr.is_paid(user):
            events.log(
                "login_blocked_unpaid", "auth",
                actor=user, severity="warn",
                details=f"paid_until={user.get('paid_until')}",
                ip=ip,
            )
            _flash(
                request,
                "Tu cuenta está impaga. Contactá al administrador para renovar el servicio.",
                "error",
            )
            return RedirectResponse("/login", status_code=303)
        request.session["user_id"] = user["id"]
        events.log("login_success", "auth", actor=user, ip=ip)
        return RedirectResponse("/", status_code=303)
    events.log(
        "login_fail", "auth",
        actor_username=username.strip(),
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
            "days_until_due": usr.days_until_due(user),
            "is_paid": usr.is_paid(user),
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
def api_tenants(q: str = "", user: dict = Depends(current_user)):
    if user["role"] == "admin":
        tenants = svc.list_tenants(search=q or None)
    else:
        tenants = svc.list_tenants(owner_id=user["id"], search=q or None)

    statuses = svc.container_statuses_bulk()
    for t in tenants:
        t["ovpn_status"] = statuses.get(f"openvpn-{t['name']}", "missing")
        t["kuma_status"] = statuses.get(f"kuma-{t['name']}", "missing")

    quota_info = None
    if user["role"] == "user":
        quota_info = {
            "used": usr.count_user_tenants(user["id"]),
            "total": user.get("tenant_quota") or 0,
        }
    return JSONResponse(
        {"tenants": tenants, "quota": quota_info, "q": q},
        headers={"Cache-Control": "no-store"},
    )


@app.get("/tenants/new", response_class=HTMLResponse)
def new_tenant_form(request: Request, user: dict = Depends(current_user)):
    return templates.TemplateResponse(
        "new_tenant.html",
        {"request": request, "user": user, "flash": _pop_flash(request)},
    )


@app.post("/tenants/new")
def new_tenant_submit(
    request: Request,
    name: str = Form(...),
    user: dict = Depends(current_user),
):
    name = name.strip().lower()
    try:
        svc.create_tenant(name, owner=user)
    except svc.ServiceError as e:
        notify.send_admin(f"⚠️ <b>Error creando tenant</b>\nNombre: <code>{name}</code>\nUsuario: {user['username']}\nError: {e}")
        _flash(request, str(e), "error")
        return RedirectResponse("/tenants/new", status_code=303)
    except Exception as e:
        notify.send_admin(f"❌ <b>Error inesperado creando tenant</b>\nNombre: <code>{name}</code>\nError: {e}")
        _flash(request, f"Error inesperado: {e}", "error")
        return RedirectResponse("/tenants/new", status_code=303)

    t = svc.get_tenant(name)
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
    _flash(request, f"Tenant '{name}' creado y levantado.", "success")
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
        },
    )


@app.get("/api/tenants/{name}")
def api_tenant_detail(name: str, user: dict = Depends(current_user)):
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    users_list = svc.list_vpn_users(tenant["id"])
    for u in users_list:
        u["networks"] = svc.list_networks(u["id"])
        u["mikrotik"] = svc.mikrotik_snippet(tenant, u)
    tenant["ovpn_status"] = svc.container_status(f"openvpn-{tenant['name']}")
    tenant["kuma_status"] = svc.container_status(f"kuma-{tenant['name']}")
    return JSONResponse(
        {"tenant": tenant, "users": users_list},
        headers={"Cache-Control": "no-store"},
    )


@app.post("/tenants/{name}/users/new")
def add_user(request: Request, name: str, user: dict = Depends(current_user)):
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    try:
        created = svc.add_vpn_user(tenant)
        events.log("vpn_user_created", "vpn_user", actor=user, tenant=tenant,
                   details=f"username={created['username']} ip={created['ip']}", ip=_client_ip(request))
        _flash(
            request,
            f"Usuario VPN creado: {created['username']} / {created['password']} (IP {created['ip']}).",
            "success",
        )
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
    cidr: str = Form(...),
    user: dict = Depends(current_user),
):
    tenant = svc.get_tenant(name)
    if not tenant:
        raise HTTPException(404)
    _require_tenant_access(user, tenant)
    try:
        svc.add_network(tenant, user_id, cidr.strip())
        events.log("network_added", "network", actor=user, tenant=tenant,
                   details=f"cidr={cidr.strip()} vpn_user_id={user_id}", ip=_client_ip(request))
        _flash(request, f"Red {cidr} agregada.", "success")
    except svc.ServiceError as e:
        _flash(request, str(e), "error")
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
    "created_at", "must_change_password", "paid_until",
)


def _user_public(u: dict) -> dict:
    out = {k: u.get(k) for k in _USER_PUBLIC_FIELDS}
    out["days_until_due"] = usr.days_until_due(u)
    out["is_paid"] = usr.is_paid(u)
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
        {"user": _user_public(target), "payments": usr.list_payments(user_id)},
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
        return RedirectResponse(f"/users/{user_id}/edit", status_code=303)
    try:
        payment = usr.register_payment(
            user_id, amount=amount_f, days=days_i,
            currency=currency, method=method, notes=notes,
            registered_by=user,
        )
    except usr.UserError as e:
        _flash(request, str(e), "error")
        return RedirectResponse(f"/users/{user_id}/edit", status_code=303)

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
    return RedirectResponse(f"/users/{user_id}/edit", status_code=303)


@app.post("/users/{user_id}/extend")
def user_quick_extend(
    request: Request,
    user_id: int,
    days: str = Form("30"),
    user: dict = Depends(current_admin),
):
    """Extensión rápida sin monto (regalo / cortesía)."""
    target = usr.get_user(user_id)
    if not target:
        raise HTTPException(404)
    try:
        days_i = int(days)
    except ValueError:
        _flash(request, "Días inválidos.", "error")
        return RedirectResponse("/users", status_code=303)
    try:
        payment = usr.register_payment(
            user_id, amount=0.0, days=days_i,
            method="cortesía", notes="Extensión sin pago",
            registered_by=user,
        )
    except usr.UserError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/users", status_code=303)

    fresh = usr.get_user(user_id)
    events.log(
        "payment_extended", "user",
        actor=user, target_user=target,
        details=f"días={days_i} cubre_hasta={payment['covers_until']}",
        ip=_client_ip(request),
    )
    notify.send_user(
        fresh,
        f"✅ <b>Cuenta extendida</b>\n\n"
        f"Tu cuenta queda al día hasta el <b>{payment['covers_until']}</b> "
        f"({days_i} días de cortesía).",
        event_key="payment_received",
    )
    _flash(
        request,
        f"Cuenta de '{target['username']}' extendida {days_i} días "
        f"(hasta {payment['covers_until']}).",
        "success",
    )
    return RedirectResponse("/users", status_code=303)


@app.get("/users/new", response_class=HTMLResponse)
def user_new_form(request: Request, user: dict = Depends(current_admin)):
    return templates.TemplateResponse(
        "user_form.html",
        {
            "request": request, "user": user,
            "edit": None, "flash": _pop_flash(request),
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
    tenant_quota: str = Form(""),
    user: dict = Depends(current_admin),
):
    quota = None
    if tenant_quota.strip():
        try:
            quota = int(tenant_quota)
        except ValueError:
            _flash(request, "Quota debe ser un número.", "error")
            return RedirectResponse("/users/new", status_code=303)

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
            tenant_quota=quota,
        )
    except usr.UserError as e:
        _flash(request, str(e), "error")
        return RedirectResponse("/users/new", status_code=303)

    events.log(
        "user_created", "user",
        actor=user, target_user=new_user,
        details=f"rol={new_user['role']}, empresa={new_user.get('company_name') or '—'}",
        ip=_client_ip(request),
    )

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
    return templates.TemplateResponse(
        "user_form.html",
        {
            "request": request, "user": user,
            "edit": edit, "flash": _pop_flash(request),
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
    tenant_quota: str = Form(""),
    new_password: str = Form(""),
    user: dict = Depends(current_admin),
):
    quota = None
    if tenant_quota.strip():
        try:
            quota = int(tenant_quota)
        except ValueError:
            _flash(request, "Quota debe ser un número.", "error")
            return RedirectResponse(f"/users/{user_id}/edit", status_code=303)
    target = usr.get_user(user_id)
    try:
        usr.update_user(
            user_id,
            company_name=company_name,
            first_name=first_name,
            last_name=last_name,
            phone_cc=phone_cc,
            phone=phone,
            email=email,
            telegram_chat_id=telegram_chat_id,
            tenant_quota=quota,
            role=role,
            new_password=new_password or None,
        )
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
    user_token = (user.get("telegram_bot_token") or "").strip()
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
    user: dict = Depends(current_admin),
):
    rows = events.list_events(
        actor_role=source or None,
        category=category or None,
        search=q or None,
        limit=300,
    )
    return JSONResponse(
        {"events": rows, "filters": {"source": source, "category": category, "q": q}},
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
def api_logs_me(user: dict = Depends(current_user)):
    rows = events.list_events_for_user(user["id"], limit=300)
    return JSONResponse({"events": rows}, headers={"Cache-Control": "no-store"})
