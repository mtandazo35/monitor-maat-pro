"""Integración con la API de Cloudflare para gestionar el DNS de los tenants.

Cuando se crea una empresa/tenant, el panel le da la orden a Cloudflare de crear un
registro A `<tenant>.<tenants_domain>` apuntando a la IP del VPS; al borrarla, lo
elimina. Así Caddy detecta el host nuevo y emite el cert automáticamente, sin que
nadie toque el DNS a mano.

Seguridad: el token se guarda CIFRADO (settings_service + crypto) y debe ser un token
SCOPED (Zone.DNS:Edit + Zone:Read sobre esa zona), NUNCA el Global API Key. Los
errores NO son fatales para la operación de tenant: si Cloudflare falla, el tenant se
crea igual y el error se reporta/loguea.
"""
import json
import urllib.parse
import urllib.request
import urllib.error

import settings_service

API = "https://api.cloudflare.com/client/v4"


class CloudflareError(Exception):
    pass


def _req(method: str, path: str, token: str, payload=None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        msg = raw
        try:
            j = json.loads(raw)
            errs = j.get("errors") or []
            msg = "; ".join(x.get("message", "") for x in errs) or raw
        except Exception:
            pass
        raise CloudflareError(f"Cloudflare API {e.code}: {msg}")
    except Exception as e:
        raise CloudflareError(f"No se pudo contactar Cloudflare: {e}")
    j = json.loads(body)
    if not j.get("success", False):
        errs = j.get("errors") or []
        raise CloudflareError("; ".join(x.get("message", "") for x in errs) or "error desconocido")
    return j


def verify_token(token: str) -> dict:
    """Valida un token (GET /user/tokens/verify). Devuelve {'ok': bool, 'msg': str}."""
    if not token or not token.strip():
        return {"ok": False, "msg": "Token vacío"}
    try:
        j = _req("GET", "/user/tokens/verify", token.strip())
        status = (j.get("result") or {}).get("status", "")
        return {"ok": status == "active", "msg": f"Token {status or 'sin estado'}"}
    except CloudflareError as e:
        return {"ok": False, "msg": str(e)}


# Cache en memoria (token, sufijo-candidato) -> (zone_id, zone_name). Evita
# re-consultar /zones en cada alta/baja de tenant; al cambiar el token la key
# cambia sola, y un restart del container lo limpia.
_zone_cache: dict = {}


def _zone_id_for(fqdn: str, token: str) -> tuple:
    """Resuelve (zone_id, zone_name) probando sufijos del fqdn: para
    'acme.kuma.midominio.com' prueba ese, luego 'kuma.midominio.com', luego
    'midominio.com' hasta que Cloudflare devuelva una zona."""
    labels = fqdn.strip(".").split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    for candidate in candidates:
        hit = _zone_cache.get((token, candidate))
        if hit:
            return hit
    for candidate in candidates:
        q = urllib.parse.quote(candidate)
        res = _req("GET", f"/zones?name={q}&status=active", token).get("result") or []
        if res:
            zone = (res[0]["id"], res[0]["name"])
            _zone_cache[(token, candidate)] = zone
            return zone
    raise CloudflareError(f"No encontré la zona en Cloudflare para '{fqdn}'. ¿El dominio está en esta cuenta?")


def _find_a_records(zone_id: str, fqdn: str, token: str) -> list:
    q = urllib.parse.quote(fqdn)
    return _req("GET", f"/zones/{zone_id}/dns_records?type=A&name={q}", token).get("result") or []


def _upsert_record(fqdn: str, ip: str, token: str, proxied: bool) -> dict:
    """Crea (o actualiza si ya existe) un registro A fqdn→ip. Idempotente.
    Sin guardas de modo — los callers deciden cuándo corresponde."""
    zone_id, _zone = _zone_id_for(fqdn, token)
    payload = {"type": "A", "name": fqdn, "content": ip, "proxied": proxied, "ttl": 1}
    existing = _find_a_records(zone_id, fqdn, token)
    if existing:
        rec_id = existing[0]["id"]
        _req("PUT", f"/zones/{zone_id}/dns_records/{rec_id}", token, payload)
        return {"updated": fqdn, "ip": ip, "proxied": proxied}
    _req("POST", f"/zones/{zone_id}/dns_records", token, payload)
    return {"created": fqdn, "ip": ip, "proxied": proxied}


def create_record(fqdn: str, ip: str) -> dict:
    """Registro A por-tenant. Solo actúa en modo cf_auto (en certbot el wildcard
    ya cubre todos los subdominios; en caddy el DNS es manual)."""
    cfg = settings_service.get_cloudflare_config()
    if not cfg["enabled"] or not cfg["token"]:
        return {"skipped": "auto-DNS por-tenant deshabilitado o sin token"}
    if not fqdn or not ip:
        return {"skipped": "falta fqdn o ip"}
    return _upsert_record(fqdn, ip, cfg["token"], cfg["proxied"])


def delete_record(fqdn: str) -> dict:
    """Borra todos los registros A de fqdn (baja de tenant, modo cf_auto). Idempotente."""
    cfg = settings_service.get_cloudflare_config()
    if not cfg["enabled"] or not cfg["token"]:
        return {"skipped": "auto-DNS por-tenant deshabilitado o sin token"}
    if not fqdn:
        return {"skipped": "falta fqdn"}
    token = cfg["token"]
    zone_id, _zone = _zone_id_for(fqdn, token)
    recs = _find_a_records(zone_id, fqdn, token)
    for r in recs:
        _req("DELETE", f"/zones/{zone_id}/dns_records/{r['id']}", token)
    return {"deleted": fqdn, "count": len(recs)}


def set_zone_ssl_mode(domain: str, value: str = "strict") -> dict:
    """Pone el modo SSL/TLS de la zona (PATCH /zones/{id}/settings/ssl).
    Usado por cf_origin para dejar la zona en 'strict' (Full strict). Requiere que
    el token tenga permiso Zone Settings:Edit; si no lo tiene, devuelve el error
    para que la UI sugiera hacerlo a mano. Best-effort, no fatal."""
    cfg = settings_service.get_cloudflare_config()
    token = cfg["token"]
    if not token:
        return {"skipped": "sin token"}
    zone_id, _zone = _zone_id_for(domain, token)
    _req("PATCH", f"/zones/{zone_id}/settings/ssl", token, {"value": value})
    return {"ok": value}


def sync_all(tenants_domain: str, ip: str, tenant_names: list) -> dict:
    """Asegura los registros DNS de los TENANTS según el modo configurado:
    - cf_auto    → un registro A por tenant (`<nombre>.<dominio>`), nube gris
    - cf_origin  → un registro A por tenant, nube NARANJA (proxied)
    - certbot    → un único registro A wildcard (`*.<dominio>`)
    - caddy      → no toca nada (DNS manual)
    El dominio del PANEL no se gestiona acá — va siempre por Caddy con su
    registro A manual (separación pedida a propósito).
    Best-effort: acumula errores por host y sigue."""
    mode = settings_service.get_tenants_ssl_mode()
    cfg = settings_service.get_cloudflare_config()
    if mode not in ("cf_auto", "certbot", "cf_origin") or not cfg["token"]:
        return {"skipped": "auto-DNS deshabilitado o sin token"}
    if not tenants_domain or not ip:
        return {"skipped": "falta tenants_domain o ip"}
    if mode == "certbot":
        targets = [f"*.{tenants_domain}"]
    else:
        targets = [f"{n}.{tenants_domain}" for n in tenant_names]
    ok, errors = [], []
    for fqdn in targets:
        try:
            _upsert_record(fqdn, ip, cfg["token"], cfg["proxied"])
            ok.append(fqdn)
        except CloudflareError as e:
            errors.append(f"{fqdn}: {e}")
    return {"ok": ok, "errors": errors}
