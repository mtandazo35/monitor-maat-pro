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


def create_record(fqdn: str, ip: str) -> dict:
    """Crea (o actualiza si ya existe) un registro A fqdn→ip. Idempotente.
    Devuelve {'skipped': ...} si la integración está deshabilitada o sin token."""
    cfg = settings_service.get_cloudflare_config()
    if not cfg["enabled"] or not cfg["token"]:
        return {"skipped": "Cloudflare deshabilitado o sin token"}
    if not fqdn or not ip:
        return {"skipped": "falta fqdn o ip"}
    token = cfg["token"]
    proxied = cfg["proxied"]
    zone_id, _zone = _zone_id_for(fqdn, token)
    payload = {"type": "A", "name": fqdn, "content": ip, "proxied": proxied, "ttl": 1}
    existing = _find_a_records(zone_id, fqdn, token)
    if existing:
        rec_id = existing[0]["id"]
        _req("PUT", f"/zones/{zone_id}/dns_records/{rec_id}", token, payload)
        return {"updated": fqdn, "ip": ip, "proxied": proxied}
    _req("POST", f"/zones/{zone_id}/dns_records", token, payload)
    return {"created": fqdn, "ip": ip, "proxied": proxied}


def delete_record(fqdn: str) -> dict:
    """Borra todos los registros A de fqdn. Idempotente."""
    cfg = settings_service.get_cloudflare_config()
    if not cfg["enabled"] or not cfg["token"]:
        return {"skipped": "Cloudflare deshabilitado o sin token"}
    if not fqdn:
        return {"skipped": "falta fqdn"}
    token = cfg["token"]
    zone_id, _zone = _zone_id_for(fqdn, token)
    recs = _find_a_records(zone_id, fqdn, token)
    for r in recs:
        _req("DELETE", f"/zones/{zone_id}/dns_records/{r['id']}", token)
    return {"deleted": fqdn, "count": len(recs)}


def sync_all(panel_domain: str, tenants_domain: str, ip: str, tenant_names: list) -> dict:
    """Asegura el registro del panel + de cada tenant existente. Best-effort:
    acumula errores por host y sigue. Devuelve {'ok': [...], 'errors': [...]}."""
    cfg = settings_service.get_cloudflare_config()
    if not cfg["enabled"] or not cfg["token"]:
        return {"skipped": "Cloudflare deshabilitado o sin token"}
    ok, errors = [], []
    targets = []
    if panel_domain:
        targets.append(panel_domain)
    if tenants_domain:
        targets += [f"{n}.{tenants_domain}" for n in tenant_names]
    for fqdn in targets:
        try:
            create_record(fqdn, ip)
            ok.append(fqdn)
        except CloudflareError as e:
            errors.append(f"{fqdn}: {e}")
    return {"ok": ok, "errors": errors}
