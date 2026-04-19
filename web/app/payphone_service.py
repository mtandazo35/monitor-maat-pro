"""Integración con PayPhone Ecuador.

Wrappea las dos llamadas que necesitamos del API de PayPhone:
- POST /api/button/Prepare        → crea pago, devuelve paymentUrl + paymentId
- POST /api/button/V2/Confirm     → confirma estado de la transacción

Cálculo de IVA 15% Ecuador: amount = base + tax, donde base = round(amount/1.15).
PayPhone trabaja en CENTAVOS (multiplicar precio en USD por 100).

Sin dependencias externas (urllib stdlib).
"""

import json
import secrets
import time
import urllib.error
import urllib.request
from typing import Optional

import settings_service


class NotConfigured(Exception):
    pass


class PayphoneError(Exception):
    pass


def is_configured() -> bool:
    cfg = settings_service.get_payphone_config()
    return bool(cfg.get("token") and cfg.get("store_id"))


def _post_json(url: str, payload: dict, token: str, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise PayphoneError(f"PayPhone HTTP {e.code}: {body}") from e
    except Exception as e:
        raise PayphoneError(f"Error llamando a PayPhone: {e}") from e


def generate_client_tx_id(prefix: str = "MM") -> str:
    """Genera un clientTransactionId único: prefix-timestamp-random."""
    return f"{prefix}-{int(time.time() * 1000)}-{secrets.token_hex(4)}"


def _split_iva(amount_usd: float) -> tuple[int, int, int]:
    """Convierte USD a (total_centavos, base_sin_iva_centavos, iva_centavos).
    PayPhone exige que total = base + iva, todo en centavos."""
    total = round(amount_usd * 100)
    base = round(total / 1.15)
    tax = total - base
    return total, base, tax


def create_payment(
    amount_usd: float,
    client_tx_id: str,
    customer_email: str,
    response_url: str,
    cancellation_url: str,
    reference: str = "Pago MonitorMaat",
    metadata: Optional[dict] = None,
) -> dict:
    """Crea pago en PayPhone. Devuelve {payment_url, payment_id, raw}.

    response_url: URL pública donde PayPhone llamará al terminar (webhook)
    cancellation_url: URL donde redirigir si el usuario cancela
    """
    cfg = settings_service.get_payphone_config()
    token = cfg.get("token")
    store_id = cfg.get("store_id")
    api_url = cfg.get("api_url") or "https://pay.payphonetodoesposible.com"
    if not token or not store_id:
        raise NotConfigured("PayPhone no configurado (Settings → PayPhone)")

    total, base, tax = _split_iva(amount_usd)
    payload = {
        "amount": total,
        "amountWithoutTax": 0,
        "amountWithTax": base,
        "tax": tax,
        "service": 0,
        "tip": 0,
        "storeId": store_id,
        "clientTransactionId": client_tx_id,
        "currency": "USD",
        "responseUrl": response_url,
        "cancellationUrl": cancellation_url,
        "reference": reference,
        "phoneNumber": None,
        "email": customer_email,
        "documentId": None,
    }
    if metadata:
        payload["optionalParameter"] = json.dumps(metadata)

    raw = _post_json(f"{api_url}/api/button/Prepare", payload, token)
    payment_url = raw.get("payWithPayPhone") or raw.get("paymentUrl") or raw.get("url")
    payment_id = raw.get("paymentId")
    if not payment_url or not payment_id:
        raise PayphoneError(f"Respuesta inesperada de PayPhone: {raw}")
    return {"payment_url": payment_url, "payment_id": str(payment_id), "raw": raw}


def confirm_transaction(payment_id: str, client_tx_id: str) -> dict:
    """Confirma una transacción contra PayPhone.
    Devuelve dict con `transactionStatus` ('Approved', 'Denied', 'Cancelled', 'Expired')
    + datos completos de la transacción."""
    cfg = settings_service.get_payphone_config()
    token = cfg.get("token")
    api_url = cfg.get("api_url") or "https://pay.payphonetodoesposible.com"
    if not token:
        raise NotConfigured("PayPhone no configurado")
    payload = {"id": int(payment_id), "clientTxId": client_tx_id}
    return _post_json(f"{api_url}/api/button/V2/Confirm", payload, token)
