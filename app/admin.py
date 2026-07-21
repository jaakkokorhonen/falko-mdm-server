"""Admin API — laitelistaus ja komentojen lähettäminen.

Endpointit:
  GET  /admin/devices              — lista kaikista laitteista
  GET  /admin/devices/<udid>        — yksittäisen laitteen tiedot
  POST /admin/devices/<udid>/command — lisää komento laitteen jonoon
  POST /admin/devices/<udid>/push   — lähetä APNs herätys

Autentikaatio: Google Identity-Aware Proxy (IAP) -otsake X-Goog-Authenticated-User-Email.
"""
import os
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import Blueprint, request, jsonify
from .db import list_devices, get_device, enqueue_command
from .apns import send_push

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
logger = logging.getLogger(__name__)


def require_iap(f):
    """Decorator: varmistaa Google IAP -otsakkeen ja falko.fi-sähköpostiosoitteen."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user_header = request.headers.get("X-Goog-Authenticated-User-Email", "")
        # Muoto: "accounts.google.com:jaakko@falko.fi"
        if not user_header or not user_header.startswith("accounts.google.com:"):
            return jsonify({"error": "IAP-autentikointi puuttuu tai on virheellinen"}), 401
        
        email = user_header.split("accounts.google.com:")[1]
        if not email.endswith("@falko.fi"):
            return jsonify({"error": "Käyttöoikeus evätty (vain falko.fi-käyttäjille)"}), 403
            
        return f(*args, **kwargs)
    return decorated


@admin_bp.get("/devices")
@require_iap
def list_all_devices():
    """Listaa kaikki rekisteröidyt laitteet."""
    devices = list_devices()
    return jsonify({"devices": devices, "count": len(devices)})


@admin_bp.get("/devices/<udid>")
@require_iap
def get_one_device(udid: str):
    """Palauttaa yksittäisen laitteen tiedot."""
    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404
    return jsonify(device)


@admin_bp.post("/devices/<udid>/command")
@require_iap
def send_command(udid: str):
    """Lisää MDM-komennon laitteen jonoon.

    Body (JSON):
      {
        "command_type": "DeviceInformation",  // Apple MDM RequestType
        "payload": {}                          // Komennon lisäparametrit
      }

    Tuetut komennot (yleisimmät):
      DeviceInformation   — laitetietojen kysely
      DeviceLock          — laite lukitaan välittömästi
      EraseDevice         — laite pyyhitään
      InstallApplication  — sovellusasennus (vaatii VPP)
      RestartDevice       — uudelleenkäynnistys
      ShutDownDevice      — sammutus
      EnableRemoteDesktop — etätyöpöytä päälle
      DisableRemoteDesktop — etätyöpöytä pois
    """
    body = request.get_json(silent=True) or {}
    command_type = body.get("command_type")
    if not command_type:
        return jsonify({"error": "command_type vaaditaan"}), 400

    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404

    cmd = {
        "command_type": command_type,
        "payload": body.get("payload", {}),
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    enqueue_command(udid, cmd)
    logger.info("Komento lisätty jonoon: UDID=%s type=%s", udid, command_type)

    return jsonify({"status": "queued", "command_type": command_type}), 202


@admin_bp.post("/devices/<udid>/push")
@require_iap
def trigger_push(udid: str):
    """Lähettää APNs herätyksen laitteelle jotta se pollaa MDM-serveriä."""
    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404

    push_token = device.get("push_token")
    push_magic = device.get("push_magic")
    topic = device.get("topic")
    if not push_token or not push_magic or not topic:
        return jsonify({"error": "Laitteella ei ole riittäviä APNs-tietoja (push_token, push_magic, topic)"}), 400

    sandbox = os.environ.get("APNS_SANDBOX", "false").lower() == "true"
    ok = send_push(push_token, push_magic, topic, sandbox=sandbox)

    if ok:
        return jsonify({"status": "push sent"}), 200
    else:
        return jsonify({"error": "APNs push epäonnistui"}), 502

