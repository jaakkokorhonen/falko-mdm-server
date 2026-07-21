"""Apple MDM Check-In endpoint (/checkin).

Käsittelee viestit:
  - Authenticate  — laitteen ensimmäinen yhteydenotto
  - TokenUpdate   — APNs push token päivittyy
  - CheckOut      — laite poistuu MDM-hallinnasta

Apple MDM Protocol Reference:
https://developer.apple.com/documentation/devicemanagement/check-in
"""
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from plistlib import loads as plist_loads, FMT_XML
from .db import upsert_device

checkin_bp = Blueprint("checkin", __name__)
logger = logging.getLogger(__name__)


@checkin_bp.post("/checkin")
def checkin():
    try:
        data = plist_loads(request.data, fmt=FMT_XML)
    except Exception as exc:
        logger.warning("Checkin: plist-jäsennys epäonnistui: %s", exc)
        return jsonify({"error": "invalid plist"}), 400

    message_type = data.get("MessageType", "")
    udid = data.get("UDID", "unknown")
    logger.info("CheckIn [%s] UDID=%s", message_type, udid)

    if message_type == "Authenticate":
        upsert_device(udid, {
            "udid": udid,
            "serial": data.get("SerialNumber", ""),
            "os": data.get("OSVersion", ""),
            "model": data.get("ProductName", ""),
            "enrolled_at": datetime.now(timezone.utc).isoformat(),
            "status": "authenticating",
        })

    elif message_type == "TokenUpdate":
        upsert_device(udid, {
            "push_token": data.get("Token", b"").hex(),
            "push_magic": data.get("PushMagic", ""),
            "topic": data.get("Topic", ""),
            "status": "enrolled",
            "last_seen": datetime.now(timezone.utc).isoformat(),
        })

    elif message_type == "CheckOut":
        upsert_device(udid, {
            "status": "unenrolled",
            "unenrolled_at": datetime.now(timezone.utc).isoformat(),
        })

    return "", 200
