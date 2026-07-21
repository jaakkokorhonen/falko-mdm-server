"""Apple MDM Check-In endpoint (/checkin).

Käsittelee viestit:
  - Authenticate  — laitteen ensimmäinen yhteydenotto
  - TokenUpdate   — APNs push token päivittyy
  - CheckOut      — laite poistuu MDM-hallinnasta

Apple MDM Protocol Reference:
https://developer.apple.com/documentation/devicemanagement/check-in

Security note: Tämä endpoint ei vaadi admin-autentikaatiota (laitteet kutsuvat sitä).
Validoi UDID-formaatin ennen Firestore-kirjoitusta. Malformed UDID voisi luoda
odottamattoman dokumenttipolun tai aiheuttaa ongelmia myöhemmissä kyselyissä.
Ref: Fleet MDM CVE-2026-34385 (SQL injection via UDID interpolation)
"""
import re
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from plistlib import loads as plist_loads, FMT_XML
from .db import upsert_device

checkin_bp = Blueprint("checkin", __name__)
logger = logging.getLogger(__name__)

# Apple UDID on joko legacy-muoto (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)
# tai uudempi UUID-muoto. Sallitaan molemmat: isot kirjaimet, numerot ja väliviiva,
# 20–40 merkkiä. Tämä hylkää tyhjän, liian lyhyen tai erikoismerkkejä sisältävän UDIDin.
_UDID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{18,38}[A-Z0-9]$")


def _validate_udid(udid: str) -> bool:
    """Tarkistaa UDID-formaatin säännöllisellä lausekkeella.

    Args:
        udid: Laitteen UDID Apple-protokollaviestistä.

    Returns:
        True jos UDID on hyväksyttävässä muodossa, False muuten.
    """
    return bool(_UDID_RE.match(udid))


@checkin_bp.post("/checkin")
def checkin():
    try:
        data = plist_loads(request.data, fmt=FMT_XML)
    except Exception as exc:
        logger.warning("Checkin: plist-jäsennys epäonnistui: %s", exc)
        return jsonify({"error": "invalid plist"}), 400

    message_type = data.get("MessageType", "")

    # UDID-formaattivalidointi: hylätään puuttuvat tai epämuodostuneet UDIDit.
    # Apple ei takaa UDID-kentän läsnäoloa Authenticate-viestissä, ja
    # malformed-arvo voisi aiheuttaa ongelmia Firestore-polkujen kanssa.
    udid = data.get("UDID", "")
    if not udid or not _validate_udid(udid):
        logger.warning("Checkin: virheellinen tai puuttuva UDID: %r", udid[:40] if udid else "")
        return "", 400

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
            # Token on bytes-objekti TokenUpdate-viestissä — muunnetaan hex-stringiksi
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
