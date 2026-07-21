"""Apple MDM Check-In endpoint (/checkin).

Käsittelee Apple MDM -protokollan Check-In -viestit:
  Authenticate  — laitteen ensimmäinen yhteydenotto rekisteröinnin yhteydessä
  TokenUpdate   — APNs push token päivittyy (myös uudelleenrekisteröinnissä)
  CheckOut      — laite poistuu MDM-hallinnasta (käyttäjä poistaa profiilin)

Apple MDM Protocol Reference:
  https://developer.apple.com/documentation/devicemanagement/check-in

Huom: Tämä endpoint EI vaadi erillistä autentikaatiota — Apple-laite
kutsuu sitä mobileconfig-profiilin CheckInURL:n määrittämällä tavalla.
IAP-suojaus ei koske tätä endpointtia (laite ei ole Google-käyttäjä).
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
    """Käsittelee Apple MDM Check-In -pyyntön.

    Apple lähettää pyyntön XML-plistinä (Content-Type: application/x-apple-aspen-mdm-checkin).
    Endpoint palauttaa aina HTTP 200 onnistuneelle viestille — Apple odottaa tätä.

    Returns:
        200 tyhjällä vastauksella kaikille tunnistetuille MessageType-arvoille.
        400 jos plist-jäsennys epäonnistuu.
    """
    try:
        data = plist_loads(request.data, fmt=FMT_XML)
    except Exception as exc:
        logger.warning("Checkin: plist-jäsennys epäonnistui: %s", exc)
        return jsonify({"error": "invalid plist"}), 400

    message_type = data.get("MessageType", "")
    # Apple ei takaa UDID-kentän läsnäoloa kaikissa Check-In -viesteissä,
    # vaikka käytännössä se on aina mukana Authenticate- ja TokenUpdate-viesteissä
    udid = data.get("UDID", "unknown")
    logger.info("CheckIn [%s] UDID=%s", message_type, udid)

    if message_type == "Authenticate":
        # Ensimmäinen yhteydenotto — tallennetaan perustiedot.
        # Status on "authenticating" kunnes TokenUpdate saapuu.
        upsert_device(udid, {
            "udid":        udid,
            "serial":      data.get("SerialNumber", ""),
            "os":          data.get("OSVersion", ""),
            "model":       data.get("ProductName", ""),
            "enrolled_at": datetime.now(timezone.utc).isoformat(),
            "status":      "authenticating",
        })

    elif message_type == "TokenUpdate":
        # Laite toimittaa APNs-tiedot — vasta nyt voimme lähettää push-herätyksiä.
        # Token on bytes-objekti plistissä, muunnetaan hex-stringiksi tallennusta varten.
        upsert_device(udid, {
            "push_token": data.get("Token", b"").hex(),
            "push_magic": data.get("PushMagic", ""),
            "topic":      data.get("Topic", ""),
            "status":     "enrolled",
            "last_seen":  datetime.now(timezone.utc).isoformat(),
        })

    elif message_type == "CheckOut":
        # Käyttäjä poisti MDM-profiilin manuaalisesti tai laite pyyhittiin.
        # APNs-tietoja ei poisteta — ne vanhenevat itsestään.
        upsert_device(udid, {
            "status":        "unenrolled",
            "unenrolled_at": datetime.now(timezone.utc).isoformat(),
        })

    # Apple-spesifikaation mukaan 200 palautetaan aina — myös tuntemattomille viesteille
    return "", 200
