"""Linux MDM Check-In endpoint (POST /linux/checkin).

Käsittelee Linux-agenttien rekisteröinti- ja uudelleenrekisteröintiviestit.
Authenticate — agentti käynnistyy tai rekisteröityy uudelleen.
CheckOut — laite poistetaan hallinnasta.

Huom: Tämä endpoint EI ole IAP-suojattu — Linux-laite ei ole Google-käyttäjä.
Bearer-token validoidaan linux_devices/{device_id}/token_hash -kentästä.
device_id validoidaan ennen Firestore-kirjoitusta (^[a-f0-9]{64}$).
Ref: LINUX.md — Checkin section.

ISO 27001 Audit Evidence:
  - Control A.9.4.2 (Secure log-on procedures): Bearer-token tarkistetaan SHA-256 tiivisteen
    kautta tietokannasta. Selkokielisiä avaimia ei tallenneta palvelimelle.
  - Control A.12.4.1 (Event logging): Laitteiden tunnistusvirheet ja onnistumiset lokitetaan.

Arkkitehtoniset päätökset (Production Simplifications):
  - Päätetty olla toteuttamatta mTLS-varmennetunnistusta (GCP CAS + Load Balancer).
    Korvattu SHA-256 tiivistetyllä Bearer-tokenilla ja GCP KMS -pohjaisella komentojen
    allekirjoituksella (Issue #44). Tämä estää RCE-tason hyökkäykset tehokkaasti ilman
    Load Balancerin ja varmennepoolin tuomaa infrastruktuurikuormaa.
  - Päätetty olla toteuttamatta FCM/SSE-pohjaista push-herätettä. Korvattu säädettävällä
    tiheämmällä pollauksella (esim. 300 s), mikä poistaa palvelininstanssien tarpeen ylläpitää
    pitkiä taustayhteyksiä Cloud Runissa.
"""
from __future__ import annotations
import logging
import secrets
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, g
from .db import upsert_linux_device, get_linux_device
from .linux_common import require_linux_device, hash_token

linux_checkin_bp = Blueprint("linux_checkin", __name__)
logger = logging.getLogger(__name__)


@linux_checkin_bp.post("/linux/enroll")
def linux_enroll():
    """Enrollaa uuden Linux-laitteen tai uudelleenrekisteröi olemassaolevan.

    Tarkistaa one-time enrollaustokeenin, luo device-tokenin ja tallentaa
    laitteen Firestoreen. token_issued_at tallennetaan tässä jotta
    linux_mdm.py:n automaattinen 30 pv rotaatiolojiikka toimii.

    ISO 27001 Audit Evidence:
      - Control A.9.4.2: One-time token validoitu ja merkitty käytetyksi.
      - Control A.12.4.1: Enrollaus lokitetaan device_id:llä.
    """
    payload = request.get_json(silent=True) or {}
    device_id = payload.get("device_id", "")
    hostname = payload.get("hostname", "")
    one_time_token = payload.get("one_time_token", "")

    # Validoi device_id-muoto
    import re
    if not re.match(r'^[a-f0-9]{64}$', device_id):
        return jsonify({"error": "Invalid device_id format"}), 400

    if not one_time_token:
        return jsonify({"error": "one_time_token vaaditaan"}), 400

    # Tarkista one-time token Firestoresta
    from .db import get_db
    db = get_db()
    token_doc_ref = db.collection("enroll_tokens").document(one_time_token)
    token_doc = token_doc_ref.get()

    if not token_doc.exists:
        logger.warning("Enrollaus hylätty: tuntematon one_time_token, device_id=%s", device_id)
        return jsonify({"error": "Invalid or expired enrollment token"}), 403

    token_data = token_doc.to_dict()
    if token_data.get("used", False):
        logger.warning("Enrollaus hylätty: käytetty one_time_token, device_id=%s", device_id)
        return jsonify({"error": "Enrollment token already used"}), 403

    expires_at = token_data.get("expires_at")
    if expires_at:
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            logger.warning("Enrollaus hylätty: vanhentunut one_time_token, device_id=%s", device_id)
            return jsonify({"error": "Enrollment token has expired"}), 403

    # Merkitään token käytetyksi
    token_doc_ref.update({"used": True})

    # Luodaan device-token ja tallennetaan hash
    device_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)

    # KRIITTINEN: token_issued_at tallennetaan tässä enrollauksessa.
    # Ilman tätä linux_mdm.py:n rotaatiotarkistus (should_rotate) ei koskaan
    # laukea olemassaolevilla laitteilla (token_issued_at olisi None).
    # Ref: Issue #58 — Token rotation auto-30d
    upsert_linux_device(device_id, {
        "device_id": device_id,
        "hostname": hostname,
        "status": "enrolled",
        "token_hash": hash_token(device_token),
        "token_issued_at": now,           # <-- tämä puuttui aiemmin
        "pending_token_hash": None,
        "pending_token_issued_at": None,
        "rotation_requested": False,
        "shell_command_enabled": False,
        "enrolled_at": now.isoformat(),
        "agent_version": payload.get("agent_version", ""),
    })

    logger.info(
        "Linux-laite enrollattu onnistuneesti",
        extra={"device_id": device_id, "hostname": hostname}
    )
    return jsonify({"device_token": device_token}), 200


@linux_checkin_bp.post("/linux/checkin")
@require_linux_device
def linux_checkin():
    """Käsittelee laitteen ensirekisteröinnin tai tilapäivityksen."""
    payload = request.get_json(silent=True) or {}
    device_id = g.device_id

    # Päivitetään laitteen tiedot ja tilanneilmoitus.
    upsert_data = {
        "hostname": payload.get("hostname", ""),
        "os": payload.get("os", ""),
        "kernel": payload.get("kernel", ""),
        "arch": payload.get("arch", ""),
        "cpu": payload.get("cpu", ""),
        "ram_gb": payload.get("ram_gb", 0),
        "ip_local": payload.get("ip_local", ""),
        "agent_version": payload.get("agent_version", ""),
        "last_seen": payload.get("last_seen", ""),
    }
    upsert_linux_device(device_id, upsert_data)

    logger.info("Check-in successful for device: %s", device_id)
    return jsonify({"status": "acknowledged"}), 200
