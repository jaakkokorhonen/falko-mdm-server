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
from flask import Blueprint, jsonify, request, g
from .db import upsert_linux_device
from .linux_common import require_linux_device

linux_checkin_bp = Blueprint("linux_checkin", __name__)
logger = logging.getLogger(__name__)


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
