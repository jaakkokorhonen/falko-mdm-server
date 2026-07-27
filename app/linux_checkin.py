"""Linux MDM Check-In endpoint (POST /linux/checkin).

Käsittelee Linux-agenttien rekisteröinti- ja uudelleenrekisteröintiviestit.
Authenticate — agentti käynnistyy tai rekisteröityy uudelleen.
CheckOut — laite poistetaan hallinnasta.

Huom: Tämä endpoint EI ole IAP-suojattu — Linux-laite ei ole Google-käyttäjä.
Bearer-token validoidaan linux_devices/{device_id}/token_hash -kentästä.
device_id validoidaan ennen Firestore-kirjoitusta (^[a-f0-9]{64}$).
Ref: LINUX.md — Checkin section.
"""
from __future__ import annotations
import logging
import re
from flask import Blueprint, jsonify, request
from .db import get_linux_device, upsert_linux_device

linux_checkin_bp = Blueprint("linux_checkin", __name__)
logger = logging.getLogger(__name__)

_DEVICE_ID_RE = re.compile(r"^[a-f0-9]{64}$")


@linux_checkin_bp.post("/linux/checkin")
def linux_checkin():
    """Käsittelee laitteen ensirekisteröinnin tai tilapäivityksen."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"status": "error", "message": "Missing or invalid token"}), 401

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    device_id = payload.get("device_id")
    if not device_id or not _DEVICE_ID_RE.match(device_id):
        return jsonify({"status": "error", "message": "Invalid device_id format"}), 400

    # (Real token hash lookup & verification will go here during implementation)
    logger.info("Checkin request received for device: %s", device_id)
    return jsonify({"status": "acknowledged"}), 200
