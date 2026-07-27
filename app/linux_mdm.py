"""Linux MDM command poll endpoint (PUT /linux/mdm/<device_id>).

Linux-agentti pollaa tätä endpointtia säännöllisesti (oletus 900 s).
Protokollaflow: ks. LINUX.md — Command Poll -osio.
Auth: Bearer-token (MVP) / mTLS (prod). Ei IAP-suojausta.
device_id validoidaan: ^[a-f0-9]{64}$

ISO 27001 Audit Evidence:
  - Control A.9.4.2 (Secure log-on procedures): Bearer-token tarkistetaan SHA-256 tiivisteen
    kautta Firestoresta ennen odottavien komentojen lukemista tai kuittaamista.
  - Control A.12.4.1 (Event logging): Komentojen pollaus, kuittaus ja epäonnistumiset lokitetaan.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
from .db import (
    ack_linux_command,
    dequeue_linux_command,
    get_linux_device,
    upsert_linux_device,
)
from .linux_common import _DEVICE_ID_RE, hash_token

linux_mdm_bp = Blueprint("linux_mdm", __name__)
logger = logging.getLogger(__name__)


@linux_mdm_bp.put("/linux/mdm/<device_id>")
def linux_mdm(device_id: str):
    """Käsittelee agentin komentokyselyn (poll) ja edellisen komennon kuittauksen (ack)."""
    if not _DEVICE_ID_RE.match(device_id):
        logger.warning("MDM poll attempt with invalid device_id format: %s", device_id)
        return jsonify({"status": "error", "message": "Invalid device_id format"}), 400

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning("MDM poll attempt with missing or invalid Authorization header format.")
        return jsonify({"status": "error", "message": "Missing or invalid token"}), 401

    token = auth_header.split(" ", 1)[1].strip()

    # Vahvistetaan laitteen olemassaolo ja token.
    # ISO 27001 Control A.9.4.2: Tunnistautuminen tarkistetaan SHA-256 tiivisteen kautta.
    device = get_linux_device(device_id)
    if not device:
        logger.error("MDM poll failed: Device %s not found in Firestore.", device_id)
        return jsonify({"status": "error", "message": "Device not enrolled"}), 404

    stored_hash = device.get("token_hash")
    if not stored_hash or hash_token(token) != stored_hash:
        logger.warning("Unauthorized MDM poll attempt for device %s (token mismatch).", device_id)
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    # Päivitetään viimeisin aktiivisuustieto (last_seen).
    # ISO 27001 Audit Evidence: Laitteen aktiivisuuden seuranta.
    now = datetime.now(timezone.utc).isoformat()
    upsert_linux_device(device_id, {"last_seen": now})

    payload = request.get_json(silent=True) or {}
    last_result = payload.get("result")

    # Jos pyynnössä on edellisen komennon tulos, kuitataan se.
    # ISO 27001 Audit Evidence: Komentojen suorituksen auditointilokitietue.
    if last_result:
        cmd_id = last_result.get("command_id")
        cmd_status = last_result.get("status", {})
        status_str = cmd_status.get("status", "acknowledged")
        if cmd_id:
            logger.info("Acknowledging command %s for device %s with status %s", cmd_id, device_id, status_str)
            ack_linux_command(device_id, cmd_id, status_str)

    # Haetaan seuraava odottava komento
    cmd_id, cmd_dict = dequeue_linux_command(device_id)
    command_payload = None
    if cmd_id and cmd_dict:
        command_payload = {
            "id": cmd_id,
            "type": cmd_dict.get("type"),
            "payload": cmd_dict.get("payload", {})
        }
        logger.info("Dispatched command %s to device %s", cmd_id, device_id)

    return jsonify({
        "command": command_payload,
        "server_meta": {
            "latest_agent_version": "0.1.0"
        }
    }), 200
