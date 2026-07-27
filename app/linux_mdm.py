"""Linux MDM command poll endpoint (PUT /linux/mdm/<device_id>).

Linux-agentti pollaa tätä endpointtia säännöllisesti (oletus 900 s).
Protokollaflow: ks. LINUX.md — Command Poll -osio.
Auth: Bearer-token (MVP) / mTLS (prod). Ei IAP-suojausta.
device_id validoidaan: ^[a-f0-9]{64}$
"""
from __future__ import annotations
import logging
import re
from flask import Blueprint, jsonify, request
from .db import (
    ack_linux_command,
    dequeue_linux_command,
    get_linux_device,
    upsert_linux_device,
)

linux_mdm_bp = Blueprint("linux_mdm", __name__)
logger = logging.getLogger(__name__)

_DEVICE_ID_RE = re.compile(r"^[a-f0-9]{64}$")


@linux_mdm_bp.put("/linux/mdm/<device_id>")
def linux_mdm(device_id: str):
    """Käsittelee agentin komentokyselyn (poll) ja edellisen komennon kuittauksen (ack)."""
    if not _DEVICE_ID_RE.match(device_id):
        return jsonify({"status": "error", "message": "Invalid device_id format"}), 400

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"status": "error", "message": "Missing or invalid token"}), 401

    # (Real command lookup, ACK, and token validation logic will be here)
    logger.info("MDM poll request received for device: %s", device_id)
    return jsonify({
        "command": None,
        "server_meta": {
            "latest_agent_version": "0.1.0"
        }
    }), 200
