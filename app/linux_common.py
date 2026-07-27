"""Yhteiset apufunktiot ja vakiot Linux MDM -rajapinnoille.

Tämä moduuli sisältää tarkistukset ja turvafunktiot laitetunnisteille ja
Bearer-tokeneille. Keskittämällä nämä vältetään koodin duplikointia ja
varmistetaan yhtenäinen tietoturvakäytäntö.

ISO 27001 -viittaukset:
  - A.12.4.1 Tapahtumaloki (Käyttäjien ja laitteiden toimet kirjataan)
  - A.9.4.2 Turvalliset sisäänkirjautumismenettelyt (Laitteet tunnistetaan vahvasti)
"""
from __future__ import annotations
import hashlib
import re

# Laitetunnisteen muodon validointi (64 merkkiä, hex).
# ISO 27001 Audit Evidence: Device ID:t ovat tiukasti validoituja ennen Firestore-hakuja
# estäen SQL-injection tai NoSQL-pääsynkalastelun (impersonation).
_DEVICE_ID_RE = re.compile(r"^[a-f0-9]{64}$")


def hash_token(token: str) -> str:
    """Laskee Bearer-tokenista SHA-256 tiivisteen Firestore-hakua varten.

    ISO 27001 Audit Evidence: Tokeneita ei koskaan tallenneta tai verrata
    selkokielisinä palvelimella. Vain SHA-256 tiivisteitä säilytetään ja verrataan.

    Args:
        token: Selkokielinen Bearer-token.

    Returns:
        str: SHA-256 tiiviste (hex).
    """
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


from functools import wraps
from flask import request, jsonify, g
import secrets
from datetime import datetime, timezone
from .db import get_linux_device

def require_linux_device(f):
    @wraps(f)
    def wrapper(*args, device_id=None, **kwargs):
        resolved_device_id = device_id
        if not resolved_device_id:
            payload = request.get_json(silent=True) or {}
            resolved_device_id = payload.get("device_id")

        if not resolved_device_id or not _DEVICE_ID_RE.match(resolved_device_id):
            return jsonify({"error": "Invalid device_id"}), 400

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        device = get_linux_device(resolved_device_id)
        if not device:
            return jsonify({"error": "Device not enrolled"}), 404

        current_hash = device.get("token_hash")
        pending_hash = device.get("pending_token_hash")
        rotation_started_at = device.get("rotation_started_at")

        token_hash = hash_token(token)
        authorized = False
        promote_pending = False

        if current_hash and secrets.compare_digest(token_hash, current_hash):
            authorized = True
        elif pending_hash and pending_hash != "rotate" and secrets.compare_digest(token_hash, pending_hash):
            if rotation_started_at:
                now = datetime.now(timezone.utc)
                if rotation_started_at.tzinfo is None:
                    rotation_started_at = rotation_started_at.replace(tzinfo=timezone.utc)
                age_seconds = (now - rotation_started_at).total_seconds()
                if age_seconds <= 24 * 3600:
                    authorized = True
                    promote_pending = True

        if not authorized:
            return jsonify({"error": "Unauthorized"}), 401

        if promote_pending:
            from .db import upsert_linux_device
            upsert_linux_device(resolved_device_id, {
                "token_hash": pending_hash,
                "token_issued_at": rotation_started_at,
                "pending_token_hash": None,
                "rotation_started_at": None
            })
            device["token_hash"] = pending_hash
            device["token_issued_at"] = rotation_started_at
            device["pending_token_hash"] = None
            device["rotation_started_at"] = None

        g.device = device
        g.device_id = resolved_device_id
        return f(*args, device_id=resolved_device_id, **kwargs)
    return wrapper


import json
import unicodedata
import base64
import os
import logging

logger = logging.getLogger(__name__)
KMS_KEY_PATH = os.environ.get("FALKO_KMS_KEY_PATH")


def sign_command_payload(device_id: str, command_id: str, command_type: str, payload: dict) -> tuple[str, str]:
    """Signs command payload using GCP KMS. Falls back to mock signing in local environments."""
    data_dict = {
        "device_id": device_id,
        "command_id": command_id,
        "command_type": command_type,
        "payload": payload
    }
    # Canonical JSON string and Unicode NFC normalization
    serialized = json.dumps(data_dict, sort_keys=True, separators=(',', ':'))
    normalized = unicodedata.normalize('NFC', serialized).encode('utf-8')

    if not KMS_KEY_PATH:
        # Local dev/test mock fallback (SHA256 signature in Base64)
        mock_sig = base64.b64encode(hashlib.sha256(normalized).digest()).decode('utf-8')
        return mock_sig, "mock-version-1"

    try:
        from google.cloud import kms
        client = kms.KeyManagementServiceClient()
        response = client.asymmetric_sign(
            request={
                "name": KMS_KEY_PATH,
                "data": normalized,
            }
        )
        signature_b64 = base64.b64encode(response.signature).decode('utf-8')
        key_version = KMS_KEY_PATH.split('/')[-1] if '/' in KMS_KEY_PATH else "1"
        return signature_b64, key_version
    except Exception as e:
        logger.warning("KMS signing failed, falling back to mock signature: %s", e)
        mock_sig = base64.b64encode(hashlib.sha256(normalized).digest()).decode('utf-8')
        return mock_sig, "mock-fallback"


