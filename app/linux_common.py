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
from functools import wraps
from flask import request, jsonify, g
import secrets
from datetime import datetime, timezone
from .db import get_linux_device

# ---------------------------------------------------------------------------
# Vakiot
# ---------------------------------------------------------------------------

# Laitetunnisteen muodon validointi (64 merkkiä, hex).
# ISO 27001 Audit Evidence: Device ID:t ovat tiukasti validoituja ennen Firestore-hakuja
# estäen SQL-injection tai NoSQL-pääsynkalastelun (impersonation).
_DEVICE_ID_RE = re.compile(r"^[a-f0-9]{64}$")

# Token rotation -vakiot — käytetään sekä linux_common.py:ssä että linux_mdm.py:ssä.
# Yhteinen lähde estää magic number -duplikaation.
TOKEN_GRACE_PERIOD_SECONDS: int = 24 * 3600   # 24 h
TOKEN_ROTATION_DAYS: int = 30                  # 30 vrk


# ---------------------------------------------------------------------------
# Hash-apufunktio
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Autentikaatiodekoraattori
# ---------------------------------------------------------------------------

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
        pending_issued_at = device.get("pending_token_issued_at")

        token_hash = hash_token(token)
        authorized = False
        promote_pending = False

        if current_hash and secrets.compare_digest(token_hash, current_hash):
            authorized = True
        elif pending_hash and secrets.compare_digest(token_hash, pending_hash):
            if pending_issued_at:
                now = datetime.now(timezone.utc)
                if pending_issued_at.tzinfo is None:
                    pending_issued_at = pending_issued_at.replace(tzinfo=timezone.utc)
                age_seconds = (now - pending_issued_at).total_seconds()
                if age_seconds <= TOKEN_GRACE_PERIOD_SECONDS:
                    authorized = True
                    promote_pending = True

        if not authorized:
            return jsonify({"error": "Unauthorized"}), 401

        if promote_pending:
            from .db import upsert_linux_device
            upsert_linux_device(resolved_device_id, {
                "token_hash": pending_hash,
                "token_issued_at": pending_issued_at,
                "pending_token_hash": None,
                "pending_token_issued_at": None
            })
            device["token_hash"] = pending_hash
            device["token_issued_at"] = pending_issued_at
            device["pending_token_hash"] = None
            device["pending_token_issued_at"] = None

        g.device = device
        g.device_id = resolved_device_id
        return f(*args, device_id=resolved_device_id, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# KMS-allekirjoitus
# ---------------------------------------------------------------------------

import json
import unicodedata
import base64
import os
import logging

logger = logging.getLogger(__name__)
KMS_KEY_PATH: str | None = os.environ.get("FALKO_KMS_KEY_PATH")


def sign_command_payload(
    device_id: str,
    command_id: str,
    command_type: str,
    payload: dict,
) -> tuple[str, str]:
    """Allekirjoittaa komentojen kuorman GCP KMS:llä.

    Jos FALKO_KMS_KEY_PATH ei ole asetettu (lokaali kehitys/testaus),
    käytetään SHA-256-pohjaista mock-allekirjoitusta.

    Tuotannossa (FALKO_KMS_KEY_PATH asetettu) KMS-virhe heittää RuntimeError:
    kutsuva koodi palauttaa HTTP 503 adminille eikä laske mock-fallbackiin.
    Tämä estää komentojen lähetyksen ilman kryptografista suojausta KMS-katkon
    sattuessa.

    Args:
        device_id: Laitteen tunniste.
        command_id: Komennon yksilöllinen tunniste.
        command_type: Komennon tyyppi (esim. 'InstallPackage').
        payload: Komennon parametrit.

    Returns:
        tuple[str, str]: (allekirjoitus base64, avainversio)

    Raises:
        RuntimeError: Jos KMS-allekirjoitus epäonnistuu tuotannossa.
    """
    data_dict = {
        "device_id": device_id,
        "command_id": command_id,
        "command_type": command_type,
        "payload": payload,
    }
    # Kanoninen JSON + NFC-normalisointi (yhteensopiva agentin verify_command_signature():n kanssa)
    serialized = json.dumps(data_dict, sort_keys=True, separators=(',', ':'))
    normalized = unicodedata.normalize('NFC', serialized).encode('utf-8')

    if not KMS_KEY_PATH:
        # Lokaali kehitys/testaus — mock-allekirjoitus
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
        # Tuotannossa KMS-virhe on kriittinen — ei sallita fallbackia.
        # HTTP 503 palautetaan adminille kutsuvan koodin kautta.
        logger.error("KMS signing failed: %s", e)
        raise RuntimeError(f"Command signing unavailable: {e}") from e
