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

        stored_hash = device.get("token_hash")
        # ISO 27001 Audit Evidence (Timing attack mitigation):
        # Käytetään secrets.compare_digest ajoitushyökkäysten estämiseen token-vertailussa.
        if not stored_hash or not secrets.compare_digest(hash_token(token), stored_hash):
            return jsonify({"error": "Unauthorized"}), 401

        g.device = device
        g.device_id = resolved_device_id
        return f(*args, device_id=resolved_device_id, **kwargs)
    return wrapper

