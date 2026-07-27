"""Linux MDM command poll endpoint (PUT /linux/mdm/<device_id>).

Linux-agentti pollaa tätä endpointtia säännöllisesti (oletus 900 s).
Protokollaflow: ks. LINUX.md — Command Poll -osio.
Auth: Bearer-token (MVP) / mTLS (prod). Ei IAP-suojausta.
device_id validoidaan: ^[a-f0-9]{64}$

ISO 27001 Audit Evidence:
  - Control A.9.4.2 (Secure log-on procedures): Bearer-token tarkistetaan SHA-256 tiivisteen
    kautta Firestoresta ennen odottavien komentojen lukemista tai kuittaamista.
  - Control A.12.4.1 (Event logging): MDM-pollauskyselyt, tulosten vastaanotot ja virheet lokitetaan.

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
import os
from google.cloud import firestore
from flask import Blueprint, jsonify, request, g
from .db import (
    ack_linux_command,
    dequeue_linux_command,
    upsert_linux_device,
)
from datetime import datetime, timezone
import secrets
from .linux_common import require_linux_device, KMS_KEY_PATH, hash_token

linux_mdm_bp = Blueprint("linux_mdm", __name__)
logger = logging.getLogger(__name__)

SERVER_AGENT_VERSION = os.environ.get("FALKO_LATEST_AGENT_VERSION", "0.1.0")

_GRACE_PERIOD_SECONDS = 24 * 3600  # 24 h


@linux_mdm_bp.put("/linux/mdm/<device_id>")
@require_linux_device
def linux_mdm(device_id: str):
    """Käsittelee agentin komentokyselyn (poll) ja edellisen komennon kuittauksen (ack)."""
    # Päivitetään viimeisin aktiivisuustieto (last_seen).
    # ISO 27001 Audit Evidence: Laitteen aktiivisuuden seuranta.
    upsert_linux_device(device_id, {"last_seen": firestore.SERVER_TIMESTAMP})

    # Tarkistetaan rotaatiotarve (Issue #58)
    device = g.device
    token_issued_at = device.get("token_issued_at")
    pending_token_hash = device.get("pending_token_hash")
    rotation_started_at = device.get("rotation_started_at")

    new_token_plaintext = None
    now = datetime.now(timezone.utc)

    # --- Grace period -invalidaatio (#58) ---
    # Jos rotation_started_at on yli 24 h vanha eikä agentti ole kuittannut
    # uutta tokenia, rotaatio on epäonnistunut. Merkitään laite token_rotation_failed
    # -tilaan ja poistetaan pending-token. Cloud Monitoring hälyttää tästä tilasta.
    # HUOM: Varmistetaan, ettei pending_token_hash ole valeluku "rotate"
    if pending_token_hash and pending_token_hash != "rotate" and rotation_started_at:
        if rotation_started_at.tzinfo is None:
            rotation_started_at = rotation_started_at.replace(tzinfo=timezone.utc)
        age = (now - rotation_started_at).total_seconds()
        if age > _GRACE_PERIOD_SECONDS:
            logger.error(
                "Token rotation grace period expired for device %s — marking token_rotation_failed",
                device_id,
            )
            upsert_linux_device(device_id, {
                "pending_token_hash": None,
                "rotation_started_at": None,
                "token_rotation_failed": True,
            })
            device["pending_token_hash"] = None
            device["rotation_started_at"] = None
            pending_token_hash = None
            rotation_started_at = None

    # --- Uuden rotaation käynnistys ---
    # Rotaatio käynnistetään jos se on pyydetty (pending_token_hash == "rotate")
    # tai jos edellinen token on yli 30 päivää vanha eikä uutta rotaatiota ole käynnissä.
    should_rotate = (pending_token_hash == "rotate")
    if not should_rotate and token_issued_at and not pending_token_hash:
        if token_issued_at.tzinfo is None:
            token_issued_at = token_issued_at.replace(tzinfo=timezone.utc)
        if (now - token_issued_at).total_seconds() > 30 * 24 * 3600:
            should_rotate = True

    if should_rotate:
        new_token_plaintext = secrets.token_urlsafe(32)
        upsert_linux_device(device_id, {
            "pending_token_hash": hash_token(new_token_plaintext),
            "rotation_started_at": now,
            "token_rotation_failed": False,
        })
        logger.info("Triggered token rotation for device %s", device_id)

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
            "payload": cmd_dict.get("payload", {}),
            "signature": cmd_dict.get("signature"),
            "key_version": cmd_dict.get("key_version")
        }
        logger.info("Dispatched command %s to device %s", cmd_id, device_id)

    server_meta = {
        "latest_agent_version": SERVER_AGENT_VERSION
    }
    if new_token_plaintext:
        server_meta["new_token"] = new_token_plaintext

    return jsonify({
        "command": command_payload,
        "server_meta": server_meta
    }), 200


@linux_mdm_bp.get("/linux/command-signing-pubkey")
def get_signing_pubkey():
    """Palauttaa KMS-avaimen julkisen avaimen PEM-muodossa agentille."""
    if not KMS_KEY_PATH:
        # Paikallinen mock-avain kehitykseen ja testaukseen
        mock_pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE13f5yW4Tevc4Yx0W7LqLlhf7pI+a\n"
            "0K/V3q6r9M8Z87f4l82s7X9+8x5k+q8e+0g0w8x8d/1o5z8A8y8Y0+3+4w==\n"
            "-----END PUBLIC KEY-----"
        )
        return jsonify({"public_key": mock_pem, "key_version": "mock-version-1"})

    try:
        from google.cloud import kms
        client = kms.KeyManagementServiceClient()
        pubkey = client.get_public_key(request={"name": KMS_KEY_PATH})
        return jsonify({"public_key": pubkey.pem, "key_version": pubkey.name.split('/')[-1]})
    except Exception as e:
        logger.error("Failed to fetch KMS public key: %s", e)
        return jsonify({"error": "Failed to fetch public key"}), 500
