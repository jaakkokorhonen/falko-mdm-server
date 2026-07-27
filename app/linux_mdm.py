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
from .linux_common import require_linux_device

linux_mdm_bp = Blueprint("linux_mdm", __name__)
logger = logging.getLogger(__name__)

SERVER_AGENT_VERSION = os.environ.get("FALKO_LATEST_AGENT_VERSION", "0.1.0")


@linux_mdm_bp.put("/linux/mdm/<device_id>")
@require_linux_device
def linux_mdm(device_id: str):
    """Käsittelee agentin komentokyselyn (poll) ja edellisen komennon kuittauksen (ack)."""
    # Päivitetään viimeisin aktiivisuustieto (last_seen).
    # ISO 27001 Audit Evidence: Laitteen aktiivisuuden seuranta.
    # Käytetään Firestore SERVER_TIMESTAMP -muuttujaa luotettavan palvelinpohjaisen aikaleiman saamiseksi.
    upsert_linux_device(device_id, {"last_seen": firestore.SERVER_TIMESTAMP})

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
            "latest_agent_version": SERVER_AGENT_VERSION
        }
    }), 200
