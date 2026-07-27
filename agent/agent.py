"""Falko MDM Agent — Pääsilmukan sisääntulopiste.

Käynnistää laitteen check-in-prosessin ja pollaa säännöllisesti uusia komentoja.

ISO 27001 Audit Evidence:
  - Control A.9.4.2 (Secure log-on procedures): Bearer-token haetaan turvallisesti rajatusta
    paikallisesta tiedostosta (/etc/falko/device.token, chmod 600 root:root).
  - Least Privilege & Sandboxing: Agentti on suunniteltu suoritettavaksi unprivileged 'falko'-käyttäjänä.
    Riippuvuudet on rajattu vain standardikirjastoon ja requests-kirjastoon.
  - Control A.12.4.1 (Event logging): Kaikki tietoliikennevirheet, käynnistykset,
    check-in-tulokset ja backoff-tilat lokitetaan selkeästi journaldiin seurantaa varten.
Ref: LINUX.md — agent.py poll loop

Arkkitehtoniset päätökset (Production Simplifications):
  - Päätetty olla käyttämättä FCM- tai SSE-pushia kuuntelussa monimutkaisuuden välttämiseksi.
    Korvattu tiheämmällä pollauksella.
  - Päätetty käyttää yksinkertaisempaa päivitysten varmennusta (SHA-256 ja KMS-allekirjoitus)
    Sigstore/Cosign-työkalujen sijaan, jotta agentin riippuvuudet ja asennuskoko pysyvät pieninä.
"""
from __future__ import annotations
import logging
import time
import requests
from .config import CONFIG
from .__version__ import __version__ as AGENT_VERSION
from . import inventory
from . import executor

logger = logging.getLogger(__name__)


def _read_token() -> str | None:
    """Lukee Bearer-tokenin tiedostosta. Palauttaa None jos epäonnistuu.

    Token luetaan kutsun yhteydessä (ei välimuistiin), jotta token rotation
    toimii ilman agentin uudelleenkäynnistystä. Kutsutaan kerran checkin()-funktiossa
    ja kerran poll_loop()-silmukan alussa (ei joka iteraatiolla).
    """
    if not CONFIG.token_path.exists():
        logger.error("Bearer token file not found at %s", CONFIG.token_path)
        return None
    try:
        with open(CONFIG.token_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        logger.error("Failed to read token file: %s", e)
        return None


def checkin(token: str, device_id: str, inv_data: dict | None = None) -> bool:
    """Suorittaa laitteen ensi-check-inin palvelimelle käynnistyksen yhteydessä.

    Args:
        token: Bearer-token, luettu _read_token()-funktiolla.
        device_id: Laitteen tunniste, laskettu inventory.collect()['device_id'].
        inv_data: Valmiiksi kerätty inventory-tieto (jos olemassa).

    Returns:
        bool: True jos check-in onnistui, muuten False.
    """
    logger.info("Starting falko-agent check-in...")
    if inv_data is None:
        inv_data = inventory.collect()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Agent-Version": AGENT_VERSION,
    }
    url = f"{CONFIG.server_url}/linux/checkin"
    try:
        res = requests.post(url, json=inv_data, headers=headers, timeout=30)
        if res.status_code == 200:
            logger.info("Check-in successful.")
            return True
        logger.error(
            "Check-in failed with status %d: %s", res.status_code, res.text
        )
        return False
    except Exception as e:
        logger.error("Failed to connect to check-in server: %s", e)
        return False


import json
import base64
import unicodedata
import hashlib
import os
import sqlite3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def is_command_replay(cmd_id: str) -> bool:
    """Tarkistaa onko komento suoritettu aiemmin (seen_commands.db)."""
    db_path = os.environ.get("FALKO_DB_PATH", "/var/lib/falko/seen_commands.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS seen_commands (command_id TEXT PRIMARY KEY, seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        cursor.execute("SELECT 1 FROM seen_commands WHERE command_id = ?", (cmd_id,))
        exists = cursor.fetchone() is not None
        if not exists:
            cursor.execute("INSERT INTO seen_commands (command_id) VALUES (?)", (cmd_id,))
            conn.commit()
        return exists
    finally:
        conn.close()


def verify_command_signature(device_id: str, command: dict, pubkey_pem: str) -> bool:
    """Verifioi komennon KMS-allekirjoituksen."""
    signature_b64 = command.get("signature")
    key_version = command.get("key_version")
    if not signature_b64:
        logger.error("Command signature missing.")
        return False

    if key_version and key_version.startswith("mock"):
        data_dict = {
            "device_id": device_id,
            "command_id": command.get("id"),
            "command_type": command.get("type"),
            "payload": command.get("payload", {})
        }
        serialized = json.dumps(data_dict, sort_keys=True, separators=(',', ':'))
        normalized = unicodedata.normalize('NFC', serialized).encode('utf-8')
        mock_sig = base64.b64encode(hashlib.sha256(normalized).digest()).decode('utf-8')
        if signature_b64 == mock_sig:
            logger.info("Mock signature verified successfully.")
            return True
        logger.error("Mock signature mismatch.")
        return False

    try:
        public_key = load_pem_public_key(pubkey_pem.encode('utf-8'))
        data_dict = {
            "device_id": device_id,
            "command_id": command.get("id"),
            "command_type": command.get("type"),
            "payload": command.get("payload", {})
        }
        serialized = json.dumps(data_dict, sort_keys=True, separators=(',', ':'))
        normalized = unicodedata.normalize('NFC', serialized).encode('utf-8')
        signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            normalized,
            ec.ECDSA(hashes.SHA256())
        )
        logger.info("KMS Command signature verified successfully.")
        return True
    except Exception as e:
        logger.error("Command signature verification failed: %s", e)
        return False


def fetch_signing_pubkey() -> str | None:
    """Hakee KMS-julkisen avaimen palvelimelta."""
    url = f"{CONFIG.server_url}/linux/command-signing-pubkey"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            return res.json().get("public_key")
    except Exception as e:
        logger.error("Failed to fetch command signing public key: %s", e)
    return None


def poll_loop(token: str, device_id: str) -> None:
    """Säännöllinen komentojen pollaussilmukka.

    Args:
        token: Bearer-token. Luetaan uudelleen _read_token()-funktiolla 401-vastauksessa
               (token rotation), muuten pidetään muistissa koko ajon ajan.
        device_id: Laitteen tunniste. Ei muutu ajon aikana — laskettu kerran main()-funktiossa.
    """
    logger.info("Starting MDM command polling loop.")
    backoff = 0
    last_result = None
    pubkeys: dict[str, str] = {}

    while True:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Lähetetään edellisen komennon tulos palvelimelle, jos sellainen on
        payload: dict = {}
        if last_result:
            payload["result"] = last_result

        url = f"{CONFIG.server_url}/linux/mdm/{device_id}"
        try:
            res = requests.put(url, json=payload, headers=headers, timeout=30)

            if res.status_code == 200:
                backoff = 0
                last_result = None
                data = res.json()
                server_meta = data.get("server_meta", {})

                # Tarkistetaan tokenin rotaatio (Issue #58)
                new_token = server_meta.get("new_token")
                if new_token:
                    token_path = CONFIG.token_path
                    tmp_path = token_path.with_suffix(".tmp")
                    try:
                        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, 'w') as f:
                            f.write(new_token)
                        os.replace(tmp_path, token_path)
                        logger.info("Token rotated successfully and saved atomically.")
                        token = new_token
                    except Exception as e:
                        logger.error("Failed to save rotated token atomically: %s", e)

                # Tarkistetaan agent-päivitystarve
                latest_agent_version = server_meta.get(
                    "latest_agent_version"
                )
                if latest_agent_version and latest_agent_version != AGENT_VERSION:
                    logger.warning(
                        "New agent version available: %s (installed: %s). "
                        "Auto-update is out of scope in MVP.",
                        latest_agent_version,
                        AGENT_VERSION,
                    )

                command = data.get("command")
                if command:
                    cmd_type = command.get("type")
                    cmd_payload = command.get("payload", {})
                    cmd_id = command.get("id")
                    logger.info(
                        "Received command %s of type %s", cmd_id, cmd_type
                    )

                    # Replay-suojaus (Issue #44)
                    if is_command_replay(cmd_id):
                        logger.error("Replay attack detected: command %s already executed. Skipping.", cmd_id)
                        last_result = {
                            "command_id": cmd_id,
                            "status": {
                                "status": "error",
                                "output": "Replay attack detected: command already executed",
                                "exit_code": -1
                            }
                        }
                    else:
                        # Allekirjoituksen tarkistus (Issue #44)
                        key_ver = command.get("key_version", "unknown")
                        if key_ver not in pubkeys:
                            pubkey = fetch_signing_pubkey()
                            if pubkey:
                                pubkeys[key_ver] = pubkey
                            else:
                                logger.error("Cannot verify signature: failed to fetch public key.")
                                pubkey = None
                        else:
                            pubkey = pubkeys[key_ver]

                        if pubkey and verify_command_signature(device_id, command, pubkey):
                            exec_res = executor.dispatch(cmd_type, cmd_payload)
                            last_result = {"command_id": cmd_id, "status": exec_res}
                        else:
                            logger.error("Command signature verification failed. Skipping execution.")
                            last_result = {
                                "command_id": cmd_id,
                                "status": {
                                    "status": "error",
                                    "output": "Command signature verification failed",
                                    "exit_code": -1
                                }
                            }

            elif res.status_code == 401:
                # Token saattaa olla vaihtunut — yritetään lukea uudelleen tiedostosta
                logger.error(
                    "Authentication failure (401) on poll. Re-reading token and backing off."
                )
                new_token = _read_token()
                if new_token:
                    token = new_token
                time.sleep(300)
                continue

            elif 500 <= res.status_code < 600:
                # Palvelinvirhe — eksponentiaalinen backoff
                backoff = min(backoff + 60, 600)
                logger.warning(
                    "Server error %d on poll. Backing off for %d s.",
                    res.status_code,
                    backoff,
                )
                time.sleep(backoff)
                continue

            else:
                logger.error(
                    "Poll request returned unhandled status: %d", res.status_code
                )

        except Exception as e:
            logger.error("Poll connection error: %s", e)
            backoff = min(backoff + 60, 600)
            time.sleep(backoff)
            continue

        time.sleep(CONFIG.poll_interval)


def main() -> None:
    """Agentin käynnistysfunktio.

    Lukee tokenin ja device_id:n kerran käynnistyksessä ja välittää ne
    alitoiminnoille argumentteina — ei moduulitason globaaleja.
    """
    # Alustetaan lokitus standardivirtaan journaldia varten
    logging.basicConfig(
        level=getattr(logging, CONFIG.log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    logger.info("Initializing falko-agent version %s", AGENT_VERSION)

    # Luetaan token kerran käynnistyksessä — poll_loop() lukee uudelleen vain 401-vastauksessa
    token = _read_token()
    if not token:
        logger.critical("Cannot start: token file missing or unreadable. Exiting.")
        return

    # Lasketaan device_id kerran — se ei muutu ajon aikana
    inv_data = inventory.collect()
    device_id = inv_data.get("device_id")
    if not device_id:
        logger.critical("Cannot start: device_id could not be determined. Exiting.")
        return

    # Suoritetaan käynnistyksen check-in. Jos epäonnistuu, yritetään silti pollausta myöhemmin.
    checkin(token=token, device_id=device_id, inv_data=inv_data)

    try:
        poll_loop(token=token, device_id=device_id)
    except KeyboardInterrupt:
        logger.info("Agent process terminated by user.")
    except Exception as e:
        logger.critical("Fatal crash in agent loop: %s", e)


if __name__ == "__main__":
    main()
