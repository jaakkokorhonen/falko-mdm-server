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


def checkin(token: str, device_id: str) -> bool:
    """Suorittaa laitteen ensi-check-inin palvelimelle käynnistyksen yhteydessä.

    Args:
        token: Bearer-token, luettu _read_token()-funktiolla.
        device_id: Laitteen tunniste, laskettu inventory.collect()['device_id'].

    Returns:
        bool: True jos check-in onnistui, muuten False.
    """
    logger.info("Starting falko-agent check-in...")
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

                # Tarkistetaan agent-päivitystarve
                latest_agent_version = data.get("server_meta", {}).get(
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
                    exec_res = executor.dispatch(cmd_type, cmd_payload)
                    last_result = {"command_id": cmd_id, "status": exec_res}

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
    device_id = inventory.collect()["device_id"]
    if not device_id:
        logger.critical("Cannot start: device_id could not be determined. Exiting.")
        return

    # Suoritetaan käynnistyksen check-in. Jos epäonnistuu, yritetään silti pollausta myöhemmin.
    checkin(token=token, device_id=device_id)

    try:
        poll_loop(token=token, device_id=device_id)
    except KeyboardInterrupt:
        logger.info("Agent process terminated by user.")
    except Exception as e:
        logger.critical("Fatal crash in agent loop: %s", e)


if __name__ == "__main__":
    main()
