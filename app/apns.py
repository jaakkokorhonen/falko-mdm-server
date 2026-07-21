"""Apple Push Notification Service (APNs) -herätys.

Lähettää push-viestin laitteelle jotta se ottaa yhteyttä MDM-serveriin.
Käyttää APNs HTTP/2 -rajapintaa JWT-autentikaatiolla.

Vaatimukset:
  - APNs-avainpari (Team ID + Key ID + .p8-yksityisavain)
  - Ympäristömuuttujat: APNS_TEAM_ID, APNS_KEY_ID, APNS_PRIVATE_KEY (PEM-muodossa)
"""
import os
import time
import logging
import jwt
import requests

logger = logging.getLogger(__name__)

APNS_HOST_PROD = "https://api.push.apple.com"
APNS_HOST_SANDBOX = "https://api.sandbox.push.apple.com"


def _get_apns_token() -> str:
    """Generoi JWT-tokenin APNs-autentikaatiota varten."""
    team_id = os.environ["APNS_TEAM_ID"]
    key_id = os.environ["APNS_KEY_ID"]
    private_key = os.environ["APNS_PRIVATE_KEY"].replace("\\n", "\n")

    payload = {
        "iss": team_id,
        "iat": int(time.time()),
    }
    token = jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={"kid": key_id},
    )
    return token


def send_push(push_token: str, push_magic: str, topic: str, sandbox: bool = False) -> bool:
    """Lähettää MDM push-herätyksen laitteelle.

    Args:
        push_token: Laitteen APNs push token (hex-string)
        push_magic: Laitteen push magic string (lähetetty TokenUpdatessa)
        topic: APNs topic (esim. com.apple.mgmt.External.XXXX)
        sandbox: True = käytä sandbox-ympäristöä (kehitys)

    Returns:
        True jos onnistui, False jos epäonnistui.
    """
    host = APNS_HOST_SANDBOX if sandbox else APNS_HOST_PROD
    url = f"{host}/3/device/{push_token}"

    try:
        token = _get_apns_token()
        headers = {
            "authorization": f"bearer {token}",
            "apns-push-type": "mdm",
            "apns-topic": topic,
        }
        # MDM push payload on aina muotoa {"mdm": "<PushMagic>"}
        body = {"mdm": push_magic}

        resp = requests.post(url, json=body, headers=headers, timeout=10)

        if resp.status_code == 200:
            logger.info("APNs push OK: %s", push_token[:16])
            return True
        else:
            logger.error("APNs push epäonnistui: %s %s", resp.status_code, resp.text)
            return False

    except Exception as exc:
        logger.exception("APNs push poikkeus: %s", exc)
        return False

