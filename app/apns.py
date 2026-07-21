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

APNS_HOST_PROD    = "https://api.push.apple.com"
APNS_HOST_SANDBOX = "https://api.sandbox.push.apple.com"

# APNs JWT-token on voimassa 60 minuuttia (Apple-raja).
# Uudistetaan ennen vanhentumista pienellä marginaalilla.
# NOTE: Apple rajoittaa JWT-tokenin uusimistiheyttä — älä lyhennä tätä arvoa.
_TOKEN_TTL_SECONDS = 50 * 60  # 50 min, 10 min marginaali ennen Apple-rajaa

# Moduulitason cache: (token_string, luontihetki).
# Vältää turhan ES256-allekirjoitusoperaation jokaisella push-pyynnöllä ja
# estää APNs-puolen rate limiting -ongelman tiheässä push-liikenteessä.
# FIXME: Tämä ei ole thread-safe. Jos Flask pyörii monisäikeisesti (threaded=True
# tai gunicorn workers), lisää threading.Lock() tokenin uusimiseen.
_cached_token: str | None = None
_cached_token_at: float = 0.0


def _get_apns_token() -> str:
    """Palauttaa voimassa olevan APNs JWT-tokenin; uudistaa tarvittaessa.

    Käyttää moduulitason cachea välttääkseen turhat ES256-allekirjoitukset.
    Token uudistetaan automaattisesti 50 minuutin välein.

    Returns:
        Voimassa oleva JWT-token APNs-autentikaatiota varten.
    """
    global _cached_token, _cached_token_at

    now = time.time()
    # Tarkista cache: jos token on tuore (alle TTL), palautetaan se suoraan
    if _cached_token and (now - _cached_token_at) < _TOKEN_TTL_SECONDS:
        return _cached_token

    # Generoidaan uusi token
    team_id = os.environ["APNS_TEAM_ID"]
    key_id  = os.environ["APNS_KEY_ID"]
    # Cloud Run tallentaa .p8-avaimen \\n-escaped muodossa Secret Managerissa
    private_key = os.environ["APNS_PRIVATE_KEY"].replace("\\n", "\n")

    payload = {
        "iss": team_id,
        "iat": int(now),
    }
    token = jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={"kid": key_id},
    )

    _cached_token    = token
    _cached_token_at = now
    logger.debug("APNs JWT-token uudistettu")
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
    url  = f"{host}/3/device/{push_token}"

    try:
        token = _get_apns_token()
        headers = {
            "authorization": f"bearer {token}",
            "apns-push-type": "mdm",
            "apns-topic": topic,
        }
        # MDM push payload on aina muotoa {"mdm": "<PushMagic>"} — Apple MDM spec
        body = {"mdm": push_magic}

        resp = requests.post(url, json=body, headers=headers, timeout=10)

        if resp.status_code == 200:
            # Logitetaan vain tokenin alku tietoturvasyistä
            logger.info("APNs push OK: %s...", push_token[:16])
            return True
        else:
            logger.error("APNs push epäonnistui: %s %s", resp.status_code, resp.text)
            return False

    except Exception as exc:
        logger.exception("APNs push poikkeus: %s", exc)
        return False
