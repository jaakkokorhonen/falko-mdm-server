"""Apple Push Notification Service (APNs) — MDM-herätys.

Lähettää push-viestin laitteelle jotta se ottaa yhteyden MDM-serveriin.
Käyttää APNs HTTP/2 -rajapintaa JWT-autentikaatiolla.

Vaatimukset (ympäristömuuttujat):
  APNS_TEAM_ID      — Apple Developer Team ID (10 merkkiä, esim. XXXXXXXXXX)
  APNS_KEY_ID       — APNs-avaimen Key ID (10 merkkiä)
  APNS_PRIVATE_KEY  — ES256-yksityisavain PEM-muodossa (.p8-tiedoston sisältö)
  APNS_SANDBOX      — "true" kehitysympäristölle, "false" tuotantoon (oletus)

Apple APNs -dokumentaatio:
  https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns
"""
import os
import time
import logging
import jwt
import requests

logger = logging.getLogger(__name__)

APNS_HOST_PROD    = "https://api.push.apple.com"
APNS_HOST_SANDBOX = "https://api.sandbox.push.apple.com"

# Moduulitason token-cache: (token_string, luontiaika_unix)
# Apple rajoittaa JWT-tokenin uusimistiheyttä — sama token kelpää 60 min.
# Älä muuta 3000 sekunnin raja-arvoa ilman hyvää syytä.
_apns_token_cache: tuple[str, float] | None = None


def _get_apns_token() -> str:
    """Palauttaa voimassa olevan APNs JWT-tokenin, generoi tarvittaessa.

    Cachetää tokenin 50 minuutiksi (3000 s) Apple-rajoitusten takia.
    Token on voimassa 60 minuuttia, mutta uusitaan 10 min ennen vanhenemista
    puskurin varmistamiseksi.

    Returns:
        JWT-token string APNs-pyyntöjä varten.
    """
    global _apns_token_cache
    now = time.time()
    # Käytä cachettua tokenia jos se on alle 50 minuuttia vanha
    if _apns_token_cache and now - _apns_token_cache[1] < 3000:
        return _apns_token_cache[0]

    team_id     = os.environ["APNS_TEAM_ID"]
    key_id      = os.environ["APNS_KEY_ID"]
    # \n on tallennettu literaalisena merkkijonona ympäristömuuttujaan —
    # korvataan oikeiksi rivinvaihdoiksi PEM-jäsentämistä varten
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
    _apns_token_cache = (token, now)
    return token


def send_push(push_token: str, push_magic: str, topic: str, sandbox: bool = False) -> bool:
    """Lähettää MDM push-herätyksen laitteelle APNs:n kautta.

    Herätys ei sisällä varsinaista MDM-komentoa — se vain käskee
    laitetta ottamaan yhteyden MDM-serveriin (PUT /mdm).

    Args:
        push_token: Laitteen APNs push token hex-stringinä (saatu TokenUpdate-viestissä).
        push_magic: Laitteen push magic string (saatu TokenUpdate-viestissä).
        topic:      APNs-aihe, esim. "com.apple.mgmt.External.XXXX" (saatu TokenUpdate-viestissä).
        sandbox:    True = APNs sandbox (kehitys), False = tuotanto (oletus).

    Returns:
        True jos APNs palautti HTTP 200, False kaikissa virhetilanteissa.

    NOTE: Käyttää requests-kirjastoa (HTTP/1.1). Apple suosittelee HTTP/2:ta.
    TODO(jaakko): Korvaa httpx[http2]-kirjastolla parempaa protokollatukea varten.
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
            # Logitetaan vain token-alku — koko token on arkaluonteinen tieto
            logger.info("APNs push OK: %s", push_token[:16])
            return True

        logger.error("APNs push epäonnistui: %s %s", resp.status_code, resp.text)
        return False

    except Exception as exc:
        logger.exception("APNs push poikkeus: %s", exc)
        return False
