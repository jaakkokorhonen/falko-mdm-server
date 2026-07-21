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

Parannus (2026-07): Thread-safe token cache (threading.Lock), httpx HTTP/2 -tuki.
  Ref: Dalton & Gentry (2022) "Push Notification Latency at Scale", ACM IMC.
  Ref: https://developer.apple.com/forums/thread/714817 (APNs HTTP/2 pakollisuus 2025+)
"""
import os
import time
import logging
import threading
import atexit
import jwt
import httpx

logger = logging.getLogger(__name__)

APNS_HOST_PROD    = "https://api.push.apple.com"
APNS_HOST_SANDBOX = "https://api.sandbox.push.apple.com"

# APNs JWT-token on voimassa 60 minuuttia (Apple-raja).
# Uudistetaan 50 min kohdalla — 10 min marginaali ennen Apple-rajaa.
# NOTE: Apple rajoittaa JWT-tokenin uusimistiheyttä — älä lyhennä tätä arvoa.
_TOKEN_TTL_SECONDS = 50 * 60

# Thread-safe token cache: (token_string, luontiaika_unix)
# Lock estää race conditionin jos Gunicorn pyörii threaded=True tai
# useammalla worker-säikeellä.
_apns_token_cache: tuple[str, float] | None = None
_token_lock = threading.Lock()

# Pitkäikäinen httpx-asiakas HTTP/2:lla — yhteys pysyy auki APNs:ään.
# Apple suosittelee persistenttiä HTTP/2-yhteyttä: se vähentää TLS-handshake-
# latenssia ja välttää OS-tason TCP-pistoke-exhaustionin.
# Ref: https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns
_http_client: httpx.Client | None = None
_http_lock = threading.Lock()


def _get_http_client() -> httpx.Client:
    """Palauttaa pitkäikäisen httpx HTTP/2 -asiakkaan, luo tarvittaessa.

    httpx tukee HTTP/2:ta suoraan (http2=True). Yhteyspoolit pysyvät auki
    jolloin jokainen push ei vaadi uutta TLS-kättelyä APNs:ään.

    Returns:
        Alustettu httpx.Client-instanssi.
    """
    global _http_client
    if _http_client is None:
        with _http_lock:
            if _http_client is None:  # double-checked locking
                _http_client = httpx.Client(
                    http2=True,
                    timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
                )
    return _http_client


# Graceful shutdown: suljetaan httpx-yhteys prosessin lopussa.
# Ilman tätä yhteys katkeaa raa'asti, mikä voi aiheuttaa virheitä
# Gunicornin graceful shutdown -sekvenssissä.
atexit.register(lambda: _http_client.close() if _http_client else None)


def _get_apns_token() -> str:
    """Palauttaa voimassa olevan APNs JWT-tokenin, generoi tarvittaessa.

    Thread-safe: käyttää threading.Lock() -lukkoa jotta usea säie ei generoi
    tokenia samanaikaisesti (race condition -> APNs TooManyProviderTokenUpdates).

    Returns:
        JWT-token string APNs-pyyntöjä varten.
    """
    global _apns_token_cache
    now = time.time()
    # Fast-path ilman lukkoa: cachettu token on vielä voimassa
    if _apns_token_cache and now - _apns_token_cache[1] < _TOKEN_TTL_SECONDS:
        return _apns_token_cache[0]

    with _token_lock:
        # Tarkista uudelleen lukon sisällä (double-checked locking)
        if _apns_token_cache and now - _apns_token_cache[1] < _TOKEN_TTL_SECONDS:
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
        logger.debug("APNs JWT-token uudistettu")
        return token


def send_push(push_token: str, push_magic: str, topic: str, sandbox: bool = False) -> bool:
    """Lähettää MDM push-herätyksen laitteelle APNs:n kautta HTTP/2:lla.

    Herätys ei sisällä varsinaista MDM-komentoa — se vain käskee
    laitetta ottamaan yhteyden MDM-serveriin (PUT /mdm).

    Args:
        push_token: Laitteen APNs push token hex-stringinä (saatu TokenUpdate-viestissä).
        push_magic: Laitteen push magic string (saatu TokenUpdate-viestissä).
        topic:      APNs-aihe, esim. "com.apple.mgmt.External.XXXX" (saatu TokenUpdate-viestissä).
        sandbox:    True = APNs sandbox (kehitys), False = tuotanto (oletus).

    Returns:
        True jos APNs palautti HTTP 200, False kaikissa virhetilanteissa.
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
        # Apple MDM spec: push payload on AINA juuri tässä muodossa — ei muita kenttiä.
        # Laitteen MDM-agentti tunnistaa sen PushMagic-arvosta ja ottaa yhteyttä serveriin.
        body = {"mdm": push_magic}

        client = _get_http_client()
        resp = client.post(url, json=body, headers=headers)

        if resp.status_code == 200:
            # Logitetaan vain token-alku — koko token on arkaluonteinen tieto
            logger.info("APNs push OK: %s", push_token[:16])
            return True

        logger.error("APNs push epäonnistui: %s %s", resp.status_code, resp.text)
        return False

    except Exception as exc:
        logger.exception("APNs push poikkeus: %s", exc)
        return False
