"""Apple Push Notification Service (APNs) — MDM-herätys.

Lähettää push-viestin laitteelle jotta se ottaa yhteyden MDM-serveriin.
Käyttää APNs HTTP/2 -rajapintaa JWT-autentikaatiolla.

Vaatimukset (ympäristömuuttujat):
  APNS_TEAM_ID      — Apple Developer Team ID (10 merkkiä, esim. XXXXXXXXXX)
  APNS_KEY_ID       — APNs-avaimen Key ID (10 merkkiä)
  APNS_KEY_SECRET   — Secret Manager -resurssinimi, muoto:
                      projects/PROJECT_ID/secrets/SECRET_NAME/versions/latest
                      (suositeltu, SEC-20)
  APNS_PRIVATE_KEY  — ES256-yksityisavain PEM-muodossa (.p8-tiedoston sisältö)
                      (fallback jos APNS_KEY_SECRET ei ole asetettu — ei suositella
                      tuotannossa, koska env-muuttuja näkyy Cloud Run -konsolissa)
  APNS_SANDBOX      — "true" kehitysympäristölle, "false" tuotantoon (oletus)

Apple APNs -dokumentaatio:
  https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns

Korjaukset (2026-07):
  - SEC-20: APNs-avain luetaan ensisijaisesti Google Cloud Secret Managerista
    (APNS_KEY_SECRET). Ympäristömuuttuja APNS_PRIVATE_KEY toimii fallbackina
    paikalliseen kehitykseen — ei tuotantoon.
  - Review-korjaus: _APNS_PRIVATE_KEY cachetaan moduulitasolla (thread-safe
    double-checked locking) — Secret Manager -kutsu tehdään vain kerran
    sovelluksen käynnistyksessä, ei jokaisen JWT-uudistuksen yhteydessä.
  - Thread-safe token cache (threading.Lock), httpx HTTP/2 -tuki.
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
# HUOM: Apple rajoittaa JWT-tokenin uusimistiheyttä — älä lyhennä tätä arvoa.
_TOKEN_TTL_SECONDS = 50 * 60

# Thread-safe token cache: (token_string, luontiaika_unix)
# Lock estää race conditionin jos Gunicorn pyörii threaded=True tai
# useammalla worker-säikeellä.
_apns_token_cache: tuple[str, float] | None = None
_token_lock = threading.Lock()

# APNs-yksityisavain cachetaan muistiin — Secret Manager -kutsu tehdään
# vain kerran sovelluksen käynnistyksessä (ei joka JWT-uudistuksella).
# Tämä vähentää Secret Manager -API-kutsuja ja estää latenssipiikkejä
# APNs-pushin yhteydessä. Lock estää race conditionin monisäikeisessä
# Gunicorn-ympäristössä.
_APNS_PRIVATE_KEY: str | None = None
_apns_key_lock = threading.Lock()

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
            if _http_client is None:  # double-checked locking — estää useamman instanssin luonnin
                _http_client = httpx.Client(
                    http2=True,
                    timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
                )
    return _http_client


# Graceful shutdown: suljetaan httpx-yhteys prosessin lopussa.
# Ilman tätä yhteys katkeaa raa'asti, mikä voi aiheuttaa virheitä
# Gunicornin graceful shutdown -sekvenssissä.
atexit.register(lambda: _http_client.close() if _http_client else None)


def _load_apns_private_key() -> str:
    """Lataa APNs ES256-yksityisavaimen ensimmäistä kertaa.

    SEC-20: Ensisijainen lähde on Google Cloud Secret Manager (APNS_KEY_SECRET).
    Tämä estää avaimen näkymisen Cloud Run -konsolissa ja prosessin
    ympäristömuuttujissa. Ympäristömuuttuja APNS_PRIVATE_KEY toimii
    fallbackina paikalliseen kehitykseen.

    Tätä funktiota kutsutaan VAIN _get_apns_private_key():n kautta, joka
    cacheaa tuloksen — älä kutsu suoraan.

    Latausjärjestys:
      1. APNS_KEY_SECRET  → Secret Manager (suositeltu tuotantoon)
      2. APNS_PRIVATE_KEY → ympäristömuuttuja (kehitys/fallback)

    Returns:
        APNs-yksityisavain PEM-muodossa.

    Raises:
        RuntimeError: Jos kumpaakaan lähdettä ei ole asetettu tai molemmat
                      epäonnistuvat.
    """
    secret_resource = os.environ.get("APNS_KEY_SECRET", "").strip()
    if secret_resource:
        try:
            from google.cloud import secretmanager  # type: ignore[import]
            client = secretmanager.SecretManagerServiceClient()
            response = client.access_secret_version(request={"name": secret_resource})
            logger.info("APNs-avain ladattu Secret Managerista: %s", secret_resource)
            return response.payload.data.decode("utf-8")
        except Exception as exc:
            logger.error(
                "Secret Manager -luku epäonnistui (%s): %s — kokeillaan APNS_PRIVATE_KEY-fallbackia",
                secret_resource, exc
            )

    # Fallback: ympäristömuuttuja (kehitys / ei-tuotanto)
    # HUOM: Ympäristömuuttujat näkyvät Cloud Run -konsolissa ja
    # /proc/self/environ -tiedostossa — älä käytä tuotannossa.
    private_key_env = os.environ.get("APNS_PRIVATE_KEY", "").strip()
    if private_key_env:
        logger.warning(
            "APNs-avain ladattu APNS_PRIVATE_KEY-ympäristömuuttujasta. "
            "Tuotannossa käytä APNS_KEY_SECRET (Secret Manager). "
            "Ref: issue SEC-20."
        )
        # \n on saatettu tallentaa literaalisena merkkijonona ympäristömuuttujaan —
        # korvataan oikeiksi rivinvaihdoiksi PEM-jäsentämistä varten.
        return private_key_env.replace("\\n", "\n")

    raise RuntimeError(
        "APNs-yksityisavain puuttuu. Aseta APNS_KEY_SECRET (Secret Manager) "
        "tai APNS_PRIVATE_KEY (kehitys). Ref: issue SEC-20."
    )


def _get_apns_private_key() -> str:
    """Palauttaa APNs-yksityisavaimen, lataa ja cacheaa sen tarvittaessa.

    Thread-safe double-checked locking: Secret Manager -kutsu tehdään
    vain kerran sovelluksen käynnistyksessä eikä joka JWT-uudistuksella.
    Tämä estää latenssipiikkejä APNs-pushin yhteydessä.

    Returns:
        APNs-yksityisavain PEM-muodossa.
    """
    global _APNS_PRIVATE_KEY
    # Fast-path ilman lukkoa: avain on jo ladattu
    if _APNS_PRIVATE_KEY is not None:
        return _APNS_PRIVATE_KEY
    with _apns_key_lock:
        # Tarkista uudelleen lukon sisällä — toinen säie on saattanut ladata avaimen
        if _APNS_PRIVATE_KEY is None:
            _APNS_PRIVATE_KEY = _load_apns_private_key()
    return _APNS_PRIVATE_KEY


def _get_apns_token() -> str:
    """Palauttaa voimassa olevan APNs JWT-tokenin, generoi tarvittaessa.

    Thread-safe: käyttää threading.Lock() -lukkoa jotta usea säie ei generoi
    tokenia samanaikaisesti (race condition → APNs TooManyProviderTokenUpdates).

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
        # _get_apns_private_key() on thread-safe ja cacheaa avaimen —
        # Secret Manager -kutsu tapahtuu vain kerran käynnistyksen yhteydessä.
        private_key = _get_apns_private_key()

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
