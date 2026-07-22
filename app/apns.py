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
_TOKEN_TTL_SECONDS = 50 * 60

# Thread-safe token cache: (token_string, luontiaika_unix)
_apns_token_cache: tuple[str, float] | None = None
_token_lock = threading.Lock()

# Pitkäikäinen httpx-asiakas HTTP/2:lla
_http_client: httpx.Client | None = None
_http_lock = threading.Lock()


def _get_http_client() -> httpx.Client:
    """Palauttaa pitkäikäisen httpx HTTP/2 -asiakkaan, luo tarvittaessa."""
    global _http_client
    if _http_client is None:
        with _http_lock:
            if _http_client is None:
                _http_client = httpx.Client(
                    http2=True,
                    timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
                )
    return _http_client


atexit.register(lambda: _http_client.close() if _http_client else None)


def _load_apns_private_key() -> str:
    """Lataa APNs ES256-yksityisavaimen.

    SEC-20: Ensisijainen lähde on Google Cloud Secret Manager (APNS_KEY_SECRET).
    Tämä estää avaimen näkymisen Cloud Run -konsolissa ja prosessin
    ympäristömuuttujissa. Ympäristömuuttuja APNS_PRIVATE_KEY toimii
    fallbackina paikalliseen kehitykseen.

    Latausjärjestys:
      1. APNS_KEY_SECRET  → Secret Manager (suositeltu tuotantoon)
      2. APNS_PRIVATE_KEY → ympäristömuuttuja (kehitys/fallback)

    Returns:
        APNs-yksityisavain PEM-muodossa.

    Raises:
        RuntimeError: Jos kumpaakaan lähdettä ei ole asetettu.
    """
    secret_resource = os.environ.get("APNS_KEY_SECRET", "").strip()
    if secret_resource:
        try:
            from google.cloud import secretmanager  # type: ignore[import]
            client = secretmanager.SecretManagerServiceClient()
            response = client.access_secret_version(request={"name": secret_resource})
            logger.debug("APNs-avain ladattu Secret Managerista: %s", secret_resource)
            return response.payload.data.decode("utf-8")
        except Exception as exc:
            logger.error(
                "Secret Manager -luku epäonnistui (%s): %s — kokeillaan APNS_PRIVATE_KEY-fallbackia",
                secret_resource, exc
            )

    # Fallback: ympäristömuuttuja (kehitys / ei-tuotanto)
    private_key_env = os.environ.get("APNS_PRIVATE_KEY", "").strip()
    if private_key_env:
        logger.warning(
            "APNs-avain ladattu APNS_PRIVATE_KEY-ympäristömuuttujasta. "
            "Tuotannossa käytä APNS_KEY_SECRET (Secret Manager). "
            "Ref: issue SEC-20."
        )
        return private_key_env.replace("\\n", "\n")

    raise RuntimeError(
        "APNs-yksityisavain puuttuu. Aseta APNS_KEY_SECRET (Secret Manager) "
        "tai APNS_PRIVATE_KEY (kehitys). Ref: issue SEC-20."
    )


def _get_apns_token() -> str:
    """Palauttaa voimassa olevan APNs JWT-tokenin, generoi tarvittaessa.

    Thread-safe: käyttää threading.Lock() -lukkoa.
    """
    global _apns_token_cache
    now = time.time()
    if _apns_token_cache and now - _apns_token_cache[1] < _TOKEN_TTL_SECONDS:
        return _apns_token_cache[0]

    with _token_lock:
        if _apns_token_cache and now - _apns_token_cache[1] < _TOKEN_TTL_SECONDS:
            return _apns_token_cache[0]

        team_id  = os.environ["APNS_TEAM_ID"]
        key_id   = os.environ["APNS_KEY_ID"]
        private_key = _load_apns_private_key()

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
    """Lähettää MDM push-herätyksen laitteelle APNs:n kautta HTTP/2:lla."""
    host = APNS_HOST_SANDBOX if sandbox else APNS_HOST_PROD
    url  = f"{host}/3/device/{push_token}"

    try:
        token = _get_apns_token()
        headers = {
            "authorization": f"bearer {token}",
            "apns-push-type": "mdm",
            "apns-topic": topic,
        }
        body = {"mdm": push_magic}

        client = _get_http_client()
        resp = client.post(url, json=body, headers=headers)

        if resp.status_code == 200:
            logger.info("APNs push OK: %s", push_token[:16])
            return True

        logger.error("APNs push epäonnistui: %s %s", resp.status_code, resp.text)
        return False

    except Exception as exc:
        logger.exception("APNs push poikkeus: %s", exc)
        return False
