"""Admin API — laitelistaus ja komentojen lähettäminen.

Endpointit:
  GET  /admin/devices              — lista kaikista laitteista
  GET  /admin/devices/<udid>        — yksittäisen laitteen tiedot
  POST /admin/devices/<udid>/command — lisää komento laitteen jonoon
  POST /admin/devices/<udid>/push   — lähetä APNs herätys

Autentikaatio: Google Identity-Aware Proxy (IAP).
  - Selain: IAP-cookie + X-Goog-Authenticated-User-Email + X-Goog-IAP-JWT-Assertion
  - Skriptit: Authorization: Bearer <ADMIN_TOKEN> (env-muuttuja ADMIN_TOKEN)

Security note: Pelkkä header-tarkistus ei riitä — JWT-assertion verifioidaan
kryptografisesti Googlen julkisilla avaimilla (google-auth). Muutoin hyökkääjä
voi spoofattaa X-Goog-Authenticated-User-Email -otsakkeen ohittaen IAP:n.
Ref: https://cloud.google.com/iap/docs/signed-headers-howto
"""
import os
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import Blueprint, request, jsonify

# google-auth validoi IAP JWT-assertion kryptografisesti Googlen julkisia avaimia vasten.
# Tämä on pakollinen askel tuotannossa: ilman tätä verkkokerrokseen ennen Cloud Runia
# pääsevä hyökkääjä voi spoofattaa X-Goog-Authenticated-User-Email -otsakkeen.
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from .db import list_devices, get_device, enqueue_command
from .apns import send_push

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
logger = logging.getLogger(__name__)

# IAP JWT-assertion verifiointiin tarvitaan audience-arvo, joka on
# muotoa /projects/<project_number>/apps/<project_id>.
# Aseta Cloud Runin ympäristömuuttujaan IAP_AUDIENCE.
# Löydät arvon: gcloud iap web describe --resource-type=backend-services
IAP_AUDIENCE = os.environ.get("IAP_AUDIENCE", "")

# Fallback-token skriptikäyttöön (CI, curl-testit).
# Jos ADMIN_TOKEN on asetettu, se hyväksytään IAP-tarkistuksen ohella.
# NOTE: Aseta vahva (>= 32 merkkiä) satunnainen arvo, esim:
#   openssl rand -base64 32 | gcloud secrets create falko-admin-token --data-file=-
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


def _verify_iap_jwt(iap_jwt: str) -> str | None:
    """Verifioi Google IAP JWT-assertion ja palauttaa sähköpostin tai None.

    Verifioi allekirjoituksen Googlen julkisilla avaimilla (ES256).
    Palauttaa sähköpostin muodossa 'user@falko.fi',
    tai None jos JWT on virheellinen tai vanhentunut.

    Args:
        iap_jwt: X-Goog-IAP-JWT-Assertion -otsakkeen arvo.

    Returns:
        Käyttäjän sähköpostiosoite tai None.
    """
    if not IAP_AUDIENCE:
        # NOTE: IAP_AUDIENCE puuttuu — JWT-assertion verifiointia ei voida tehdä.
        # Tuotannossa tämä on virheellinen tila; local-kehityksessä hyväksyttävä.
        logger.warning("IAP_AUDIENCE ei ole asetettu — JWT-assertion verifiointia ei tehdä")
        return None
    try:
        info = id_token.verify_token(
            iap_jwt,
            google_requests.Request(),
            audience=IAP_AUDIENCE,
            certs_url="https://www.gstatic.com/iap/verify/public_key",
        )
        # JWT:n email-kenttä on muotoa "user@falko.fi"
        return info.get("email")
    except Exception as exc:
        logger.warning("IAP JWT-assertion verifiointi epäonnistui: %s", exc)
        return None


def require_auth(f):
    """Decorator: autentikoi pyyntö IAP JWT:llä tai ADMIN_TOKEN-fallbackilla.

    Hyväksyntäjärjestys:
      1. IAP: verifioi X-Goog-IAP-JWT-Assertion kryptografisesti, tarkista @falko.fi-domain
      2. Bearer token: Authorization: Bearer <ADMIN_TOKEN> (skriptikäyttö)

    Jos kumpikaan ei onnistu, palautetaan 401 tai 403.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # --- Vaihtoehto 1: IAP JWT-assertion (selainpyynnöt) ---
        iap_jwt = request.headers.get("X-Goog-IAP-JWT-Assertion", "")
        if iap_jwt:
            email = _verify_iap_jwt(iap_jwt)
            if email is None:
                return jsonify({"error": "IAP JWT-assertion verifiointi epäonnistui"}), 401
            if not email.endswith("@falko.fi"):
                return jsonify({"error": "Käyttöoikeus evätty (vain falko.fi-käyttäjille)"}), 403
            return f(*args, **kwargs)

        # --- Vaihtoehto 2: Bearer-token fallback (skriptit, CI) ---
        # NOTE: ADMIN_TOKEN on oltava asetettu; tyhjä arvo hylätään aina.
        auth_header = request.headers.get("Authorization", "")
        if ADMIN_TOKEN and auth_header == f"Bearer {ADMIN_TOKEN}":
            return f(*args, **kwargs)

        # Kumpaakaan hyväksyttyä autentikaatiotapaa ei löydy.
        return jsonify({"error": "Autentikaatio puuttuu tai on virheellinen"}), 401

    return decorated


@admin_bp.get("/devices")
@require_auth
def list_all_devices():
    """Listaa kaikki rekisteröidyt laitteet."""
    devices = list_devices()
    return jsonify({"devices": devices, "count": len(devices)})


@admin_bp.get("/devices/<udid>")
@require_auth
def get_one_device(udid: str):
    """Palauttaa yksittäisen laitteen tiedot."""
    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404
    return jsonify(device)


@admin_bp.post("/devices/<udid>/command")
@require_auth
def send_command(udid: str):
    """Lisää MDM-komennon laitteen jonoon.

    Body (JSON):
      {
        "command_type": "DeviceInformation",  // Apple MDM RequestType
        "payload": {}                          // Komennon lisäparametrit
      }

    Tuetut komennot (yleisimmät):
      DeviceInformation   — laitetietojen kysely
      DeviceLock          — laite lukitaan välittömästi
      EraseDevice         — laite pyyhitään
      InstallApplication  — sovellusasennus (vaatii VPP)
      RestartDevice       — uudelleenkäynnistys
      ShutDownDevice      — sammutus
      EnableRemoteDesktop — etätyöpöytä päälle
      DisableRemoteDesktop — etätyöpöytä pois
    """
    body = request.get_json(silent=True) or {}
    command_type = body.get("command_type")
    if not command_type:
        return jsonify({"error": "command_type vaaditaan"}), 400

    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404

    cmd = {
        "command_type": command_type,
        "payload": body.get("payload", {}),
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    enqueue_command(udid, cmd)
    logger.info("Komento lisätty jonoon: UDID=%s type=%s", udid, command_type)

    return jsonify({"status": "queued", "command_type": command_type}), 202


@admin_bp.post("/devices/<udid>/push")
@require_auth
def trigger_push(udid: str):
    """Lähettää APNs herätyksen laitteelle jotta se pollaa MDM-serveriä."""
    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404

    push_token = device.get("push_token")
    push_magic = device.get("push_magic")
    topic = device.get("topic")
    if not push_token or not push_magic or not topic:
        return jsonify({"error": "Laitteella ei ole riittäviä APNs-tietoja (push_token, push_magic, topic)"}), 400

    sandbox = os.environ.get("APNS_SANDBOX", "false").lower() == "true"
    ok = send_push(push_token, push_magic, topic, sandbox=sandbox)

    if ok:
        return jsonify({"status": "push sent"}), 200
    else:
        return jsonify({"error": "APNs push epäonnistui"}), 502
