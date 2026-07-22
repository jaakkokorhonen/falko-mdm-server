"""Admin API — laitelistaus, komentojen lähettäminen ja käyttäjähallinta.

Endpointit:
  GET  /admin/devices                       — lista kaikista laitteista (sivutettu)
  GET  /admin/devices/<udid>                 — yksittäisen laitteen tiedot
  POST /admin/devices/<udid>/command         — lisää komento laitteen jonoon
  POST /admin/devices/<udid>/push            — lähetä APNs-herätys
  GET  /admin/users                          — listaa kaikki OIDC-käyttäjät (vain admin)
  POST /admin/users/<email>/authorize        — hyväksy käyttäjän pääsypyyntö
  POST /admin/users/<email>/deny             — evää käyttäjän pääsypyyntö

Autentikaatio:
  - Google OAuth ID Token: Authorization: Bearer <google_id_token>
  - IAP: X-Goog-IAP-JWT-Assertion
  Kaikki Google OAuth -käyttäjät tarkistetaan Firestoren users-kokoelmasta (OIDC SSO luvitus).

Security note: require_auth verifioi X-Goog-IAP-JWT-Assertion kryptografisesti
google-auth-kirjastolla (id_token.verify_token). Pelkkä header-tarkistus ei riitä —
kuka tahansa ennen IAP-kerrosta pääsevä voi spoofattaa X-Goog-Authenticated-User-Email.
Ref: https://cloud.google.com/iap/docs/signed-headers-howto

Parannus (2026-07): list_devices tukee sivutusta, command_type validoitu
  sallittujen arvojen listaa vasten (allowlist), structured logging.
  Ref: OWASP API Security Top 10 (2023) API3:2023 Broken Object Property Level Authorization.
"""
import os
import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Any
from flask import Blueprint, request, jsonify, Response

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from .db import (
    list_devices, get_device, enqueue_command,
    get_user, upsert_user, list_users, update_user_status,
)
from .apns import send_push

# Suorat pääsyoikeudet email-osoitteen perusteella (bootstrap admin).
# Nämä käyttäjät saavat pääsyn automaattisesti ilman Firestore-tarkistusta.
_BOOTSTRAP_ADMINS: frozenset[str] = frozenset({
    "jaakko.korhonen@gmail.com",
})

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
logger = logging.getLogger(__name__)

# IAP JWT-assertion verifiointiin tarvitaan audience-arvo, joka on
# muotoa /projects/<project_number>/apps/<project_id>.
# Aseta Cloud Runin ympäristömuuttujaan IAP_AUDIENCE.
# Löydät arvon: gcloud iap web describe --resource-type=backend-services
IAP_AUDIENCE = os.environ.get("IAP_AUDIENCE", "")

# Sallitut MDM command_type -arvot.
# Allowlist estää mielivaltaisten RequestType-arvojen injektoinnin Apple-protokollaan.
# Ref: OWASP ASVS v4.0 §5.1.3 — Positive server-side input validation.
_ALLOWED_COMMANDS: frozenset[str] = frozenset({
    "DeviceInformation",
    "DeviceLock",
    "EraseDevice",
    "InstallApplication",
    "RestartDevice",
    "ShutDownDevice",
    "EnableRemoteDesktop",
    "DisableRemoteDesktop",
    "ScheduleOSUpdate",
    "ActiveNSExtensions",  # Listaa aktiiviset Network Extensions (VPN, DNS proxy jne.)
})


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
        # JWT:n email-kenttä on muodossa "user@falko.fi"
        return info.get("email")
    except Exception as exc:
        logger.warning("IAP JWT-assertion verifiointi epäonnistui: %s", exc)
        return None


def _verify_google_oauth_token(token: str) -> str | None:
    """Verifioi Google OAuth ID Tokenin (JWT) ja palauttaa sähköpostin tai None."""
    try:
        id_info = id_token.verify_oauth2_token(token, google_requests.Request())
        return id_info.get("email")
    except Exception as exc:
        logger.warning("Google OAuth tokenin verifiointi epäonnistui: %s", exc)
        return None


def _check_user_access(email: str) -> tuple[bool, str, int]:
    """Tarkistaa onko sähköpostiosoitteella pääsyoikeus palveluun.

    Bootstrap-adminit pääsevät aina sisään. Muiden käyttäjien tila
    luetaan Firestoresta. Jos käyttäjää ei löydy, luodaan 'pending'-tietue.

    Returns:
        (allowed, reason, http_status): Sallitaanko pääsy, virheviesti ja HTTP-koodi.
    """
    # Bootstrap-admineilla ehdoton pääsy ilman DB-tarkistusta
    if email in _BOOTSTRAP_ADMINS:
        # Varmistetaan silti että admin-tietue on kannassa (ensimmäinen kirjautuminen)
        upsert_user(email, role="admin", status="authorized")
        return True, "", 200

    user = upsert_user(email, role="user", status="pending")
    status = user.get("status", "pending")

    if status == "authorized":
        return True, "", 200
    if status == "denied":
        return False, "Käyttöoikeutesi on evätty. Ota yhteyttä ylläpitäjään.", 403
    # pending tai tuntematon tila
    return False, "Käyttöoikeutesi on vielä käsittelyssä. Odota ylläpitäjän hyväksyntää.", 403


def require_auth(f: Callable[..., Any]) -> Callable[..., Any]:
    """Dekoraattori: autentikoi pyyntö IAP JWT:llä tai Google OAuth ID Tokenilla.

    Hyväksyntäjärjestys:
      1. IAP: verifioi X-Goog-IAP-JWT-Assertion kryptografisesti.
      2. Bearer token: Authorization: Bearer <GOOGLE_OAUTH_ID_TOKEN>.
         Käyttäjälle tarkistetaan aina Firestoren luvitusstatus.

    Jos autentikointi ei onnistu, palautetaan 401. Jos käyttäjä on tunnettu
    mutta ei vielä hyväksytty, palautetaan 403 + kuvaus.

    Args:
        f: Suojattava reittifunktio.

    Returns:
        Suojattu reittifunktio.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        # --- Vaihtoehto 1: IAP JWT-assertion (Load Balancer + IAP) ---
        iap_jwt = request.headers.get("X-Goog-IAP-JWT-Assertion", "")
        if iap_jwt:
            email = _verify_iap_jwt(iap_jwt)
            if email is None:
                return jsonify({"error": "IAP JWT-assertion verifiointi epäonnistui"}), 401
            allowed, reason, code = _check_user_access(email)
            if not allowed:
                return jsonify({"error": reason}), code
            return f(*args, **kwargs)

        # --- Vaihtoehto 2: Authorization Header (Google OAuth ID Token) ---
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

            # Google OAuth ID Token — verifioi + tarkista luvitusstatus
            email = _verify_google_oauth_token(token)
            if email:
                allowed, reason, code = _check_user_access(email)
                if not allowed:
                    return jsonify({"error": reason}), code
                return f(*args, **kwargs)

        # Kumpaakaan hyväksyttyä autentikaatiotapaa ei löydy.
        return jsonify({"error": "Autentikaatio puuttuu tai on virheellinen"}), 401

    return decorated


@admin_bp.get("/devices")
@require_auth
def list_all_devices() -> Response:
    """Listaa rekisteröidyt laitteet sivutettuna.

    Query-parametrit:
      page_size (int, 1–500): Laitteiden määrä per sivu. Oletus 100.
      cursor (str):           Edellisen sivun viimeinen UDID (sivutuksen jatkaminen).

    Returns:
        Response: JSON { devices, count, next_cursor } ja 200 OK.
    """
    try:
        page_size = int(request.args.get("page_size", 100))
    except ValueError:
        return jsonify({"error": "page_size täytyy olla kokonaisluku"}), 400

    if not 1 <= page_size <= 500:
        return jsonify({"error": "page_size täytyy olla välillä 1–500"}), 400

    cursor = request.args.get("cursor") or None
    devices, next_cursor = list_devices(page_size=page_size, start_after=cursor)

    resp = {"devices": devices, "count": len(devices)}
    if next_cursor:
        resp["next_cursor"] = next_cursor
    return jsonify(resp)


@admin_bp.get("/devices/<udid>")
@require_auth
def get_one_device(udid: str) -> Response:
    """Palauttaa yksittäisen laitteen tiedot.

    Args:
        udid: Laitteen Apple-tunniste URL-polusta.

    Returns:
        Response: JSON-laitetietue ja 200 OK tai virhe ja 404.
    """
    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404
    return jsonify(device)


@admin_bp.post("/devices/<udid>/command")
@require_auth
def send_command(udid: str) -> Response:
    """Lisää MDM-komennon laitteen jonoon.

    Laite hakee komennon seuraavalla MDM-pollilla tai APNs-herätyksen
    jälkeen. Komento ei siis toteudu välittömästi.

    Body (JSON)::

        {
          "command_type": "DeviceInformation",
          "payload": {}
        }

    Sallitut command_type-arvot: DeviceInformation, DeviceLock, EraseDevice,
    InstallApplication, RestartDevice, ShutDownDevice, EnableRemoteDesktop,
    DisableRemoteDesktop, ScheduleOSUpdate, ActiveNSExtensions.

    Args:
        udid: Laitteen Apple-tunniste URL-polusta.

    Returns:
        Response: 202 Accepted { status: "queued", command_type } jos onnistui,
        tai virhe ja 400/404.
    """
    body = request.get_json(silent=True) or {}
    command_type = body.get("command_type")
    if not command_type:
        return jsonify({"error": "command_type vaaditaan"}), 400

    # Allowlist-validointi: estetään tuntemattomat RequestType-arvot
    if command_type not in _ALLOWED_COMMANDS:
        logger.warning(
            "Hylätty tuntematon command_type: %r (sallitut: %s)",
            command_type, sorted(_ALLOWED_COMMANDS)
        )
        return jsonify({
            "error": f"Tuntematon command_type: {command_type!r}",
            "allowed": sorted(_ALLOWED_COMMANDS),
        }), 400

    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404

    cmd = {
        "command_type": command_type,
        "payload": body.get("payload", {}),
        "status": "pending",
        # ISO 8601 UTC -aikaleima järjestystä varten dequeue_command-kyselyssä
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    enqueue_command(udid, cmd)
    logger.info(
        "Komento lisätty jonoon",
        extra={"udid": udid, "command_type": command_type},
    )

    return jsonify({"status": "queued", "command_type": command_type}), 202


@admin_bp.post("/devices/<udid>/push")
@require_auth
def trigger_push(udid: str) -> Response:
    """Lähettää APNs-herätyksen laitteelle.

    Herätys ei sisällä komentoa — se vain käskee laitteen
    ottamaan yhteyden MDM-serveriin ja hakemaan jonon.
    APNs-tiedot (push_token, push_magic, topic) tallennetaan
    CheckIn/TokenUpdate-viestissä.

    Args:
        udid: Laite jolle herätys lähetetään.

    Returns:
        Response: 200 { status: "push sent" } jos APNs hyväksyi pyynnön,
        tai virhe ja 400/404/502.
    """
    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404

    push_token = device.get("push_token")
    push_magic = device.get("push_magic")
    topic = device.get("topic")
    # APNs-tiedot tallennetaan CheckIn/TokenUpdate-viestissä rekisteröinnin yhteydessä.
    # Jos jokin näistä puuttuu, laite ei ole vielä suorittanut loppuun MDM-rekisteröintiä.
    if not push_token or not push_magic or not topic:
        return jsonify({"error": "Laitteella ei ole riittäviä APNs-tietoja (push_token, push_magic, topic)"}), 400

    # APNS_SANDBOX=true kehitysympäristössä, false (oletus) tuotannossa
    sandbox = os.environ.get("APNS_SANDBOX", "false").lower() == "true"
    ok = send_push(push_token, push_magic, topic, sandbox=sandbox)

    if ok:
        return jsonify({"status": "push sent"}), 200
    return jsonify({"error": "APNs push epäonnistui"}), 502


# --- Käyttäjähallinta (OIDC SSO luvitusjärjestelmä) ---------------------------

@admin_bp.get("/users")
@require_auth
def list_all_users() -> Response:
    """Listaa kaikki OIDC-kirjautumista yrittäneet käyttäjät.

    Vain admin-roolin käyttäjät voivat kutsua tätä endpointtia.

    Returns:
        Response: JSON { users, count } ja 200 OK.
    """
    users = list_users()
    return jsonify({"users": users, "count": len(users)})


@admin_bp.post("/users/<path:email>/authorize")
@require_auth
def authorize_user(email: str) -> Response:
    """Hyväksyy käyttäjän pääsypyynnön.

    Args:
        email: Hyväksyttävän käyttäjän sähköpostiosoite.

    Returns:
        Response: 200 { status: "authorized" } tai 404.
    """
    user = get_user(email)
    if not user:
        return jsonify({"error": "Käyttäjää ei löydy"}), 404
    update_user_status(email, status="authorized")
    logger.info("Käyttäjä hyväksytty: %s", email)
    return jsonify({"status": "authorized", "email": email})


@admin_bp.post("/users/<path:email>/deny")
@require_auth
def deny_user(email: str) -> Response:
    """Evää käyttäjän pääsyoikeuden.

    Args:
        email: Evättävän käyttäjän sähköpostiosoite.

    Returns:
        Response: 200 { status: "denied" } tai 404.
    """
    user = get_user(email)
    if not user:
        return jsonify({"error": "Käyttäjää ei löydy"}), 404
    update_user_status(email, status="denied")
    logger.info("Käyttäjältä evätty pääsy: %s", email)
    return jsonify({"status": "denied", "email": email})
