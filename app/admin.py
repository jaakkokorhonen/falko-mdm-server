"""Admin API — laitelistaus, komentojen lähettäminen ja käyttäjähallinta.

Endpointit:
  GET  /admin/devices                       — lista kaikista laitteista (sivutettu)
  GET  /admin/devices/<udid>                 — yksittäisen laitteen tiedot
  POST /admin/devices/<udid>/command         — lisää komento laitteen jonoon
  POST /admin/devices/<udid>/push            — lähetä APNs-herätys
  GET  /admin/users                          — listaa kaikki OIDC-käyttäjät (vain admin)
  POST /admin/users/<email>/authorize        — hyväksy käyttäjän pääsypyyntö
  POST /admin/users/<email>/deny             — evää käyttäjän pääsypyyntö

Autentikaatiotasot:
  @require_auth  — Kaikki hyväksytyt käyttäjät (status=authorized, role=user tai admin).
                   Käytetään: device-listaus, laitetiedot, komennon lähetys, APNs-push.
                   HUOM: EraseDevice ja ShutDownDevice vaativat admin-roolin (ks. alla).
  @require_admin — Vain admin-roolin käyttäjät (status=authorized, role=admin).
                   Käytetään: käyttäjähallinta (/users/*) ja DANGER-komennot.

Autentikaatiotapa:
  - Google OAuth ID Token: Authorization: Bearer <google_id_token>
  - IAP: X-Goog-IAP-JWT-Assertion
  Kaikki Google OAuth -käyttäjät tarkistetaan Firestoren users-kokoelmasta (OIDC SSO luvitus).

Security note: require_auth verifioi X-Goog-IAP-JWT-Assertion kryptografisesti
google-auth-kirjastolla (id_token.verify_token). Pelkkä header-tarkistus ei riitä —
kuka tahansa ennen IAP-kerrosta pääsevä voi spoofattaa X-Goog-Authenticated-User-Email.
Ref: https://cloud.google.com/iap/docs/signed-headers-howto

Korjaukset (2026-07):
  - SEC-10: Bootstrap admin siirretty BOOTSTRAP_ADMIN_EMAIL-ympäristömuuttujaan.
  - SEC-11: require_admin-dekoraattori — roolitarkistus /users-endpointille ja
    DANGER-komennoille (EraseDevice, ShutDownDevice, DeviceLock).
  - SEC-20 (apns.py): APNs-avain Secret Managerista.
  - Review-korjaukset: bootstrap-virheenkäsittely, auth-semantiikka, DANGER-rajaus.
  Ref: OWASP API Security Top 10 (2023) API3:2023, API5:2023.
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

# SEC-10: Bootstrap admin luetaan ympäristömuuttujasta kovakoodatun sähköpostin sijaan.
# Aseta Cloud Run -ympäristömuuttuja BOOTSTRAP_ADMIN_EMAIL tai tallenna
# Secret Manageriin ja mount Cloud Runin env:iin.
# Tyhjä arvo tarkoittaa: ei bootstrap-adminia (täysi Firestore-tarkistus kaikille).
_bootstrap_admin_email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
_BOOTSTRAP_ADMINS: frozenset[str] = (
    frozenset({_bootstrap_admin_email}) if _bootstrap_admin_email else frozenset()
)

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

# Komennot jotka vaativat admin-roolin (require_admin) eikä pelkkää
# authorized-statusta (require_auth). Peruuttamattomat tai korkean riskin komennot.
# Ref: OWASP API5:2023 Broken Function Level Authorization.
_DANGER_COMMANDS: frozenset[str] = frozenset({
    "EraseDevice",      # Pyyhkii kaiken laitteen datan — peruuttamaton
    "ShutDownDevice",   # Sammuttaa laitteen — vaatii fyysistä toimenpidettä
    "DeviceLock",       # Voi lukita laitteen PIN-koodilla jota ei tiedetä
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
    if email.lower() in _BOOTSTRAP_ADMINS:
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


def _get_authenticated_email() -> tuple[str | None, str]:
    """Palauttaa autentikoituneen käyttäjän sähköpostin ja autentikointitavan.

    Kokeilee järjestyksessä: IAP JWT → Bearer Google OAuth Token.

    Returns:
        (email, method) jossa method on 'iap', 'bearer' tai 'none'.
        Email on None jos autentikointi epäonnistuu tai headeria ei löydy.
    """
    iap_jwt = request.headers.get("X-Goog-IAP-JWT-Assertion", "")
    if iap_jwt:
        # IAP JWT löytyi — verifioi kryptografisesti
        email = _verify_iap_jwt(iap_jwt)
        if email is None:
            # JWT löytyi mutta verifiointi epäonnistui — tämä on eri tilanne
            # kuin "ei headeria" — logitetaan jo _verify_iap_jwt:ssä
            logger.warning("IAP JWT-assertion hylätty — palautetaan None")
        return email, "iap"

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        email = _verify_google_oauth_token(token)
        return email, "bearer"

    return None, "none"


def require_auth(f: Callable[..., Any]) -> Callable[..., Any]:
    """Dekoraattori: autentikoi pyyntö ja tarkistaa pääsyoikeuden.

    Hyväksyy kaikki authorized-statuksen käyttäjät riippumatta roolista
    (role=user tai role=admin). Tämä on tarkoituksellinen valinta:
    kaikki hyväksytyt MDM-ylläpitäjät voivat listata laitteita ja
    lähettää useimpia komentoja. Vain DANGER_COMMANDS vaativat admin-roolin
    (tarkistetaan send_command-endpointissa erikseen).

    Hyväksyntäjärjestys:
      1. IAP: verifioi X-Goog-IAP-JWT-Assertion kryptografisesti.
      2. Bearer token: Authorization: Bearer <GOOGLE_OAUTH_ID_TOKEN>.
         Käyttäjälle tarkistetaan aina Firestoren luvitusstatus.

    Jos autentikointi ei onnistu, palautetaan 401. Jos käyttäjä on tunnettu
    mutta ei vielä hyväksytty, palautetaan 403 + kuvaus.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        email, method = _get_authenticated_email()
        if not email:
            logger.warning(
                "Autentikaatio epäonnistui: method=%s path=%s",
                method, request.path
            )
            return jsonify({"error": "Autentikaatio puuttuu tai on virheellinen"}), 401

        allowed, reason, code = _check_user_access(email)
        if not allowed:
            return jsonify({"error": reason}), code

        return f(*args, **kwargs)
    return decorated


def require_admin(f: Callable[..., Any]) -> Callable[..., Any]:
    """Dekoraattori: autentikoi pyyntö ja vaatii admin-roolin.

    SEC-11: /admin/users ja käyttäjähallintaendpointit vaativat admin-roolin.
    authorized-statuksen käyttäjä (role=user) ei pääse näihin endpointteihin.
    Ref: OWASP API5:2023 Broken Function Level Authorization.
    """
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        email, method = _get_authenticated_email()
        if not email:
            logger.warning(
                "Admin-autentikaatio epäonnistui: method=%s path=%s",
                method, request.path
            )
            return jsonify({"error": "Autentikaatio puuttuu tai on virheellinen"}), 401

        # Bootstrap-adminit ohittavat DB-tarkistuksen
        if email.lower() in _BOOTSTRAP_ADMINS:
            try:
                upsert_user(email, role="admin", status="authorized")
            except Exception as exc:
                # upsert epäonnistui (esim. Firestore poissa) — kirjataan mutta
                # ei estetä pääsyä: bootstrap-admin on oikeusperusta joka on
                # vahvistettu ympäristömuuttujalla, ei DB:llä.
                logger.error(
                    "Bootstrap-admin upsert epäonnistui (%s) — pääsy sallitaan silti: %s",
                    email, exc
                )
            return f(*args, **kwargs)

        user = get_user(email)
        if not user:
            return jsonify({"error": "Käyttäjää ei löydy"}), 401
        if user.get("status") != "authorized":
            return jsonify({"error": "Pääsy evätty"}), 403
        if user.get("role") != "admin":
            return jsonify({"error": "Tämä toiminto vaatii admin-oikeudet"}), 403

        return f(*args, **kwargs)
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

    DANGER-komennot (EraseDevice, ShutDownDevice, DeviceLock) vaativat
    admin-roolin — pelkkä authorized-status ei riitä. Tämä on server-puolen
    enforcement UI:n vahvistusmodaalin lisäksi.
    Ref: OWASP API5:2023, _DANGER_COMMANDS.

    Body (JSON)::

        {
          "command_type": "DeviceInformation",
          "payload": {}
        }

    Sallitut command_type-arvot: ks. _ALLOWED_COMMANDS.
    Admin-roolia vaativat: ks. _DANGER_COMMANDS.

    Args:
        udid: Laitteen Apple-tunniste URL-polusta.

    Returns:
        Response: 202 Accepted { status: "queued", command_type } jos onnistui,
        tai virhe ja 400/403/404.
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

    # SEC-11 / OWASP API5:2023: DANGER-komennot vaativat admin-roolin.
    # UI näyttää vahvistusmodaalin (SEC-25), mutta server ei luota UI:hin —
    # tarkistetaan rooli aina myös server-puolella (defense in depth).
    if command_type in _DANGER_COMMANDS:
        email, _ = _get_authenticated_email()
        if email:
            # Bootstrap-admin ohittaa DB-tarkistuksen
            if email.lower() not in _BOOTSTRAP_ADMINS:
                user = get_user(email)
                if not user or user.get("role") != "admin":
                    logger.warning(
                        "DANGER-komento hylätty — ei admin-roolia: email=%s command=%s",
                        email, command_type
                    )
                    return jsonify({
                        "error": f"Komento {command_type!r} vaatii admin-oikeudet."
                    }), 403
        # email on None vain jos _get_authenticated_email palautti None —
        # require_auth on jo tarkistanut autentikaation, joten tämä ei
        # normaalisti tapahdu. Defensiivisesti estetään silti.
        else:
            return jsonify({"error": "Autentikaatio puuttuu"}), 401

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
@require_admin  # SEC-11: vaatii admin-roolin, ei pelkkää authorized-statusta
def list_all_users() -> Response:
    """Listaa kaikki OIDC-kirjautumista yrittäneet käyttäjät.

    Vain admin-roolin käyttäjät voivat kutsua tätä endpointtia.

    Returns:
        Response: JSON { users, count } ja 200 OK.
    """
    users = list_users()
    return jsonify({"users": users, "count": len(users)})


@admin_bp.post("/users/<path:email>/authorize")
@require_admin  # SEC-11: käyttäjähallinta vaatii admin-roolin
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
@require_admin  # SEC-11: käyttäjähallinta vaatii admin-roolin
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
