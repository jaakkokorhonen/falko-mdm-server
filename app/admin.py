"""Admin API — laitelistaus ja komentojen lähettäminen.

Endpointit:
  GET  /admin/devices                   — lista kaikista laitteista
  GET  /admin/devices/<udid>             — yksittäisen laitteen tiedot
  POST /admin/devices/<udid>/command     — lisää komento laitteen jonoon
  POST /admin/devices/<udid>/push        — lähetä APNs-herätys

Autentikaatio:
  Google Identity-Aware Proxy (IAP) tarkistaa käyttäjän Google Workspace
  -tunnistuksen ennen kuin pyynnöt pääsevät tähän serviceen. IAP lisää
  X-Goog-Authenticated-User-Email -otsakkeen jokaisen pyyntöön.

  Tässä servicessä ei tarvita omaa kirjautumislogiikkaa — luottamus
  on sidottu infrastruktuuriin, ei sovelluskoodiin. Ks. README:
  Tietoturvaperiaate.

TIETOTURVAHUOM: require_iap-dekoraattori tarkistaa otsakkeen muodon
jälkikeen, mutta oikea suoja vaatii että Cloud Run on ei-julkinen
ja liikenne kulkee IAP-suojatun Load Balancerin kautta.
"""
import os
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import Blueprint, request, jsonify
from .db import list_devices, get_device, enqueue_command
from .apns import send_push

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
logger = logging.getLogger(__name__)


def require_iap(f):
    """Dekoraattori: varmistaa Google IAP -otsakkeen ja @falko.fi-osoitteen.

    IAP lisää jokaiseen pyyntyy otsakkeen muodossa:
      X-Goog-Authenticated-User-Email: accounts.google.com:kayttaja@falko.fi

    Tarkistaa:
      1. Otsake on olemassa ja alkaa oikealla etuliitteellä.
      2. Sähköpostiosoite päättyy @falko.fi:hin.

    TODO(jaakko): Lisää JWT-allekirjoituksen verifiointi
    X-Goog-IAP-JWT-Assertion -otsakkeesta google-auth-kirjastolla
    vahvemmaksi suojaksi suoran HTTP-pyyntöhuijauksen varalta.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user_header = request.headers.get("X-Goog-Authenticated-User-Email", "")
        # IAP-otsakkeen muoto: "accounts.google.com:<email>"
        # Puuttuva tai vääränmuotoinen otsake = pyynntö ei tullut IAP:n kautta
        if not user_header or not user_header.startswith("accounts.google.com:"):
            return jsonify({"error": "IAP-autentikointi puuttuu tai on virheellinen"}), 401

        email = user_header.split("accounts.google.com:")[1]
        # Rajoitetaan pääsy vain @falko.fi Workspace-domainille.
        # IAP:n IAM-säännöllä pitäisi jo hoitua, mutta tämä on toinen puolustuslinja.
        if not email.endswith("@falko.fi"):
            return jsonify({"error": "Käyttöoikeus evätty (vain falko.fi-käyttäjille)"}), 403

        return f(*args, **kwargs)
    return decorated


@admin_bp.get("/devices")
@require_iap
def list_all_devices():
    """Listaa kaikki rekisteröidyt laitteet.

    Returns:
        JSON { devices: [...], count: int }
    """
    devices = list_devices()
    return jsonify({"devices": devices, "count": len(devices)})


@admin_bp.get("/devices/<udid>")
@require_iap
def get_one_device(udid: str):
    """Palauttaa yksittäisen laitteen tiedot.

    Args:
        udid: Laitteen Apple-tunniste URL-polusta.

    Returns:
        JSON-laitetietue tai 404 jos laitetta ei löydy.
    """
    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404
    return jsonify(device)


@admin_bp.post("/devices/<udid>/command")
@require_iap
def send_command(udid: str):
    """Lisää MDM-komennon laitteen jonoon.

    Laite hakee komennon seuraavalla MDM-pollilla tai APNs-herätyksen
    jälkeen. Komento ei siis toteudu välittömästi.

    Body (JSON)::

        {
          "command_type": "DeviceInformation",
          "payload": {}
        }

    Tuetut komennot (yleisimmät Apple MDM RequestTypet):
      DeviceInformation    — laitetietojen kysely
      DeviceLock           — laite lukitaan välittömästi
      EraseDevice          — PERUUTTAMATON: laite pyyhitään
      InstallApplication   — sovellusasennus (vaatii VPP-lisenssit)
      RestartDevice        — uudelleenkäynnistys
      ShutDownDevice       — PERUUTTAMATON: sammutus
      EnableRemoteDesktop  — etätyöpöytä päälle
      DisableRemoteDesktop — etätyöpöytä pois

    Returns:
        202 Accepted { status: "queued", command_type } jos onnistui.
        400 Bad Request jos command_type puuttuu.
        404 jos laitetta ei löydy.
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
        # ISO 8601 UTC -aikaleima järjestystä varten dequeue_command-kyselymssä
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    enqueue_command(udid, cmd)
    logger.info("Komento lisätty jonoon: UDID=%s type=%s", udid, command_type)

    return jsonify({"status": "queued", "command_type": command_type}), 202


@admin_bp.post("/devices/<udid>/push")
@require_iap
def trigger_push(udid: str):
    """Lähettää APNs-herätyksen laitteelle.

    Herätys ei sisällä komentoa — se vain käskee laitteen
    ottamaan yhteyden MDM-serveriin ja hakemaan jonon.
    APNs-tiedot (push_token, push_magic, topic) tallennetaan
    CheckIn/TokenUpdate-viestissä.

    Args:
        udid: Laite jolle herätys lähetetään.

    Returns:
        200 { status: "push sent" } jos APNs hyväksyi pyyntön.
        400 jos laitteen APNs-tiedot puuttuvat.
        404 jos laitetta ei löydy.
        502 jos APNs hylkäsi pyyntön.
    """
    device = get_device(udid)
    if not device:
        return jsonify({"error": "Laitetta ei löydy"}), 404

    push_token = device.get("push_token")
    push_magic = device.get("push_magic")
    topic = device.get("topic")
    # Kaikki kolme vaaditaan APNs-yhteyteen. Ne tallennetaan vasta
    # TokenUpdate-viestissä, joten uudet laitteet eivät välttämättä ole vielä valmiita.
    if not push_token or not push_magic or not topic:
        return jsonify({"error": "Laitteella ei ole riittäviä APNs-tietoja (push_token, push_magic, topic)"}), 400

    # APNS_SANDBOX=true kehitysympäristössä, false (oletus) tuotannossa
    sandbox = os.environ.get("APNS_SANDBOX", "false").lower() == "true"
    ok = send_push(push_token, push_magic, topic, sandbox=sandbox)

    if ok:
        return jsonify({"status": "push sent"}), 200
    return jsonify({"error": "APNs push epäonnistui"}), 502
