"""Apple MDM Command endpoint (/mdm).

Laite lähettää PUT /mdm -pyyntön jokaisella MDM-pollilla tai
APNs-herätysviestin jälkeen. Endpoint:
  1. Kuitataan edellinen komento (jos Status lähetettiin)
  2. Päivitetään last_seen
  3. Palautetaan seuraava komento jonosta (tai tyhjä 200)

Apple MDM Protocol Reference:
  https://developer.apple.com/documentation/devicemanagement/implementing-the-simple-mdm-protocol

Huom: Tämä endpoint EI vaadi IAP-autentikaatiota — kutsuja on Apple-laite,
ei ihmiskäyttäjä. Laitteen identiteetti perustuu TLS-sertifikaattiin
(MDM Identity Certificate, sisältyy mobileconfig-profiiliin).
"""
import logging
import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, Response
from plistlib import loads as plist_loads, dumps as plist_dumps, FMT_XML
from .db import upsert_device, dequeue_command, ack_command

mdm_bp = Blueprint("mdm", __name__)
logger = logging.getLogger(__name__)


def _build_command_plist(command_type: str, cmd_uuid: str, payload: dict | None = None) -> bytes:
    """Rakentaa MDM-komentovastausplistin Apple-spesifikaation mukaisesti.

    Apple odottaa rakennetta::

        {
          "Command": { "RequestType": "DeviceInformation", ...payload },
          "CommandUUID": "<uuid>"
        }

    Args:
        command_type: Apple MDM RequestType, esim. "DeviceLock".
        cmd_uuid:     Komennon uniikki tunniste (Firestore-dokumentti-ID).
        payload:      Lisaparametrit komennolle (esim. PIN DeviceLockille).
                      Sulautetaan Command-dictiin suoraan.

    Returns:
        XML plist bytes -muodossa.
    """
    cmd: dict = {"RequestType": command_type}
    if payload:
        # Payload-avaimet sulautetaan Command-dictiin —
        # Apple-spesifikaatio vaatii tasaisen rakenteen, ei alidiktiä
        cmd.update(payload)
    return plist_dumps(
        {"Command": cmd, "CommandUUID": cmd_uuid},
        fmt=FMT_XML,
    )


@mdm_bp.route("/mdm", methods=["PUT"])
def mdm():
    """Käsittelee laitteen MDM-pollin tai APNs-herätykseen vastauksen.

    Protokollan kulku:
      1. Laite lähettää PUT /mdm (tyhjä Status ensimmäisellä kerralla)
      2. Serveri palauttaa komennon plistinä
      3. Laite suorittaa komennon, lähettää uuden PUT jossa Status + CommandUUID
      4. Serveri kuittaa ja palauttaa seuraavan komennon tai tyhjän 200

    Returns:
        200 + komento XML plistinä jos jono ei ole tyhjä.
        200 tyhjällä vastauksella jos jono on tyhjä (Apple-spesifikaatio).
        400 jos plist-jäsennys epäonnistuu.
    """
    try:
        data = plist_loads(request.data, fmt=FMT_XML)
    except Exception as exc:
        logger.warning("MDM: plist-jäsennys epäonnistui: %s", exc)
        return Response("", status=400)

    udid     = data.get("UDID", "unknown")
    status   = data.get("Status", "")
    cmd_uuid = data.get("CommandUUID", "")

    logger.info("MDM PUT UDID=%s Status=%s CommandUUID=%s", udid, status, cmd_uuid)

    # Päivitetään aina last_seen riippumatta pyyntön sisällöstä —
    # kertoo että laite on aktiivinen ja tavoitettavissa
    upsert_device(udid, {
        "last_seen":   datetime.now(timezone.utc).isoformat(),
        "last_status": status,
    })

    # Kuitataan edellinen komento jos laite raportoi tuloksen
    if cmd_uuid and status in ("Acknowledged", "Error", "CommandFormatError", "NotNow"):
        # NotNow = laite ei juuri nyt pysty (esim. käyttäjä kirjautunut ulos).
        # Kuitataan sent-tilaan, ei yritetä automaattisesti uudelleen.
        # TODO(jaakko): Lisää NotNow-retry-logiikka — komento pitäisi
        # palauttaa takaisin "pending"-tilaan uudelleenyritystenä.
        ack_command(udid, cmd_uuid, status.lower())

    # Haetaan seuraava komento jonosta
    cmd_id, cmd = dequeue_command(udid)
    if cmd is None:
        # Tyhjä 200 = Apple-spesifikaation mukainen "ei komentoja" -vastaus
        return Response("", status=200)

    # Merkitaan komento lähetetyksi ennen vastauksen palautusta
    ack_command(udid, cmd_id, "sent")

    command_type = cmd.get("command_type", "DeviceInformation")
    payload      = cmd.get("payload", {})

    response_plist = _build_command_plist(command_type, cmd_id, payload)
    return Response(response_plist, status=200, mimetype="application/xml")
