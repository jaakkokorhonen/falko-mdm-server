"""Apple MDM Command endpoint (/mdm).

Laite lähettää PUT /mdm -pyynnön jokaisella MDM-pollilla tai
APNs-herätysviestin jälkeen. Endpoint palauttaa seuraavan
odottavan komennon plistinä tai tyhjän 200 jos jonossa ei ole mitään.

Apple MDM Protocol Reference:
https://developer.apple.com/documentation/devicemanagement/implementing-the-simple-mdm-protocol
"""
import re
import logging
import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, Response
from plistlib import loads as plist_loads, dumps as plist_dumps, FMT_XML
from .db import upsert_device, dequeue_command, ack_command

mdm_bp = Blueprint("mdm", __name__)
logger = logging.getLogger(__name__)

# Sama validaatio kuin checkin.py:ssä: hylätään virheelliset UDIDit
# ennen Firestore-kirjoitusta.
_UDID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{18,38}[A-Z0-9]$")


def _build_command_plist(command_type: str, cmd_uuid: str, payload: dict | None = None) -> bytes:
    """Rakentaa MDM-komentovastausplistin."""
    cmd: dict = {
        "RequestType": command_type,
    }
    if payload:
        cmd.update(payload)
    return plist_dumps({
        "Command": cmd,
        "CommandUUID": cmd_uuid,
    }, fmt=FMT_XML)


@mdm_bp.route("/mdm", methods=["PUT"])
def mdm():
    try:
        data = plist_loads(request.data, fmt=FMT_XML)
    except Exception as exc:
        logger.warning("MDM: plist-jäsennys epäonnistui: %s", exc)
        return Response("", status=400)

    # UDID-validointi: hylätään puuttuvat tai epämuodostuneet UDIDit
    udid = data.get("UDID", "")
    if not udid or not _UDID_RE.match(udid):
        logger.warning("MDM: virheellinen tai puuttuva UDID: %r", udid[:40] if udid else "")
        return Response("", status=400)

    status   = data.get("Status", "")
    cmd_uuid = data.get("CommandUUID", "")

    logger.info("MDM PUT UDID=%s Status=%s CommandUUID=%s", udid, status, cmd_uuid)

    # Päivitetään laite viimeksi nähdyksi
    upsert_device(udid, {
        "last_seen":   datetime.now(timezone.utc).isoformat(),
        "last_status": status,
    })

    # Kuitataan edellinen komento jos laite raportoi sen tilan.
    # NotNow tarkoittaa: laite ei juuri nyt pysty suorittamaan, ei virhetilaa —
    # komento jää jonoon uudelleenyritystä varten.
    if cmd_uuid and status in ("Acknowledged", "Error", "CommandFormatError", "NotNow"):
        ack_command(udid, cmd_uuid, status.lower())

    # Haetaan seuraava komento jonosta (FIFO-järjestys)
    cmd_id, cmd = dequeue_command(udid)
    if cmd is None:
        # Tyhjä 200: Apple-spec mukainen tapa ilmoittaa ettei komentoja ole
        return Response("", status=200)

    # Merkitään komento lähetetyksi jotta se ei tule uudelleen jonosta
    ack_command(udid, cmd_id, "sent")

    command_type = cmd.get("command_type", "DeviceInformation")
    payload      = cmd.get("payload", {})

    response_plist = _build_command_plist(command_type, cmd_id, payload)
    return Response(response_plist, status=200, mimetype="application/xml")
