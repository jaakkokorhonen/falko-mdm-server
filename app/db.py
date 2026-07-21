"""Firestore-abstraktio. Tallentaa laitetiedot ja MDM-komantojono.

Rakenne Firestoressä:
  devices/{udid}                    — laitetietue (malli, OS, tila, APNs-tiedot)
  devices/{udid}/commands/{cmd_id}  — MDM-komanto (status: pending | sent | acknowledged | error)

Kaikki tietokantakutsut kulkevat tämän moduulin kautta —
älä kutsu Firestorea suoraan muista moduuleista.

Parannus (2026-07): list_devices tukee sivutusta (page_size + cursor),
  get_db validoi projektin puuttumisen selkeällä virheellä.
  Ref: Google Firestore docs "Query cursors" (2024).
"""
import os
import logging
from google.cloud import firestore

logger = logging.getLogger(__name__)

# Moduulitason singleton — Firestore-asiakas alustetaan kerran per prosessi.
_db = None

# Oletussivukoko list_devices-kyselylle.
# Pieni arvo estää muistipiikin jos laitemäärä kasvaa.
_DEFAULT_PAGE_SIZE = 100


def get_db() -> firestore.Client:
    """Palauttaa Firestore-asiakkaan, alustaa sen tarvittaessa.

    Käyttää lazy-alustusta: yhteys avataan vasta ensimmäisellä kutsulla.
    Nostaa EnvironmentError jos GCP_PROJECT puuttuu paikallisessa ajossa.

    Returns:
        Alustettu Firestore-asiakasinstanssi.

    Raises:
        EnvironmentError: Jos GCP_PROJECT puuttuu eikä ole Cloud Run -ympäristössä.
    """
    global _db
    if _db is None:
        project = os.environ.get("GCP_PROJECT")
        if not project:
            # Cloud Runissa SDK päättelee projektin metatietopalvelusta.
            # Paikallisessa ajossa GCP_PROJECT on pakollinen.
            logger.warning(
                "GCP_PROJECT ei ole asetettu — Firestore käyttää SDK:n autodetectiä. "
                "Paikallisessa ajossa aseta GCP_PROJECT ympäristömuuttujaan."
            )
        _db = firestore.Client(project=project)
    return _db


# --- Laitteet ----------------------------------------------------------------

def upsert_device(udid: str, data: dict) -> None:
    """Luo tai päivittää laitetietueen Firestoreen.

    Käyttää merge=True jotta osapäivitykset (esim. vain push_token)
    eivät ylikirjoita muita kenttiä.

    Args:
        udid: Laitteen Apple-tunniste (Unique Device Identifier).
        data: Päivitettävät kentät dict-muodossa.
    """
    db = get_db()
    db.collection("devices").document(udid).set(data, merge=True)


def get_device(udid: str) -> dict | None:
    """Hakee yksittäisen laitteen tiedot.

    Args:
        udid: Laitteen tunniste.

    Returns:
        Laitetietue dict-muodossa, tai None jos laitetta ei löydy.
    """
    db = get_db()
    doc = db.collection("devices").document(udid).get()
    return doc.to_dict() if doc.exists else None


def list_devices(
    page_size: int = _DEFAULT_PAGE_SIZE,
    start_after: str | None = None,
) -> tuple[list[dict], str | None]:
    """Palauttaa laitteet sivutettuna listana.

    Käyttää Firestore cursor-pohjaista sivutusta jotta yksittäinen
    kysely ei palauta rajoittamatonta datamäärää.

    Args:
        page_size:   Maksimimäärä laitteita per sivu (1–500). Oletus 100.
        start_after: Edellisen sivun viimeisen laitteen UDID (sivutuskriteeri).
                     None = ensimmäinen sivu.

    Returns:
        Kaksikko (devices, next_cursor) jossa:
          - devices: Lista laitetietueista, joissa mukana 'udid'-avain.
          - next_cursor: Seuraavan sivun UDID tai None jos sivuja ei enää ole.
    """
    db = get_db()
    capped = min(max(1, page_size), 500)
    query = db.collection("devices").order_by("__name__").limit(capped)
    if start_after:
        cursor_doc = db.collection("devices").document(start_after).get()
        if cursor_doc.exists:
            query = query.start_after(cursor_doc)

    docs = list(query.stream())
    devices = [{"udid": d.id, **d.to_dict()} for d in docs]
    next_cursor = docs[-1].id if docs and len(docs) == capped else None
    return devices, next_cursor


# --- Komentojono -------------------------------------------------------------


def enqueue_command(udid: str, command: dict) -> None:
    """Lisää Apple MDM -komennon laitteen odottavien komentojen jonoon Firestoreen.

    Args:
        udid:    Laitteen uniikki UDID-tunniste.
        command: Lisättävä komentosanakirja (command_type, status, created_at jne.).
    """
    db = get_db()
    db.collection("devices").document(udid) \
      .collection("commands").add(command)


def dequeue_command(udid: str) -> tuple[str, dict] | tuple[None, None]:
    """Hakee ja palauttaa seuraavan odottavan komennon laitteen jonosta (FIFO).

    Args:
        udid: Laitteen uniikki UDID-tunniste.

    Returns:
        Kaksikko (cmd_id, cmd_dict), tai (None, None) jos jonossa ei ole komentoja.
    """
    db = get_db()
    docs = (
        db.collection("devices").document(udid)
          .collection("commands")
          .where("status", "==", "pending")
          .order_by("created_at")
          .limit(1)
          .stream()
    )
    for doc in docs:
        return doc.id, doc.to_dict()
    return None, None


def ack_command(udid: str, cmd_id: str, status: str = "acknowledged") -> None:
    """Päivittää laitteelle lähetetyn komennon tilan Firestoreen.

    Args:
        udid:   Laitteen uniikki UDID-tunniste.
        cmd_id: Päivitettävän komennon dokumentti-ID.
        status: Komennon uusi tila ('sent', 'acknowledged', 'error', 'notnow').
    """
    db = get_db()
    db.collection("devices").document(udid) \
      .collection("commands").document(cmd_id) \
      .update({"status": status})
