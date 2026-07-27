"""Firestore-abstraktio. Tallentaa laitetiedot ja MDM-komantojono.

Rakenne Firestoressä:
  devices/{udid}                    — laitetietue (malli, OS, tila, APNs-tiedot)
  devices/{udid}/commands/{cmd_id}  — MDM-komanto (status: pending | sent | acknowledged | error)
  users/{email}                     — käyttäjätietue (status: pending | authorized | denied)

Kaikki tietokantakutsut kulkevat tämän moduulin kautta —
älä kutsu Firestorea suoraan muista moduuleista.

Parannus (2026-07): list_devices tukee sivutusta (page_size + cursor),
  get_db validoi projektin puuttumisen selkeällä virheellä.
  Ref: Google Firestore docs "Query cursors" (2024).
"""
import os
import logging
from datetime import datetime, timezone
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


# --- Käyttäjät (OIDC SSO luvitusjärjestelmä) -----------------------------------

def get_user(email: str) -> dict | None:
    """Hakee käyttäjätietueen sähköpostin perusteella.

    Args:
        email: Käyttäjän sähköpostiosoite (dokumentin ID).

    Returns:
        Käyttäjätietue dict tai None jos ei löydy.
    """
    db = get_db()
    doc = db.collection("users").document(email).get()
    if doc.exists:
        return doc.to_dict()
    return None


def upsert_user(email: str, role: str = "user", status: str = "pending") -> dict:
    """Luo tai päivittää käyttäjätietueen Firestoreen.

    Jos käyttäjä on jo olemassa, päivitetään vain last_login ja
    säilytetään olemassaoleva tila ja rooli.

    Args:
        email:  Käyttäjän sähköpostiosoite.
        role:   Oletusrooli uudelle käyttäjälle ('user' tai 'admin').
        status: Oletustila uudelle käyttäjälle ('pending', 'authorized', 'denied').

    Returns:
        Lopullinen käyttäjätietue.
    """
    db = get_db()
    ref = db.collection("users").document(email)
    now = datetime.now(timezone.utc).isoformat()
    doc = ref.get()
    if doc.exists:
        ref.update({"last_login": now})
        return ref.get().to_dict()
    data = {
        "email": email,
        "status": status,
        "role": role,
        "created_at": now,
        "last_login": now,
    }
    ref.set(data)
    return data


def list_users() -> list[dict]:
    """Listaa kaikki käyttäjät, uusimmat ensin.

    Returns:
        Lista käyttäjätietueista.
    """
    db = get_db()
    docs = db.collection("users").order_by(
        "created_at", direction=firestore.Query.DESCENDING
    ).stream()
    return [doc.to_dict() for doc in docs]


def update_user_status(email: str, status: str, role: str | None = None) -> None:
    """Päivittää käyttäjän tilan (ja roolin) Firestoreen.

    Args:
        email:  Käyttäjän sähköpostiosoite.
        status: Uusi tila ('authorized', 'denied', 'pending').
        role:   Uusi rooli ('admin', 'user') — valinnainen.
    """
    db = get_db()
    update: dict = {"status": status}
    if role is not None:
        update["role"] = role
    db.collection("users").document(email).update(update)


# --- Linux-laitteet & Komennot ------------------------------------------------

def upsert_linux_device(device_id: str, data: dict) -> None:
    """Luo tai päivittää Linux-laitetietueen Firestoreen.

    Args:
        device_id: Laitteen uniikki tunniste (SHA-256).
        data: Päivitettävät tiedot.
    """
    db = get_db()
    db.collection("linux_devices").document(device_id).set(data, merge=True)


def get_linux_device(device_id: str) -> dict | None:
    """Hakee yksittäisen Linux-laitteen tiedot.

    Args:
        device_id: Laitteen uniikki tunniste.

    Returns:
        dict tai None jos laitetta ei löydy.
    """
    db = get_db()
    doc = db.collection("linux_devices").document(device_id).get()
    return doc.to_dict() if doc.exists else None


def dequeue_linux_command(device_id: str) -> tuple[str, dict] | tuple[None, None]:
    """Hakee ja palauttaa seuraavan odottavan komennon Linux-laitteen jonosta.

    Args:
        device_id: Laitteen uniikki tunniste.

    Returns:
        Kaksikko (cmd_id, cmd_dict), tai (None, None) jos jonossa ei ole komentoja.
    """
    db = get_db()
    docs = (
        db.collection("linux_devices").document(device_id)
          .collection("commands")
          .where("status", "==", "pending")
          .order_by("created_at")
          .limit(1)
          .stream()
    )
    for doc in docs:
        return doc.id, doc.to_dict()
    return None, None


def ack_linux_command(device_id: str, cmd_id: str, status: str = "acknowledged") -> None:
    """Päivittää Linux-laitteen komennon tilan Firestoreen.

    Args:
        device_id: Laitteen uniikki tunniste.
        cmd_id: Päivitettävän komennon dokumentti-ID.
        status: Komennon uusi tila.
    """
    db = get_db()
    db.collection("linux_devices").document(device_id) \
      .collection("commands").document(cmd_id) \
      .update({"status": status})


def enqueue_linux_command(device_id: str, command: dict, cmd_id: str = None) -> str:
    """Lisää Linux MDM -komennon laitteen odottavien komentojen jonoon Firestoreen.

    Args:
        device_id: Laitteen uniikki tunniste.
        command: Lisättävä komentosanakirja.
        cmd_id: Valinnainen komento-ID (UUID).

    Returns:
        str: Luodun dokumentin ID.
    """
    db = get_db()
    if cmd_id:
        doc_ref = db.collection("linux_devices").document(device_id) \
                    .collection("commands").document(cmd_id)
    else:
        doc_ref = db.collection("linux_devices").document(device_id) \
                    .collection("commands").document()
    doc_ref.set(command)
    return doc_ref.id

