"""Firestore-abstraktio. Tallentaa laitetiedot ja MDM-komantojono.

Rakenne Firestoressä:
  devices/{udid}                    — laitetietue (malli, OS, tila, APNs-tiedot)
  devices/{udid}/commands/{cmd_id}  — MDM-komanto (status: pending | sent | acknowledged | error)

Kaikki tietokantakutsut kulkevat tämän moduulin kautta —
älä kutsu Firestorea suoraan muista moduuleista.
"""
import os
from google.cloud import firestore

# Moduulitason singleton — Firestore-asiakas alustetaan kerran per prosessi.
# Cloud Runissa jokainen instanssi saa oman prosessinsa, joten tämä on turvallista.
_db = None


def get_db() -> firestore.Client:
    """Palauttaa Firestore-asiakkaan, alustaa sen tarvittaessa.

    Käyttää lazy-alustusta: yhteys avataan vasta ensimmäisellä kutsulla
    eikä sovelluksen käynnistyksessä. Tämä nopeuttaa cold startia.

    Returns:
        Alustettu Firestore-asiakasinstanssi.
    """
    global _db
    if _db is None:
        project = os.environ.get("GCP_PROJECT")
        # GCP_PROJECT voidaan jättää pois Cloud Runissa — SDK päättelee sen
        # automaattisesti metatietopalvelusta. Paikallisessa ajossa vaaditaan.
        _db = firestore.Client(project=project)
    return _db


# --- Laitteet ----------------------------------------------------------------

def upsert_device(udid: str, data: dict) -> None:
    """Luo tai päivittää laitetietueen Firestoreen.

    Käyttää merge=True jotta osapäivitykset (esim. vain push_token)
    eivät ylikirjoita muita kentät.

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


def list_devices() -> list[dict]:
    """Palauttaa kaikki laitteet listana.

    Lisää 'udid'-kentän dokumentin ID:stä, koska se ei ole automaattisesti
    mukana Firestore-dokumentin datassa.

    Returns:
        Lista laitetietueista, joissa mukana 'udid'-avain.

    NOTE: Ei sivutusta — hakee kaikki kerralla. Riittää kymmenille laitteille;
    laajemmassa käytössä lisää .limit() + sivutus.
    """
    db = get_db()
    return [{"udid": d.id, **d.to_dict()} for d in db.collection("devices").stream()]


# --- Komentojono -------------------------------------------------------------


def enqueue_command(udid: str, command: dict) -> None:
    """Lisää Apple MDM -komennon laitteen odottavien komentojen jonoon Firestoreen.

    Args:
        udid: Laitteen uniikki UDID-tunniste.
        command: Lisättävä komentosanakirja, joka sisältää command_type:n, tilan jne.
    """
    db = get_db()
    db.collection("devices").document(udid) \
      .collection("commands").add(command)


def dequeue_command(udid: str) -> tuple[str, dict] | tuple[None, None]:
    """Hakee ja palauttaa seuraavan odottavan komennon laitteen jonosta (FIFO).

    Args:
        udid: Laitteen uniikki UDID-tunniste.

    Returns:
        Kaksikko (tuple), jossa on komennon dokumentti-ID ja komennon tiedot dictinä,
        tai (None, None) jos odottavia komentoja ei ole.
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
        udid: Laitteen uniikki UDID-tunniste.
        cmd_id: Päivitettävän komennon dokumentti-ID.
        status: Komennon uusi tila (esim. 'sent', 'acknowledged', 'error').
    """
    db = get_db()
    db.collection("devices").document(udid) \
      .collection("commands").document(cmd_id) \
      .update({"status": status})

