"""Firestore-yhteys. Tallentaa laitetiedot ja komennot."""
import os
from google.cloud import firestore

_db = None

def get_db() -> firestore.Client:
    global _db
    if _db is None:
        project = os.environ.get("GCP_PROJECT")
        _db = firestore.Client(project=project)
    return _db


# --- Laitteet ----------------------------------------------------------------

def upsert_device(udid: str, data: dict):
    """Luo tai päivittää laitetietueen Firestoreen."""
    db = get_db()
    db.collection("devices").document(udid).set(data, merge=True)


def get_device(udid: str) -> dict | None:
    db = get_db()
    doc = db.collection("devices").document(udid).get()
    return doc.to_dict() if doc.exists else None


def list_devices() -> list[dict]:
    db = get_db()
    return [{"udid": d.id, **d.to_dict()} for d in db.collection("devices").stream()]


# --- Komandojono -------------------------------------------------------------

def enqueue_command(udid: str, command: dict):
    """Lisää MDM-komennon laitteen jonoon."""
    db = get_db()
    db.collection("devices").document(udid) \
      .collection("commands").add(command)


def dequeue_command(udid: str) -> tuple[str, dict] | tuple[None, None]:
    """Palauttaa seuraavan odottavan komennon (FIFO) tai (None, None)."""
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


def ack_command(udid: str, cmd_id: str, status: str = "acknowledged"):
    db = get_db()
    db.collection("devices").document(udid) \
      .collection("commands").document(cmd_id) \
      .update({"status": status})
