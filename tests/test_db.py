"""Yksikkötestit app/db.py -moduulille.

Kaikki Firestore-kutsut on mockattu — testit eivät vaadi ulkoista tietokantaa.
Testaa käyttäytymistä, ei Firestore-kutsujen sisäistä rakennetta.
"""
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Apufunktiot
# ---------------------------------------------------------------------------

def _mock_doc(exists=True, data=None, doc_id="test-id"):
    doc = MagicMock()
    doc.exists = exists
    doc.id = doc_id
    doc.to_dict.return_value = data or {}
    return doc


# ---------------------------------------------------------------------------
# upsert_device
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_upsert_device_calls_set_with_merge(mocker):
    """upsert_device kutsuu Firestore set(merge=True)."""
    mock_db = mocker.patch("app.db.get_db")
    mock_col = MagicMock()
    mock_db.return_value.collection.return_value = mock_col
    mock_doc_ref = MagicMock()
    mock_col.document.return_value = mock_doc_ref

    from app.db import upsert_device
    upsert_device("TEST-UDID-123", {"status": "enrolled"})

    mock_doc_ref.set.assert_called_once_with({"status": "enrolled"}, merge=True)


# ---------------------------------------------------------------------------
# get_device
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_get_device_returns_dict_when_exists(mocker):
    """get_device palauttaa dict kun dokumentti on olemassa."""
    mock_db = mocker.patch("app.db.get_db")
    doc = _mock_doc(exists=True, data={"udid": "ABC", "status": "enrolled"})
    mock_db.return_value.collection.return_value.document.return_value.get.return_value = doc

    from app.db import get_device
    result = get_device("ABC")
    assert result == {"udid": "ABC", "status": "enrolled"}


@pytest.mark.regression
def test_get_device_returns_none_when_missing(mocker):
    """get_device palauttaa None kun laitetta ei löydy."""
    mock_db = mocker.patch("app.db.get_db")
    doc = _mock_doc(exists=False)
    mock_db.return_value.collection.return_value.document.return_value.get.return_value = doc

    from app.db import get_device
    result = get_device("MISSING-UDID")
    assert result is None


# ---------------------------------------------------------------------------
# list_devices — sivutus
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_list_devices_returns_devices_and_no_cursor_when_fewer_than_page_size(mocker):
    """list_devices palauttaa (devices, None) kun tuloksia on vähemmän kuin page_size."""
    mock_db = mocker.patch("app.db.get_db")
    docs = [_mock_doc(data={"status": "enrolled"}, doc_id=f"dev-{i}") for i in range(3)]
    query_mock = MagicMock()
    query_mock.stream.return_value = iter(docs)
    mock_db.return_value.collection.return_value.order_by.return_value.limit.return_value = query_mock

    from app.db import list_devices
    devices, cursor = list_devices(page_size=10)
    assert len(devices) == 3
    assert cursor is None  # alle page_size -> ei seuraavaa sivua


@pytest.mark.regression
def test_list_devices_returns_cursor_when_full_page(mocker):
    """list_devices palauttaa next_cursor kun sivu on täynnä."""
    mock_db = mocker.patch("app.db.get_db")
    docs = [_mock_doc(data={"status": "enrolled"}, doc_id=f"dev-{i}") for i in range(5)]
    query_mock = MagicMock()
    query_mock.stream.return_value = iter(docs)
    mock_db.return_value.collection.return_value.order_by.return_value.limit.return_value = query_mock

    from app.db import list_devices
    devices, cursor = list_devices(page_size=5)
    assert len(devices) == 5
    assert cursor == "dev-4"  # viimeisen dokumentin ID


# ---------------------------------------------------------------------------
# enqueue / dequeue / ack_command
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_enqueue_command_calls_add(mocker):
    """enqueue_command lisää komennon subkokoelmaan."""
    mock_db = mocker.patch("app.db.get_db")
    mock_subcol = MagicMock()
    mock_db.return_value.collection.return_value.document.return_value \
        .collection.return_value = mock_subcol

    from app.db import enqueue_command
    enqueue_command("TEST-UDID", {"command_type": "DeviceLock", "status": "pending"})
    mock_subcol.add.assert_called_once()


@pytest.mark.regression
def test_dequeue_command_returns_first_pending(mocker):
    """dequeue_command palauttaa ensimmäisen pending-komennon."""
    mock_db = mocker.patch("app.db.get_db")
    cmd_doc = _mock_doc(data={"command_type": "DeviceLock", "status": "pending"}, doc_id="cmd-1")
    # Rakennetaan kysely-mock ketjutetusti
    query = MagicMock()
    query.stream.return_value = iter([cmd_doc])
    (
        mock_db.return_value
        .collection.return_value
        .document.return_value
        .collection.return_value
        .where.return_value
        .order_by.return_value
        .limit.return_value
    ) = query

    from app.db import dequeue_command
    cmd_id, cmd = dequeue_command("TEST-UDID")
    assert cmd_id == "cmd-1"
    assert cmd["command_type"] == "DeviceLock"


@pytest.mark.regression
def test_dequeue_command_returns_none_when_empty(mocker):
    """dequeue_command palauttaa (None, None) kun jonossa ei ole komentoja."""
    mock_db = mocker.patch("app.db.get_db")
    query = MagicMock()
    query.stream.return_value = iter([])  # tyhjä jono
    (
        mock_db.return_value
        .collection.return_value
        .document.return_value
        .collection.return_value
        .where.return_value
        .order_by.return_value
        .limit.return_value
    ) = query

    from app.db import dequeue_command
    cmd_id, cmd = dequeue_command("TEST-UDID")
    assert cmd_id is None
    assert cmd is None


@pytest.mark.regression
def test_ack_command_updates_status(mocker):
    """ack_command päivittää komennon tilan Firestoreen."""
    mock_db = mocker.patch("app.db.get_db")
    mock_doc_ref = MagicMock()
    (
        mock_db.return_value
        .collection.return_value
        .document.return_value
        .collection.return_value
        .document.return_value
    ) = mock_doc_ref

    from app.db import ack_command
    ack_command("TEST-UDID", "cmd-1", "acknowledged")
    mock_doc_ref.update.assert_called_once_with({"status": "acknowledged"})


# ---------------------------------------------------------------------------
# get_user / upsert_user / update_user_status
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_get_user_returns_dict_when_exists(mocker):
    """get_user palauttaa käyttäjätietueen."""
    mock_db = mocker.patch("app.db.get_db")
    doc = _mock_doc(exists=True, data={"email": "u@test.fi", "status": "authorized"})
    mock_db.return_value.collection.return_value.document.return_value.get.return_value = doc

    from app.db import get_user
    result = get_user("u@test.fi")
    assert result["status"] == "authorized"


@pytest.mark.regression
def test_get_user_returns_none_when_missing(mocker):
    """get_user palauttaa None kun käyttäjää ei löydy."""
    mock_db = mocker.patch("app.db.get_db")
    doc = _mock_doc(exists=False)
    mock_db.return_value.collection.return_value.document.return_value.get.return_value = doc

    from app.db import get_user
    assert get_user("nobody@test.fi") is None


@pytest.mark.regression
def test_upsert_user_creates_new_user(mocker):
    """upsert_user luo uuden käyttäjätietueen jos sitä ei ole."""
    mock_db = mocker.patch("app.db.get_db")
    doc = _mock_doc(exists=False)
    ref_mock = MagicMock()
    ref_mock.get.return_value = doc
    mock_db.return_value.collection.return_value.document.return_value = ref_mock

    from app.db import upsert_user
    result = upsert_user("new@test.fi", role="user", status="pending")
    ref_mock.set.assert_called_once()
    assert result["email"] == "new@test.fi"
    assert result["status"] == "pending"


@pytest.mark.regression
def test_upsert_user_updates_last_login_for_existing(mocker):
    """upsert_user päivittää last_login olemassaolevalle käyttäjälle."""
    mock_db = mocker.patch("app.db.get_db")
    existing = {"email": "old@test.fi", "status": "authorized", "role": "user",
                "created_at": "2026-01-01T00:00:00+00:00", "last_login": "2026-01-01T00:00:00+00:00"}
    doc_exists = _mock_doc(exists=True, data=existing)
    doc_updated = _mock_doc(exists=True, data={**existing, "last_login": "2026-07-22T00:00:00+00:00"})
    ref_mock = MagicMock()
    ref_mock.get.side_effect = [doc_exists, doc_updated]
    mock_db.return_value.collection.return_value.document.return_value = ref_mock

    from app.db import upsert_user
    result = upsert_user("old@test.fi")
    ref_mock.update.assert_called_once()
    assert "last_login" in ref_mock.update.call_args[0][0]


@pytest.mark.regression
def test_update_user_status_updates_status_field(mocker):
    """update_user_status päivittää status-kentän."""
    mock_db = mocker.patch("app.db.get_db")
    doc_ref = MagicMock()
    mock_db.return_value.collection.return_value.document.return_value = doc_ref

    from app.db import update_user_status
    update_user_status("u@test.fi", "authorized")
    doc_ref.update.assert_called_once_with({"status": "authorized"})


@pytest.mark.regression
def test_update_user_status_with_role(mocker):
    """update_user_status päivittää myös roolin kun se annetaan."""
    mock_db = mocker.patch("app.db.get_db")
    doc_ref = MagicMock()
    mock_db.return_value.collection.return_value.document.return_value = doc_ref

    from app.db import update_user_status
    update_user_status("u@test.fi", "authorized", role="admin")
    doc_ref.update.assert_called_once_with({"status": "authorized", "role": "admin"})
