"""Testit Apple MDM Check-In -endpointille (/checkin).

Kattaa:
  - healthz smoke
  - TokenUpdate: onnistuminen, puuttuvat kentät
  - Authenticate: onnistuminen, virheellinen payload
  - CheckOut: onnistuminen (idempotent)
  - Tuntematon MessageType: hyväksytään hiljaa (Apple-spesifikaatio)
  - Plist-parsevirhe: palautetaan 400
  - Puuttuva tai virheellinen UDID: palautetaan 400
"""
import plistlib
import pytest


# ---------------------------------------------------------------------------
# Apufunktio: rakennetaan validi Check-In plist
# ---------------------------------------------------------------------------

def _make_plist(data: dict) -> bytes:
    return plistlib.dumps(data, fmt=plistlib.FMT_XML)


VALID_UDID = "AABBCCDD-1122-3344-5566-778899AABBCC"


# ---------------------------------------------------------------------------
# Smoke
# ---------------------------------------------------------------------------

@pytest.mark.smoke
def test_healthz(client):
    """GET /healthz palauttaa 200 OK."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}


# ---------------------------------------------------------------------------
# Plist-parsevirhe
# ---------------------------------------------------------------------------

@pytest.mark.smoke
def test_checkin_missing_body_returns_400(client):
    """POST /checkin ilman dataa: 400."""
    response = client.post("/checkin")
    assert response.status_code == 400
    assert "error" in response.json


@pytest.mark.regression
def test_checkin_invalid_plist_returns_400(client):
    """POST /checkin epäkelvolla XML:llä: 400."""
    response = client.post("/checkin", data=b"<not-a-plist>", content_type="application/xml")
    assert response.status_code == 400
    assert "error" in response.json


# ---------------------------------------------------------------------------
# UDID-validointi
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_checkin_missing_udid_returns_400(client):
    """Puuttuva UDID-kenttä: 400."""
    payload = _make_plist({"MessageType": "TokenUpdate"})
    response = client.post("/checkin", data=payload, content_type="application/xml")
    assert response.status_code == 400


@pytest.mark.regression
def test_checkin_invalid_udid_returns_400(client):
    """Virheellinen UDID (sisältää erikoismerkkejä): 400."""
    payload = _make_plist({"MessageType": "TokenUpdate", "UDID": "../../../etc/passwd"})
    response = client.post("/checkin", data=payload, content_type="application/xml")
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# TokenUpdate
# ---------------------------------------------------------------------------

@pytest.mark.smoke
def test_checkin_token_update_success(client, mocker):
    """Validi TokenUpdate tallentaa push-tiedot ja palauttaa 200."""
    mock_upsert = mocker.patch("app.checkin.upsert_device")
    payload = _make_plist({
        "MessageType": "TokenUpdate",
        "UDID": VALID_UDID,
        "Token": b"\xde\xad\xbe\xef" * 8,
        "PushMagic": "test-magic",
        "Topic": "com.apple.mgmt.External.test",
    })
    response = client.post("/checkin", data=payload, content_type="application/xml")
    assert response.status_code == 200
    mock_upsert.assert_called_once()
    call_data = mock_upsert.call_args[0][1]
    assert call_data["status"] == "enrolled"
    assert "push_token" in call_data
    assert call_data["push_magic"] == "test-magic"
    assert call_data["topic"] == "com.apple.mgmt.External.test"


@pytest.mark.regression
def test_checkin_token_update_missing_push_magic(client, mocker):
    """TokenUpdate ilman PushMagic: endpoint hyväksyy (kenttä tallentuu tyhjänä)."""
    mocker.patch("app.checkin.upsert_device")
    payload = _make_plist({
        "MessageType": "TokenUpdate",
        "UDID": VALID_UDID,
        "Token": b"\x00" * 32,
        # PushMagic puuttuu
        "Topic": "com.apple.mgmt.External.test",
    })
    response = client.post("/checkin", data=payload, content_type="application/xml")
    # Endpoint palauttaa 200 — puuttuva kenttä tallentuu tyhjänä (Apple-yhteensopivuus)
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Authenticate
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_checkin_authenticate_success(client, mocker):
    """Validi Authenticate tallentaa perustiedot ja palauttaa 200."""
    mock_upsert = mocker.patch("app.checkin.upsert_device")
    payload = _make_plist({
        "MessageType": "Authenticate",
        "UDID": VALID_UDID,
        "SerialNumber": "C02XG2JHQ6GH",
        "OSVersion": "14.5",
        "ProductName": "MacBookPro18,2",
    })
    response = client.post("/checkin", data=payload, content_type="application/xml")
    assert response.status_code == 200
    mock_upsert.assert_called_once()
    call_data = mock_upsert.call_args[0][1]
    assert call_data["status"] == "authenticating"
    assert call_data["udid"] == VALID_UDID


@pytest.mark.regression
def test_checkin_authenticate_minimal_payload(client, mocker):
    """Authenticate ilman valinnaisia kenttiä: tallentuu tyhjillä arvoilla."""
    mocker.patch("app.checkin.upsert_device")
    payload = _make_plist({
        "MessageType": "Authenticate",
        "UDID": VALID_UDID,
    })
    response = client.post("/checkin", data=payload, content_type="application/xml")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# CheckOut
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_checkin_checkout_success(client, mocker):
    """Validi CheckOut merkitsee laitteen unenrolled-tilaan ja palauttaa 200."""
    mock_upsert = mocker.patch("app.checkin.upsert_device")
    payload = _make_plist({
        "MessageType": "CheckOut",
        "UDID": VALID_UDID,
    })
    response = client.post("/checkin", data=payload, content_type="application/xml")
    assert response.status_code == 200
    call_data = mock_upsert.call_args[0][1]
    assert call_data["status"] == "unenrolled"
    assert "unenrolled_at" in call_data


@pytest.mark.regression
def test_checkin_checkout_idempotent(client, mocker):
    """CheckOut toistettuna ei nosta poikkeusta (idempotent)."""
    mocker.patch("app.checkin.upsert_device")
    payload = _make_plist({"MessageType": "CheckOut", "UDID": VALID_UDID})
    r1 = client.post("/checkin", data=payload, content_type="application/xml")
    r2 = client.post("/checkin", data=payload, content_type="application/xml")
    assert r1.status_code == 200
    assert r2.status_code == 200


# ---------------------------------------------------------------------------
# Tuntematon MessageType
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_checkin_unknown_message_type_returns_200(client, mocker):
    """Tuntematon MessageType: Apple-spesifikaation mukaan palautetaan 200."""
    mocker.patch("app.checkin.upsert_device")
    payload = _make_plist({
        "MessageType": "FutureUnknownType",
        "UDID": VALID_UDID,
    })
    response = client.post("/checkin", data=payload, content_type="application/xml")
    assert response.status_code == 200
