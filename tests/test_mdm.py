"""Testit Apple MDM Command -endpointille (/mdm PUT).

Kattaa:
  - GET /mdm hylätään 405
  - validi PUT tyhjällä jonolla: 200 tyhjä
  - validi PUT jossa jono sisältää komennon: 200 + plist
  - komennon kuittaus (Status=Acknowledged)
  - virheellinen UDID: 400
  - plist-parsevirhe: 400
  - komennon payload-muodostus oikein
"""
import plistlib
import pytest


# ---------------------------------------------------------------------------
# Apufunktio
# ---------------------------------------------------------------------------

def _make_plist(data: dict) -> bytes:
    return plistlib.dumps(data, fmt=plistlib.FMT_XML)


VALID_UDID = "AABBCCDD-1122-3344-5566-778899AABBCC"


# ---------------------------------------------------------------------------
# HTTP-metodin validointi
# ---------------------------------------------------------------------------

@pytest.mark.smoke
def test_mdm_endpoint_get_rejected(client):
    """GET /mdm ei ole sallittu: 405."""
    response = client.get("/mdm")
    assert response.status_code == 405


# ---------------------------------------------------------------------------
# Tyhjä jono
# ---------------------------------------------------------------------------

@pytest.mark.smoke
def test_mdm_put_empty_queue_returns_200_empty(client, mocker):
    """PUT /mdm ilman jonossa olevia komentoja: 200 tyhjä vastaus."""
    mocker.patch("app.mdm.dequeue_command", return_value=(None, None))
    mocker.patch("app.mdm.ack_command")
    payload = _make_plist({"UDID": VALID_UDID, "Status": ""})
    response = client.put("/mdm", data=payload, content_type="application/xml")
    assert response.status_code == 200
    assert response.data == b""


# ---------------------------------------------------------------------------
# Jono sisältää komennon
# ---------------------------------------------------------------------------

@pytest.mark.smoke
def test_mdm_put_returns_command_plist(client, mocker):
    """PUT /mdm kun jonossa on DeviceLock-komento: palautetaan plist."""
    mocker.patch("app.mdm.dequeue_command", return_value=("cmd-1", {
        "command_type": "DeviceLock",
        "payload": {"PIN": "123456"},
    }))
    mock_ack = mocker.patch("app.mdm.ack_command")
    payload = _make_plist({"UDID": VALID_UDID, "Status": ""})
    response = client.put("/mdm", data=payload, content_type="application/xml")
    assert response.status_code == 200
    # Vastaus on XML plist
    parsed = plistlib.loads(response.data)
    assert parsed["Command"]["RequestType"] == "DeviceLock"
    assert "CommandUUID" in parsed
    # Komento merkitty sent-tilaan
    mock_ack.assert_called_with(VALID_UDID, "cmd-1", "sent")


@pytest.mark.regression
def test_mdm_put_command_uuid_matches(client, mocker):
    """Palautetun plistin CommandUUID vastaa jonon cmd_id:tä."""
    mocker.patch("app.mdm.dequeue_command", return_value=("uuid-xyz", {
        "command_type": "DeviceInformation",
        "payload": {},
    }))
    mocker.patch("app.mdm.ack_command")
    payload = _make_plist({"UDID": VALID_UDID, "Status": ""})
    response = client.put("/mdm", data=payload, content_type="application/xml")
    parsed = plistlib.loads(response.data)
    assert parsed["CommandUUID"] == "uuid-xyz"


# ---------------------------------------------------------------------------
# Komennon kuittaus
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_mdm_put_acknowledges_previous_command(client, mocker):
    """PUT /mdm jossa Status=Acknowledged kuittaa edellisen komennon."""
    mocker.patch("app.mdm.dequeue_command", return_value=(None, None))
    mock_ack = mocker.patch("app.mdm.ack_command")
    payload = _make_plist({
        "UDID": VALID_UDID,
        "Status": "Acknowledged",
        "CommandUUID": "prev-cmd-id",
    })
    response = client.put("/mdm", data=payload, content_type="application/xml")
    assert response.status_code == 200
    # Ensimmäinen ack-kutsu on edellisen komennon kuittaus
    ack_calls = mock_ack.call_args_list
    acked = [(c.args[1], c.args[2]) for c in ack_calls]
    assert ("prev-cmd-id", "acknowledged") in acked


@pytest.mark.regression
def test_mdm_put_error_status_acks_as_error(client, mocker):
    """Status=Error kuittaa komennon error-tilaan."""
    mocker.patch("app.mdm.dequeue_command", return_value=(None, None))
    mock_ack = mocker.patch("app.mdm.ack_command")
    payload = _make_plist({
        "UDID": VALID_UDID,
        "Status": "Error",
        "CommandUUID": "err-cmd-id",
    })
    client.put("/mdm", data=payload, content_type="application/xml")
    acked = [(c.args[1], c.args[2]) for c in mock_ack.call_args_list]
    assert ("err-cmd-id", "error") in acked


# ---------------------------------------------------------------------------
# Virhetilanteet
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_mdm_put_invalid_udid_returns_400(client, mocker):
    """Virheellinen UDID: 400."""
    mocker.patch("app.mdm.dequeue_command", return_value=(None, None))
    payload = _make_plist({"UDID": "../evil", "Status": ""})
    response = client.put("/mdm", data=payload, content_type="application/xml")
    assert response.status_code == 400


@pytest.mark.regression
def test_mdm_put_missing_udid_returns_400(client, mocker):
    """Puuttuva UDID: 400."""
    mocker.patch("app.mdm.dequeue_command", return_value=(None, None))
    payload = _make_plist({"Status": ""})
    response = client.put("/mdm", data=payload, content_type="application/xml")
    assert response.status_code == 400


@pytest.mark.regression
def test_mdm_put_invalid_plist_returns_400(client):
    """Epäkelpo plist: 400."""
    response = client.put("/mdm", data=b"garbage", content_type="application/xml")
    assert response.status_code == 400
