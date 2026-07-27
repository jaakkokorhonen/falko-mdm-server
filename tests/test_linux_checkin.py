"""Unit tests for Linux check-in endpoint (/linux/checkin)."""
from __future__ import annotations
import pytest
from app.linux_common import hash_token

# Valid device ID for testing (64-char hex)
VALID_DEVICE_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
INVALID_DEVICE_ID = "invalid-id"
VALID_TOKEN = "test-device-auth-token-12345678"
TOKEN_HASH = hash_token(VALID_TOKEN)


@pytest.fixture
def mock_device():
    return {
        "device_id": VALID_DEVICE_ID,
        "token_hash": TOKEN_HASH,
        "hostname": "test-workstation",
        "os": "Ubuntu 22.04 LTS",
    }


@pytest.mark.smoke
def test_linux_checkin_success(client, mocker, mock_device):
    """Verify checkin success when authorization and payload are valid."""
    mocker.patch("app.linux_checkin.get_linux_device", return_value=mock_device)
    mock_upsert = mocker.patch("app.linux_checkin.upsert_linux_device")

    payload = {
        "device_id": VALID_DEVICE_ID,
        "hostname": "test-workstation",
        "os": "Ubuntu 22.04 LTS",
        "kernel": "5.15.0-generic",
        "arch": "x86_64",
        "cpu": "Intel i7",
        "ram_gb": 16,
        "ip_local": "192.168.1.50",
        "agent_version": "0.1.0",
        "last_seen": "2026-07-27T16:00:00Z",
    }

    response = client.post(
        "/linux/checkin",
        json=payload,
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json == {"status": "acknowledged"}
    mock_upsert.assert_called_once_with(VALID_DEVICE_ID, mocker.ANY)


@pytest.mark.regression
def test_linux_checkin_missing_auth(client):
    """Missing Authorization header returns 401."""
    response = client.post("/linux/checkin", json={"device_id": VALID_DEVICE_ID})
    assert response.status_code == 401
    assert "token" in response.json["message"]


@pytest.mark.regression
def test_linux_checkin_invalid_auth_prefix(client):
    """Auth header not starting with 'Bearer ' returns 401."""
    response = client.post(
        "/linux/checkin",
        json={"device_id": VALID_DEVICE_ID},
        headers={"Authorization": f"Basic {VALID_TOKEN}"},
    )
    assert response.status_code == 401


@pytest.mark.regression
def test_linux_checkin_device_not_enrolled(client, mocker):
    """If device is not found in DB, return 404."""
    mocker.patch("app.linux_checkin.get_linux_device", return_value=None)

    response = client.post(
        "/linux/checkin",
        json={"device_id": VALID_DEVICE_ID},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )
    assert response.status_code == 404
    assert "not enrolled" in response.json["message"]


@pytest.mark.regression
def test_linux_checkin_token_mismatch(client, mocker, mock_device):
    """Token mismatch returns 401."""
    mocker.patch("app.linux_checkin.get_linux_device", return_value=mock_device)

    response = client.post(
        "/linux/checkin",
        json={"device_id": VALID_DEVICE_ID},
        headers={"Authorization": "Bearer wrong-token-value"},
    )
    assert response.status_code == 401
    assert "Unauthorized" in response.json["message"]


@pytest.mark.regression
def test_linux_checkin_invalid_device_id_format(client):
    """Invalid device_id format returns 400."""
    response = client.post(
        "/linux/checkin",
        json={"device_id": INVALID_DEVICE_ID},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )
    assert response.status_code == 400
    assert "device_id" in response.json["message"]
