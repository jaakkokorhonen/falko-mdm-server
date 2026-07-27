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
    mocker.patch("app.linux_common.get_linux_device", return_value=mock_device)
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
    mocker.patch("app.linux_common.get_linux_device", return_value=None)

    response = client.post(
        "/linux/checkin",
        json={"device_id": VALID_DEVICE_ID},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )
    assert response.status_code == 404


@pytest.mark.regression
def test_linux_checkin_token_mismatch(client, mocker, mock_device):
    """Token mismatch returns 401."""
    mocker.patch("app.linux_common.get_linux_device", return_value=mock_device)

    response = client.post(
        "/linux/checkin",
        json={"device_id": VALID_DEVICE_ID},
        headers={"Authorization": "Bearer wrong-token-value"},
    )
    assert response.status_code == 401


@pytest.mark.regression
def test_linux_checkin_invalid_device_id_format(client):
    """Invalid device_id format returns 400."""
    response = client.post(
        "/linux/checkin",
        json={"device_id": INVALID_DEVICE_ID},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )
    assert response.status_code == 400
    assert "device_id" in response.json.get("error", "")


from datetime import datetime, timezone, timedelta

@pytest.mark.regression
def test_linux_enroll_success(client, mocker):
    """Verify enrollment succeeds with a valid enrollment token."""
    mock_token_data = {
        "used": False,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    }
    
    class MockDoc:
        exists = True
        def to_dict(self):
            return mock_token_data
            
    class MockCollection:
        def document(self, token_hash):
            return MockDoc()
            
    class MockDB:
        def collection(self, name):
            return MockCollection()
            
    mocker.patch("app.linux_checkin.get_db", return_value=MockDB())
    mock_upsert = mocker.patch("app.linux_checkin.upsert_linux_device")

    payload = {
        "device_id": VALID_DEVICE_ID,
        "enrollment_token": "valid-token-123",
        "hostname": "test-workstation",
        "os": "Ubuntu 22.04 LTS"
    }

    response = client.post("/linux/enroll", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "enrolled"
    assert "device_token" in data
    mock_upsert.assert_called_once()


@pytest.mark.regression
def test_linux_enroll_already_used(client, mocker):
    """Verify enrollment fails if the enrollment token has already been used."""
    mock_token_data = {
        "used": True,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    }
    
    class MockDoc:
        exists = True
        def to_dict(self):
            return mock_token_data
            
    class MockCollection:
        def document(self, token_hash):
            return MockDoc()
            
    class MockDB:
        def collection(self, name):
            return MockCollection()
            
    mocker.patch("app.linux_checkin.get_db", return_value=MockDB())

    payload = {
        "device_id": VALID_DEVICE_ID,
        "enrollment_token": "already-used-token",
        "hostname": "test-workstation"
    }

    response = client.post("/linux/enroll", json=payload)
    assert response.status_code == 401
    assert "already used" in response.get_json()["error"]


@pytest.mark.regression
def test_linux_enroll_expired(client, mocker):
    """Verify enrollment fails if the enrollment token is expired."""
    mock_token_data = {
        "used": False,
        "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    }
    
    class MockDoc:
        exists = True
        def to_dict(self):
            return mock_token_data
            
    class MockCollection:
        def document(self, token_hash):
            return MockDoc()
            
    class MockDB:
        def collection(self, name):
            return MockCollection()
            
    mocker.patch("app.linux_checkin.get_db", return_value=MockDB())

    payload = {
        "device_id": VALID_DEVICE_ID,
        "enrollment_token": "expired-token",
        "hostname": "test-workstation"
    }

    response = client.post("/linux/enroll", json=payload)
    assert response.status_code == 401
    assert "expired" in response.get_json()["error"]


from app.linux_common import sign_command_payload

@pytest.mark.regression
def test_sign_command_payload_kms_error(mocker):
    """Verify that sign_command_payload raises RuntimeError if KMS client fails in production."""
    # Set KMS_KEY_PATH temporarily to simulate production
    mocker.patch("app.linux_common.KMS_KEY_PATH", "projects/p/locations/l/keyRings/k/cryptoKeys/key")
    
    # Mock KeyManagementServiceClient to raise an exception
    class MockKMSClient:
        def get_crypto_key(self, request):
            raise Exception("KMS unavailable")
            
    mocker.patch("google.cloud.kms.KeyManagementServiceClient", return_value=MockKMSClient())

    with pytest.raises(RuntimeError) as exc_info:
        sign_command_payload("dev-1", "cmd-1", "ShellCommand", {"command": "echo"})
    
    assert "Command signing unavailable" in str(exc_info.value)


