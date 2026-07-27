"""Unit tests for Linux MDM command poll endpoint (/linux/mdm/<device_id>)."""
from __future__ import annotations
import pytest
from app.linux_common import hash_token

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
    }


@pytest.mark.smoke
def test_linux_mdm_poll_no_command(client, mocker, mock_device):
    """Verify polling succeeds and returns empty command if none pending."""
    mocker.patch("app.linux_common.get_linux_device", return_value=mock_device)
    mocker.patch("app.linux_mdm.upsert_linux_device")
    mocker.patch("app.linux_mdm.dequeue_linux_command", return_value=(None, None))

    response = client.put(
        f"/linux/mdm/{VALID_DEVICE_ID}",
        json={},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json["command"] is None
    assert response.json["server_meta"]["latest_agent_version"] == "0.1.0"


@pytest.mark.regression
def test_linux_mdm_poll_with_pending_command(client, mocker, mock_device):
    """Verify pending command is fetched and returned to client agent."""
    mocker.patch("app.linux_common.get_linux_device", return_value=mock_device)
    mocker.patch("app.linux_mdm.upsert_linux_device")

    cmd_payload = {"type": "ShellCommand", "payload": {"command": "echo 'Hello'"}}
    mocker.patch(
        "app.linux_mdm.dequeue_linux_command", return_value=("cmd-123", cmd_payload)
    )

    response = client.put(
        f"/linux/mdm/{VALID_DEVICE_ID}",
        json={},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json["command"] == {
        "id": "cmd-123",
        "type": "ShellCommand",
        "payload": {"command": "echo 'Hello'"},
    }


@pytest.mark.regression
def test_linux_mdm_poll_with_acknowledgement(client, mocker, mock_device):
    """Verify last command result is acknowledged in database."""
    mocker.patch("app.linux_common.get_linux_device", return_value=mock_device)
    mocker.patch("app.linux_mdm.upsert_linux_device")
    mocker.patch("app.linux_mdm.dequeue_linux_command", return_value=(None, None))
    mock_ack = mocker.patch("app.linux_mdm.ack_linux_command")

    result_payload = {
        "result": {
            "command_id": "cmd-123",
            "status": {"status": "acknowledged", "exit_code": 0, "output": "success"},
        }
    }

    response = client.put(
        f"/linux/mdm/{VALID_DEVICE_ID}",
        json=result_payload,
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )

    assert response.status_code == 200
    mock_ack.assert_called_once_with(VALID_DEVICE_ID, "cmd-123", "acknowledged")


@pytest.mark.regression
def test_linux_mdm_poll_unauthorized(client, mocker, mock_device):
    """Poll with incorrect token returns 401."""
    mocker.patch("app.linux_common.get_linux_device", return_value=mock_device)

    response = client.put(
        f"/linux/mdm/{VALID_DEVICE_ID}",
        json={},
        headers={"Authorization": "Bearer incorrect-token"},
    )

    assert response.status_code == 401


@pytest.mark.regression
def test_linux_mdm_poll_invalid_device_id_format(client):
    """Poll with malformed device ID format returns 400."""
    response = client.put(
        f"/linux/mdm/{INVALID_DEVICE_ID}",
        json={},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )

    assert response.status_code == 400
