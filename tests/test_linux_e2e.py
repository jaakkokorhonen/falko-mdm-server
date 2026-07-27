"""End-to-End integration tests for Linux MDM (enroll -> check-in -> command -> signature verification -> ack)."""
import json
import base64
import unicodedata
import uuid
import os
import sqlite3
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

import app.db as db
import app.linux_common as linux_common
from agent.agent import verify_command_signature, is_command_replay

os.environ["FALKO_TEST_MODE"] = "1"

from cryptography.hazmat.primitives.serialization import load_pem_private_key

PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
PUBLIC_PEM = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')


OTHER_KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_PUBLIC_PEM = OTHER_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')


def e2e_sign_command(device_id: str, command_id: str, command_type: str, payload: dict) -> str:
    data_dict = {
        "device_id": device_id,
        "command_id": command_id,
        "command_type": command_type,
        "payload": payload
    }
    serialized = json.dumps(data_dict, sort_keys=True, separators=(',', ':'))
    normalized = unicodedata.normalize('NFC', serialized).encode('utf-8')
    signature = PRIVATE_KEY.sign(normalized, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')


@pytest.fixture
def clean_sqlite_db(tmp_path):
    """Temporary SQLite database for seen commands."""
    db_file = tmp_path / "seen_commands.db"
    old_env = os.environ.get("FALKO_DB_PATH")
    os.environ["FALKO_DB_PATH"] = str(db_file)
    yield str(db_file)
    if old_env:
        os.environ["FALKO_DB_PATH"] = old_env
    else:
        os.environ.pop("FALKO_DB_PATH", None)


@pytest.mark.regression
def test_linux_e2e_flow(client, clean_sqlite_db, mocker):
    device_id = "a" * 64
    raw_token = "e2e-super-secret-enroll-token"
    token_hash = linux_common.hash_token(raw_token)

    # Mock DB storage for testing without live Firestore
    device_store = {}
    commands_store = []

    def mock_get_linux_device(did):
        return device_store.get(did)

    def mock_upsert_linux_device(did, data):
        if did not in device_store:
            device_store[did] = {}
        device_store[did].update(data)

    def mock_enqueue_linux_command(did, cmd, cmd_id):
        cmd["id"] = cmd_id
        commands_store.append(cmd)
        return cmd_id

    def mock_dequeue_linux_command(did):
        for cmd in commands_store:
            if cmd.get("status") == "pending":
                return cmd["id"], cmd
        return None, None

    def mock_ack_linux_command(did, cmd_id, status="acknowledged"):
        for cmd in commands_store:
            if cmd["id"] == cmd_id:
                cmd["status"] = status

    # Setup mocker patches instead of decorator @patch
    mocker.patch("app.linux_common.get_linux_device", side_effect=mock_get_linux_device)
    mocker.patch("app.linux_checkin.get_linux_device", side_effect=mock_get_linux_device)
    mocker.patch("app.linux_checkin.upsert_linux_device", side_effect=mock_upsert_linux_device)
    mocker.patch("app.linux_mdm.dequeue_linux_command", side_effect=mock_dequeue_linux_command)
    mocker.patch("app.linux_mdm.ack_linux_command", side_effect=mock_ack_linux_command)
    mocker.patch("app.linux_mdm.upsert_linux_device", side_effect=mock_upsert_linux_device)
    mocker.patch("app.admin.get_linux_device", side_effect=mock_get_linux_device)
    mocker.patch("app.admin.enqueue_linux_command", side_effect=mock_enqueue_linux_command)

    # 1. Enroll the device via checkin route
    enroll_payload = {
        "device_id": device_id,
        "hostname": "e2e-workstation",
        "os": "Ubuntu 24.04",
        "kernel": "6.8.0-generic",
        "arch": "x86_64",
        "ram_gb": 16,
    }
    # Enrolling first registers the device and sets the token_hash
    # To bypass checkin validation and simulate enrollment:
    mock_upsert_linux_device(device_id, {"device_id": device_id, "token_hash": token_hash})

    # Call check-in to verify it succeeds with Bearer token
    headers = {"Authorization": f"Bearer {raw_token}"}
    resp = client.post("/linux/checkin", json=enroll_payload, headers=headers)
    assert resp.status_code == 200
    assert mock_get_linux_device(device_id) is not None
    assert mock_get_linux_device(device_id)["token_hash"] == token_hash

    # 2. Enqueue command via admin (signed)
    cmd_id = str(uuid.uuid4())
    cmd_type = "ShellCommand"
    cmd_payload = {"command": "echo 'e2e test'"}
    
    # Sign the command using the private key
    sig = e2e_sign_command(device_id, cmd_id, cmd_type, cmd_payload)
    
    cmd_doc = {
        "type": cmd_type,
        "payload": cmd_payload,
        "status": "pending",
        "signature": sig,
        "key_version": "v1"
    }
    mock_enqueue_linux_command(device_id, cmd_doc, cmd_id)

    # 3. Poll command (acting as agent)
    poll_resp = client.put(f"/linux/mdm/{device_id}", json={}, headers=headers)
    assert poll_resp.status_code == 200
    data = poll_resp.get_json()
    command = data.get("command")
    assert command is not None
    assert command["id"] == cmd_id
    assert command["signature"] == sig

    # 4. Agent verification (Signature verification & Replay protection)
    # Verify signature (positive case)
    assert verify_command_signature(device_id, command, PUBLIC_PEM) is True
    
    # Verify signature (negative case: altered signature)
    bad_signature_cmd = {**command, "signature": "altered-sig-value"}
    assert verify_command_signature(device_id, bad_signature_cmd, PUBLIC_PEM) is False

    # Verify signature (negative case: wrong public key)
    assert verify_command_signature(device_id, command, OTHER_PUBLIC_PEM) is False

    # Verify replay detection (first time false, second time true)
    assert is_command_replay(cmd_id) is False
    assert is_command_replay(cmd_id) is True

    # 5. Agent sends ACK
    ack_payload = {
        "result": {
            "command_id": cmd_id,
            "status": {
                "status": "acknowledged",
                "output": "e2e test",
                "exit_code": 0
            }
        }
    }
    ack_resp = client.put(f"/linux/mdm/{device_id}", json=ack_payload, headers=headers)
    assert ack_resp.status_code == 200
    
    # Check command status in DB is acknowledged
    assert commands_store[0]["status"] == "acknowledged"


from datetime import datetime, timezone, timedelta

@pytest.mark.regression
def test_linux_token_rotation_and_shell_policy(client, clean_sqlite_db, mocker):
    device_id = "b" * 64
    raw_token = "original-secret-token"
    token_hash = linux_common.hash_token(raw_token)

    # Store mocked device data
    device_store = {
        device_id: {
            "device_id": device_id,
            "token_hash": token_hash,
            "token_issued_at": datetime.now(timezone.utc) - timedelta(days=31),
            "shell_command_enabled": False
        }
    }

    settings_store = {
        "shell_command_policy": {
            "mode": "disabled",
            "allowlist": ["apt-get update"]
        }
    }

    def mock_get_linux_device(did):
        return device_store.get(did)

    def mock_upsert_linux_device(did, data):
        if did not in device_store:
            device_store[did] = {}
        device_store[did].update(data)

    mocker.patch("app.linux_common.get_linux_device", side_effect=mock_get_linux_device)
    mocker.patch("app.linux_checkin.get_linux_device", side_effect=mock_get_linux_device)
    mocker.patch("app.linux_mdm.upsert_linux_device", side_effect=mock_upsert_linux_device)
    mocker.patch("app.linux_common.upsert_linux_device", side_effect=mock_upsert_linux_device)
    mocker.patch("app.admin.get_linux_device", side_effect=mock_get_linux_device)
    mocker.patch("app.admin.upsert_linux_device", side_effect=mock_upsert_linux_device)
    mocker.patch("app.admin.enqueue_linux_command")

    class MockDoc:
        def __init__(self, data, exists=True):
            self.data = data
            self.exists = exists
        def to_dict(self):
            return self.data

    class MockCollection:
        def __init__(self, name):
            self.name = name
        def document(self, doc_id):
            if self.name == "linux_settings" and doc_id == "shell_command_policy":
                return MockDoc(settings_store.get(doc_id))
            return MockDoc(None, exists=False)

    class MockDB:
        def collection(self, name):
            return MockCollection(name)

    mocker.patch("app.db.get_db", return_value=MockDB())
    mocker.patch("app.admin.get_db", return_value=MockDB())

    # Mock admin auth
    mocker.patch("app.admin._verify_google_oauth_token", return_value="jaakko.korhonen@gmail.com")
    mocker.patch("app.admin.get_user", return_value={"role": "admin"})

    # --- 1. Test Token Rotation ---
    # Poll with old token - should trigger auto-rotation because token is 31 days old
    headers = {"Authorization": f"Bearer {raw_token}"}
    poll_resp = client.put(f"/linux/mdm/{device_id}", json={}, headers=headers)
    assert poll_resp.status_code == 200
    data = poll_resp.get_json()
    new_token = data.get("server_meta", {}).get("new_token")
    assert new_token is not None
    assert device_store[device_id].get("pending_token_hash") is not None

    # Poll again with old token (grace period validation) - should still succeed
    poll_resp2 = client.put(f"/linux/mdm/{device_id}", json={}, headers=headers)
    assert poll_resp2.status_code == 200

    # Test Grace Period Expiration (24h limit)
    # Set rotation_started_at to 25 hours ago
    device_store[device_id]["rotation_started_at"] = datetime.now(timezone.utc) - timedelta(hours=25)
    poll_resp_expired = client.put(f"/linux/mdm/{device_id}", json={}, headers=headers)
    assert poll_resp_expired.status_code == 200
    assert device_store[device_id].get("pending_token_hash") is None
    assert device_store[device_id].get("token_rotation_failed") is True

    # Reset token and pending token for subsequent checks
    new_token_hash = linux_common.hash_token("rotated-token-123")
    device_store[device_id]["pending_token_hash"] = new_token_hash
    device_store[device_id]["rotation_started_at"] = datetime.now(timezone.utc)
    new_token = "rotated-token-123"

    # Poll with new token - should promote pending token and succeed
    new_headers = {"Authorization": f"Bearer {new_token}"}
    poll_resp3 = client.put(f"/linux/mdm/{device_id}", json={}, headers=new_headers)
    assert poll_resp3.status_code == 200
    # The pending token hash should now be promoted to token_hash
    assert device_store[device_id].get("token_hash") == linux_common.hash_token(new_token)
    assert device_store[device_id].get("pending_token_hash") is None

    # Poll again with old token - should now be unauthorized (401)
    poll_resp4 = client.put(f"/linux/mdm/{device_id}", json={}, headers=headers)
    assert poll_resp4.status_code == 401

    # --- 2. Test ShellCommand Policy ---
    # Mode: disabled
    admin_headers = {"Authorization": "Bearer mock-google-token"}
    cmd_payload = {"command": "apt-get update"}
    resp = client.post(f"/admin/devices/{device_id}/command", json={
        "command_type": "ShellCommand",
        "payload": cmd_payload
    }, headers=admin_headers)
    assert resp.status_code == 400
    assert "globally disabled" in resp.get_json()["error"]

    # Mode: allowlist, but device shell_command_enabled is False
    settings_store["shell_command_policy"]["mode"] = "allowlist"
    resp = client.post(f"/admin/devices/{device_id}/command", json={
        "command_type": "ShellCommand",
        "payload": cmd_payload
    }, headers=admin_headers)
    assert resp.status_code == 400
    assert "not enabled for this device" in resp.get_json()["error"]

    # Mode: allowlist, device shell_command_enabled is True, command match
    device_store[device_id]["shell_command_enabled"] = True
    resp = client.post(f"/admin/devices/{device_id}/command", json={
        "command_type": "ShellCommand",
        "payload": cmd_payload
    }, headers=admin_headers)
    assert resp.status_code == 202

    # Mode: allowlist, device shell_command_enabled is True, command mismatch
    resp = client.post(f"/admin/devices/{device_id}/command", json={
        "command_type": "ShellCommand",
        "payload": {"command": "rm -rf /"}
    }, headers=admin_headers)
    assert resp.status_code == 400
    assert "Command not in allowlist" in resp.get_json()["error"]

    # Mode: any
    settings_store["shell_command_policy"]["mode"] = "any"
    resp = client.post(f"/admin/devices/{device_id}/command", json={
        "command_type": "ShellCommand",
        "payload": {"command": "rm -rf /"}
    }, headers=admin_headers)
    assert resp.status_code == 202

