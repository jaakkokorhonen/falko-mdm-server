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

from cryptography.hazmat.primitives.serialization import load_pem_private_key

PEM_KEY = (
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIN3v5YwQ6N8v6f4Tebv4L8A3y1iVF+k6w8Y0+3+4w+oAoGCCqGSM49AwEH\n"
    "HoUQDQgAE13f5yW4Tevc4Yx0W7LqLlhf7pI+a0K/V3q6r9M8Z87f4l82s7X9+8x5k\n"
    "+q8e+0g0w8x8d/1o5z8A8y8Y0+3+4w==\n"
    "-----END EC PRIVATE KEY-----"
)

PRIVATE_KEY = load_pem_private_key(PEM_KEY.encode('utf-8'), password=None)
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
