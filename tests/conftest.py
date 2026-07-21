import pytest
import os

# Asetetaan testiympäristömuuttujat ennen sovelluksen latausta
os.environ["SECRET_KEY"] = "test-secret-key-123"
os.environ["GCP_PROJECT"] = "falko-mdm-test"
os.environ["APNS_TEAM_ID"] = "STQ5U5TZR2"
os.environ["APNS_KEY_ID"] = "AU467BS82C"

from main import create_app

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
    })
    yield app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture(autouse=True)
def mock_db_operations(mocker):
    """Mockaa kaikki db.py -tiedoston Firestore-operaatiot testien ajaksi."""
    mocker.patch("app.db.get_db")
    
    # Mockataan admin.py -tiedostoon tuodut funktiot
    mocker.patch("app.admin.list_devices", return_value=[
        {"udid": "device-1", "model": "MacBookAir10,1"},
        {"udid": "device-2", "model": "MacBookPro18,2"}
    ])
    mocker.patch("app.admin.get_device", return_value={
        "udid": "test-udid",
        "push_magic": "magic-token",
        "token": "push-token-hex"
    })
    mocker.patch("app.admin.enqueue_command")
    
    # Mockataan checkin.py -tiedostoon tuodut funktiot
    mocker.patch("app.checkin.upsert_device")

    # Mockataan mdm.py -tiedostoon tuodut funktiot
    mocker.patch("app.mdm.dequeue_command", return_value=("cmd-123", {
        "command_uuid": "cmd-uuid-123",
        "command": {
            "RequestType": "DeviceLock"
        }
    }))
    mocker.patch("app.mdm.ack_command")
