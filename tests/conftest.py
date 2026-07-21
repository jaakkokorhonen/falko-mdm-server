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

# ---------------------------------------------------------------------------
# Esiluodut käyttäjätietueet testiympäristöön
# ---------------------------------------------------------------------------
AUTHORIZED_USER = {"email": "test.user@falko.fi", "status": "authorized", "role": "user", "created_at": "2026-07-01T00:00:00+00:00", "last_login": "2026-07-22T00:00:00+00:00"}
PENDING_USER    = {"email": "pending@example.com",   "status": "pending",    "role": "user", "created_at": "2026-07-20T00:00:00+00:00", "last_login": "2026-07-20T00:00:00+00:00"}
DENIED_USER     = {"email": "denied@example.com",    "status": "denied",     "role": "user", "created_at": "2026-07-15T00:00:00+00:00", "last_login": "2026-07-15T00:00:00+00:00"}
BOOTSTRAP_USER  = {"email": "jaakko.korhonen@gmail.com", "status": "authorized", "role": "admin", "created_at": "2026-07-01T00:00:00+00:00", "last_login": "2026-07-22T00:00:00+00:00"}

@pytest.fixture(autouse=True)
def mock_db_operations(mocker):
    """Mockaa kaikki db.py- ja admin.py-tiedoston Firestore-operaatiot testien ajaksi.

    Jokainen testi käynnistyy puhtaalta pöydältä.
    Tarvittaessa yksittäinen testi voi ylikirjoittaa palautusarvon
    mocker.patch()-kutsulla ennen toimintaa.
    """
    # --- Firestore-yhteys (perusmock kaikille db-kutsuille) ---
    mocker.patch("app.db.get_db")

    # --- Laitteet ---
    mocker.patch("app.admin.list_devices", return_value=([
        {"udid": "device-1", "model": "MacBookAir10,1"},
        {"udid": "device-2", "model": "MacBookPro18,2"}
    ], None))
    mocker.patch("app.admin.get_device", return_value={
        "udid": "test-udid",
        "push_magic": "magic-token",
        "token": "push-token-hex"
    })
    mocker.patch("app.admin.enqueue_command")

    # --- Käyttäjät (OIDC SSO luvitusjärjestelmä) ---
    # Oletuksena: kirjautuva käyttäjä on "authorized".
    # Testit jotka testaavat pending/denied-tilanteita ylikirjoittavat tämän.
    mocker.patch("app.admin.upsert_user", return_value=AUTHORIZED_USER)
    mocker.patch("app.admin.get_user", return_value=AUTHORIZED_USER)
    mocker.patch("app.admin.list_users", return_value=[
        AUTHORIZED_USER, PENDING_USER, DENIED_USER
    ])
    mocker.patch("app.admin.update_user_status")

    # --- MDM-protokolla ---
    mocker.patch("app.checkin.upsert_device")
    mocker.patch("app.mdm.dequeue_command", return_value=("cmd-123", {
        "command_uuid": "cmd-uuid-123",
        "command": {
            "RequestType": "DeviceLock"
        }
    }))
    mocker.patch("app.mdm.ack_command")
