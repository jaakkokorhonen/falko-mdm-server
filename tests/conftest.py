import pytest
import os

# Asetetaan testiympariston muuttujat ennen sovelluksen latausta.
# APNS_PRIVATE_KEY: EC-avain JWT-allekirjoitukseen (testiarvo, ei oikea avain).
os.environ["SECRET_KEY"]       = "test-secret-key-123"
os.environ["GCP_PROJECT"]      = "falko-mdm-test"
os.environ["APNS_TEAM_ID"]     = "STQ5U5TZR2"
os.environ["APNS_KEY_ID"]      = "AU467BS82C"
os.environ["APNS_PRIVATE_KEY"] = (
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHQCAQEEIOaRsVX2m5PBOyq/9j6z5Vc9aA3y1iVFakeKeyDataFakeKeyDataFakeX\n"
    "oAoGCCqGSM49AwEHoWQDYgAEFakePublicKeyDataFakePublicKeyDataFakePublic\n"
    "-----END EC PRIVATE KEY-----"
)

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
# Esiluodut kayttajatietueet testiymparistoon
# ---------------------------------------------------------------------------
AUTHORIZED_USER = {"email": "test.user@falko.fi",         "status": "authorized", "role": "user",  "created_at": "2026-07-01T00:00:00+00:00", "last_login": "2026-07-22T00:00:00+00:00"}
PENDING_USER    = {"email": "pending@example.com",         "status": "pending",    "role": "user",  "created_at": "2026-07-20T00:00:00+00:00", "last_login": "2026-07-20T00:00:00+00:00"}
DENIED_USER     = {"email": "denied@example.com",          "status": "denied",     "role": "user",  "created_at": "2026-07-15T00:00:00+00:00", "last_login": "2026-07-15T00:00:00+00:00"}
BOOTSTRAP_USER  = {"email": "jaakko.korhonen@gmail.com",   "status": "authorized", "role": "admin", "created_at": "2026-07-01T00:00:00+00:00", "last_login": "2026-07-22T00:00:00+00:00"}

@pytest.fixture(autouse=True)
def mock_db_operations(mocker):
    """Mockaa kaikki Firestore-operaatiot testien ajaksi.

    Jokainen testi kaynnistyy puhtaalta poydalta.
    Yksittainen testi voi ylikirjoittaa palautusarvon
    mocker.patch()-kutsulla ennen toimintaa.

    TARKEA: dequeue_command palauttaa (cmd_id, cmd_dict)-tuplen, jossa
    cmd_dict kayttaa avaimia 'command_type' ja 'payload' (ei 'command_uuid'
    tai 'command') — nama ovat mdm.py:n odottama rakenne.
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

    # --- Kayttajat (OIDC SSO luvitusjarjestelma) ---
    # Oletuksena: kirjautuva kayttaja on "authorized".
    # Testit jotka testaavat pending/denied-tilanteita ylikirjoittavat taman.
    mocker.patch("app.admin.upsert_user", return_value=AUTHORIZED_USER)
    mocker.patch("app.admin.get_user", return_value=AUTHORIZED_USER)
    mocker.patch("app.admin.list_users", return_value=[
        AUTHORIZED_USER, PENDING_USER, DENIED_USER
    ])
    mocker.patch("app.admin.update_user_status")

    # --- MDM-protokolla ---
    mocker.patch("app.checkin.upsert_device")

    # MDM-puolen upsert_device (eri importtipolku kuin checkin.py:ssa).
    # Tama on patchattava erikseen — mdm.py importoi suoraan app.db:sta.
    mocker.patch("app.mdm.upsert_device")

    # dequeue_command palauttaa (cmd_id, cmd_dict).
    # cmd_dict-rakenne: avaimet 'command_type' ja 'payload' —
    # nama ovat mdm.py:n cmd.get('command_type') ja cmd.get('payload') -kutsujen
    # odottamat avaimet. Aiempi rakenne {'command_uuid': ..., 'command': {...}}
    # ei tasmaa ja aiheutti hiljaisen oletusarvon 'DeviceInformation'.
    mocker.patch("app.mdm.dequeue_command", return_value=("cmd-123", {
        "command_type": "DeviceLock",
        "payload": {},
    }))
    mocker.patch("app.mdm.ack_command")
