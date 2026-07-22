"""Integraatiotestit admin-moduulille: autentikaatio, roolitarkistus ja komennot.

Testiryhmät:
  1. require_auth — perusautentikaatiovirheet (401 ilman headeria, väärä token)
  2. IAP JWT -polut — authorized / pending / denied / invalid
  3. Google OAuth -polut — authorized / pending / denied
  4. Bootstrap-admin — pääsy riippumatta Firestore-tilasta
  5. DANGER-komennot (SEC-11) — user-rooli saa 403, admin-rooli 200
  6. Allowlist-validointi (OWASP ASVS §5.1.3) — tuntematon komento → 400
  7. APNs-push — autentikoitu user pääsee, ei vaadi admin-roolia
  8. Edge caset — puuttuva body, tyhjä command_type

Mocking-periaate:
  _verify_iap_jwt / _verify_google_oauth_token → palauttaa sähköpostin
  get_user / upsert_user → palauttaa Firestore-käyttäjäobjektin
  get_device / enqueue_command / send_push → mock_db-fixture

Ref: OWASP API Security Top 10 (2023) API3:2023, API5:2023.
Ref: CONTRIBUTING.md §Tietoturvatestien minimivaatimukset.
"""
import pytest
import os
from unittest.mock import patch

# Testeissä käytetään ADMIN_TOKEN-muuttujaa — se on vaadittu conftest-fixture
os.environ["ADMIN_TOKEN"] = "test-admin-token-123"


# ---------------------------------------------------------------------------
# 1. require_auth — perusautentikaatio
# ---------------------------------------------------------------------------

def test_admin_list_devices_unauthorized(client):
    """Pyyntö ilman auth-headeria → 401 Unauthorized.

    Varmistaa että require_auth-dekoraattori hylkää kaikki
    autentikoimattomat pyynnöt ennen Firestore-kutsuja.
    Ref: OWASP API2:2023 Broken Authentication.
    """
    response = client.get("/admin/devices")
    assert response.status_code == 401
    assert response.json == {"error": "Autentikaatio puuttuu tai on virheellinen"}


def test_admin_list_devices_authorized_by_google_token(client, mocker, mock_db, admin_user_record):
    """Validi Google OAuth Bearer-token + authorized-status → 200 OK.

    _verify_google_oauth_token mockataan palauttamaan sähköposti;
    get_user palauttaa authorized-admin-recordin.
    """
    mocker.patch("app.admin._verify_google_oauth_token", return_value="jaakko.korhonen@gmail.com")
    mocker.patch("app.admin.get_user", return_value=admin_user_record)

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer valid-google-id-token"},
    )
    assert response.status_code == 200
    # mock_db.list_devices palauttaa 2 laitetta
    assert len(response.json["devices"]) == 2
    assert response.json["devices"][0]["udid"] == "device-1"


def test_admin_list_devices_invalid_bearer_token(client, mocker):
    """Virheellinen Bearer-token (_verify_google_oauth_token → None) → 401.

    Token voi olla vanhentunut, väärennetty tai väärän projektin token.
    """
    mocker.patch("app.admin._verify_google_oauth_token", return_value=None)

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer totally-wrong-token"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 2. IAP JWT -autentikaatio + Firestore-pääsyoikeustarkistus
# ---------------------------------------------------------------------------

def test_admin_list_devices_iap_authorized_user(client, mocker, mock_db, regular_user_record):
    """IAP JWT + Firestore-status 'authorized' + role 'user' → 200 OK.

    Laitelistan hakeminen ei vaadi admin-roolia — riittää että status=authorized.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="test.user@falko.fi")
    mocker.patch("app.admin.get_user", return_value=regular_user_record)

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "valid-jwt"},
    )
    assert response.status_code == 200
    assert len(response.json["devices"]) == 2


def test_admin_list_devices_iap_pending_user(client, mocker, mock_db):
    """IAP JWT + Firestore-status 'pending' → 403, virheviestissä 'käsittelyssä'.

    Uusi käyttäjä jonka pääsypyyntö on vielä admin-hyväksyntää odottamassa.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="pending@example.com")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "pending@example.com", "status": "pending", "role": "user"
    })
    mocker.patch("app.admin.get_user", return_value={
        "email": "pending@example.com", "status": "pending", "role": "user"
    })

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "pending-jwt"},
    )
    assert response.status_code == 403
    assert "käsittelyssä" in response.json["error"]


def test_admin_list_devices_iap_denied_user(client, mocker, mock_db):
    """IAP JWT + Firestore-status 'denied' → 403, virheviestissä 'evätty'.

    Admin on erikseen evännyt käyttäjän pääsypyynnön.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="denied@example.com")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "denied@example.com", "status": "denied", "role": "user"
    })
    mocker.patch("app.admin.get_user", return_value={
        "email": "denied@example.com", "status": "denied", "role": "user"
    })

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "denied-jwt"},
    )
    assert response.status_code == 403
    assert "evätty" in response.json["error"]


def test_admin_list_devices_iap_invalid_jwt(client, mocker):
    """Väärä tai vanhentunut IAP JWT (_verify_iap_jwt → None) → 401.

    JWT:n allekirjoitus ei täsmää Googlen julkisiin avaimiin.
    Tätä tilannetta EI saa käsitellä kuten puuttuvaa headeria —
    401 on oikea vastaus molemmissa tapauksissa mutta syyt ovat eri.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value=None)

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "tampered-jwt"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 3. Bootstrap-admin
# ---------------------------------------------------------------------------

def test_admin_bootstrap_admin_always_authorized(client, mocker, mock_db):
    """Bootstrap-admin saa aina pääsyn — Firestore-tilasta riippumatta.

    BOOTSTRAP_ADMIN_EMAIL-ympäristömuuttuja asettaa ensi-installaation
    admin-oikeuden ilman Firestore-riippuvuutta. Testi simuloi tilannetta
    jossa Firestore palauttaisi 'pending' mutta bootstrap-admin pääsee silti.

    Ref: CONTRIBUTING.md §Bootstrap-admin; SEC-10.
    """
    bootstrap_email = "jaakko.korhonen@gmail.com"
    mocker.patch("app.admin._verify_iap_jwt", return_value=bootstrap_email)
    # Simuloidaan pending-tilaa — bootstrap-admin ei saa jäädä jumiin
    mocker.patch("app.admin.upsert_user", return_value={
        "email": bootstrap_email, "status": "pending", "role": "user"
    })
    mocker.patch("app.admin.get_user", return_value={
        "email": bootstrap_email, "status": "pending", "role": "user"
    })

    with patch.dict('os.environ', {'BOOTSTRAP_ADMIN_EMAIL': bootstrap_email}):
        response = client.get(
            "/admin/devices",
            headers={"X-Goog-IAP-JWT-Assertion": "bootstrap-jwt"},
        )
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# 4. Google OAuth ID Token -polut
# ---------------------------------------------------------------------------

def test_admin_google_oauth_token_authorized(client, mocker, mock_db, regular_user_record):
    """Google OAuth ID Token + Firestore-status 'authorized' → 200 OK."""
    mocker.patch("app.admin._verify_google_oauth_token", return_value="test.user@falko.fi")
    mocker.patch("app.admin.get_user", return_value=regular_user_record)

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer google-id-token-abc123"},
    )
    assert response.status_code == 200


def test_admin_google_oauth_token_pending(client, mocker, mock_db):
    """Google OAuth ID Token + status 'pending' → 403 käsittelyssä."""
    mocker.patch("app.admin._verify_google_oauth_token", return_value="newuser@example.com")
    mocker.patch("app.admin.get_user", return_value={
        "email": "newuser@example.com", "status": "pending", "role": "user"
    })
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "newuser@example.com", "status": "pending", "role": "user"
    })

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer google-id-token-new"},
    )
    assert response.status_code == 403
    assert "käsittelyssä" in response.json["error"]


def test_admin_google_oauth_token_denied(client, mocker, mock_db):
    """Google OAuth ID Token + status 'denied' → 403 evätty."""
    mocker.patch("app.admin._verify_google_oauth_token", return_value="blocked@example.com")
    mocker.patch("app.admin.get_user", return_value={
        "email": "blocked@example.com", "status": "denied", "role": "user"
    })
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "blocked@example.com", "status": "denied", "role": "user"
    })

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer google-id-token-blocked"},
    )
    assert response.status_code == 403
    assert "evätty" in response.json["error"]


# ---------------------------------------------------------------------------
# 5. DANGER-komennot — roolitarkistus (SEC-11, OWASP API5:2023)
# ---------------------------------------------------------------------------

# DANGER_COMMANDS on sama setti kuin app/admin.py:n _DANGER_COMMANDS.
# Testi parametrisoidaan jotta jokainen vaarallinen komento testataan
# erikseen — yksi testi kattaa kaikki kolme.
_DANGER_COMMANDS_LIST = ["EraseDevice", "ShutDownDevice", "DeviceLock"]


@pytest.mark.parametrize("command", _DANGER_COMMANDS_LIST)
def test_danger_command_user_role_returns_403(client, mocker, mock_db, regular_user_record, command):
    """User-rooli (role='user') yrittää DANGER-komentoa → 403 Forbidden.

    Tämä on kriittisin tietoturvatesti: user-rooli ei saa pystyä
    pyyhkimään tai sammuttamaan laitteita. Palvelin validoi roolin
    _DANGER_COMMANDS-tarkistuksessa ennen enqueue_command-kutsua.

    Parametrit: kaikki kolme DANGER-komentoa testataan erikseen.
    Ref: OWASP API5:2023 Broken Function Level Authorization.
    Ref: CONTRIBUTING.md §Tietoturvatestien minimivaatimukset.

    Args:
        command: yksi DANGER-komennoista ('EraseDevice' | 'ShutDownDevice' | 'DeviceLock')
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="user@falko.fi")
    mocker.patch("app.admin.get_user", return_value=regular_user_record)

    response = client.post(
        "/admin/devices/TEST-UDID-0001/command",
        json={"command_type": command},
        headers={"X-Goog-IAP-JWT-Assertion": "user-jwt"},
    )
    assert response.status_code == 403, (
        f"Odotettu 403 user-roolilla komennolla {command}, "
        f"saatiin {response.status_code}: {response.json}"
    )
    # Varmistaa ettei komentoa päässyt jonoon
    mock_db.enqueue_command.assert_not_called()


@pytest.mark.parametrize("command", _DANGER_COMMANDS_LIST)
def test_danger_command_admin_role_returns_200(client, mocker, mock_db, admin_user_record, command):
    """Admin-rooli (role='admin') lähettää DANGER-komennon → 200 OK.

    Admin-rooli on ainoa rooli joka saa lähettää peruuttamattomia komentoja.
    Testi varmistaa ettei admin-roolia estetä virheellisesti.

    Args:
        command: yksi DANGER-komennoista ('EraseDevice' | 'ShutDownDevice' | 'DeviceLock')
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="admin@falko.fi")
    mocker.patch("app.admin.get_user", return_value=admin_user_record)

    response = client.post(
        "/admin/devices/TEST-UDID-0001/command",
        json={"command_type": command},
        headers={"X-Goog-IAP-JWT-Assertion": "admin-jwt"},
    )
    assert response.status_code == 200, (
        f"Admin-rooli estetty komennolta {command}: "
        f"{response.status_code} {response.json}"
    )
    # Varmistaa että komento todella lisättiin jonoon
    mock_db.enqueue_command.assert_called_once()


# ---------------------------------------------------------------------------
# 6. Sallittu komento user-roolilla
# ---------------------------------------------------------------------------

def test_allowed_command_user_role_returns_200(client, mocker, mock_db, regular_user_record):
    """User-rooli lähettää sallitun (ei-DANGER) komennon → 200 OK.

    DeviceInformation ei ole vaarallinen komento — user-roolin tulee
    pystyä lähettämään se. Testi varmistaa ettei require_admin estä
    tavallisia komentoja.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="user@falko.fi")
    mocker.patch("app.admin.get_user", return_value=regular_user_record)

    response = client.post(
        "/admin/devices/TEST-UDID-0001/command",
        json={"command_type": "DeviceInformation"},
        headers={"X-Goog-IAP-JWT-Assertion": "user-jwt"},
    )
    assert response.status_code == 200
    mock_db.enqueue_command.assert_called_once()


# ---------------------------------------------------------------------------
# 7. Allowlist-validointi (OWASP ASVS §5.1.3)
# ---------------------------------------------------------------------------

def test_unknown_command_allowlist_returns_400(client, mocker, mock_db, admin_user_record):
    """Tuntematon command_type → 400 Bad Request.

    _ALLOWED_COMMANDS on positiivinen sallittujen komentojen lista.
    Kaikki sen ulkopuolella olevat arvot hylätään 400:lla ennen
    Firestore-kirjoitusta — estää mielivaltaisten Apple MDM
    RequestType-arvojen injektoinnin.

    Ref: OWASP ASVS v4.0 §5.1.3 — Positive server-side input validation.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="admin@falko.fi")
    mocker.patch("app.admin.get_user", return_value=admin_user_record)

    response = client.post(
        "/admin/devices/TEST-UDID-0001/command",
        json={"command_type": "MaliciousCommand"},
        headers={"X-Goog-IAP-JWT-Assertion": "admin-jwt"},
    )
    assert response.status_code == 400
    # Komentoa ei saa päästä jonoon
    mock_db.enqueue_command.assert_not_called()


def test_missing_command_type_returns_400(client, mocker, mock_db, admin_user_record):
    """Puuttuva command_type → 400 Bad Request.

    Tyhjä body tai puuttuva kenttä on virheellinen pyyntö.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="admin@falko.fi")
    mocker.patch("app.admin.get_user", return_value=admin_user_record)

    response = client.post(
        "/admin/devices/TEST-UDID-0001/command",
        json={},  # ei command_type-kenttää
        headers={"X-Goog-IAP-JWT-Assertion": "admin-jwt"},
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# 8. APNs-push — autentikoitu user pääsee (ei vaadi admin-roolia)
# ---------------------------------------------------------------------------

def test_push_authenticated_user_returns_200(client, mocker, mock_db, regular_user_record):
    """User-rooli lähettää APNs-herätyksen → 200 OK.

    APNs-push on matalariskinen operaatio: se vain herättää laitteen
    ottamaan yhteyttä serveriin. Se ei vaadi admin-roolia — riittää
    että status=authorized.

    mock_db.get_device palauttaa laitteen jolla on push_token ja
    push_magic — ilman niitä push ei onnistu.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="user@falko.fi")
    mocker.patch("app.admin.get_user", return_value=regular_user_record)
    # Laitteella pitää olla push_token ja push_magic APNs-herätystä varten
    mock_db.get_device.return_value = {
        'udid': 'TEST-UDID-0001',
        'serial': 'C02XG0JJHTD6',
        'status': 'enrolled',
        'push_token': 'a' * 64,   # hex-string, 64 merkkiä
        'push_magic': 'test-push-magic-value',
        'topic':      'com.apple.mgmt.External.TEST',
    }
    # send_push mockataan — ei oikeita APNs-kutsuja testissä
    mock_db.send_push.return_value = True
    mocker.patch("app.admin.send_push", return_value=True)

    response = client.post(
        "/admin/devices/TEST-UDID-0001/push",
        headers={"X-Goog-IAP-JWT-Assertion": "user-jwt"},
    )
    assert response.status_code == 200
