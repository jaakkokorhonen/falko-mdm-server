"""Testit admin-moduulin autentikaatiolle ja laitehallintaendpointeille.

Kattaa:
  - require_auth: 401 ilman tokenia, 200 ADMIN_TOKENilla, IAP JWT -polut
  - Uusi Firestore-pohjainen pääsyoikeus: authorized / pending / denied
  - Bootstrap-admin (jaakko.korhonen@gmail.com) saa aina pääsyn
  - DANGER-komennot: roolitarkistus user vs. admin
  - Allowlist: tuntematon komento → 400

Testausstrategia: pytest-mock (mocker-fixture) ulkoisille riippuvuuksille.
Parametrisointi: @pytest.mark.parametrize yhdenmukaistaa samanlaiset
tapaukset useilla syötteillä (Okken 2022, pytest docs 8.x).

"""
import pytest
import os

# Asetetaan testien aikainen ADMIN_TOKEN testiympariston muuttujaksi
os.environ["ADMIN_TOKEN"] = "test-admin-token-123"


# ---------------------------------------------------------------------------
# require_auth — perusautentikaatio
# ---------------------------------------------------------------------------

def test_admin_list_devices_unauthorized(client):
    """Varmistaa, että /admin/devices ilman otsakkeita palauttaa 401 Unauthorized."""
    response = client.get("/admin/devices")
    assert response.status_code == 401
    assert response.json == {"error": "Autentikaatio puuttuu tai on virheellinen"}


def test_admin_list_devices_authorized_by_google_token(client, mocker):
    """Varmistaa, että /admin/devices toimii validilla Google OAuth -Bearer-tokenilla."""
    mocker.patch("app.admin._verify_google_oauth_token", return_value="jaakko.korhonen@gmail.com")

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer valid-google-id-token"},
    )
    assert response.status_code == 200
    assert len(response.json["devices"]) == 2
    assert response.json["devices"][0]["udid"] == "device-1"


def test_admin_list_devices_invalid_bearer_token(client, mocker):
    """Varmistaa, että väärä Bearer-token palauttaa 401."""
    mocker.patch("app.admin._verify_google_oauth_token", return_value=None)

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer totally-wrong-token"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# IAP JWT -autentikaatio + Firestore-pääsyoikeustarkistus
# ---------------------------------------------------------------------------

def test_admin_list_devices_iap_authorized_user(client, mocker):
    """IAP JWT + Firestore-status 'authorized' → 200 OK."""
    mocker.patch("app.admin._verify_iap_jwt", return_value="test.user@falko.fi")
    # conftest palauttaa oletuksena AUTHORIZED_USER — ei tarvitse ylikirjoittaa

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "valid-jwt"},
    )
    assert response.status_code == 200
    assert len(response.json["devices"]) == 2


def test_admin_list_devices_iap_pending_user(client, mocker):
    """IAP JWT + Firestore-status 'pending' → 403, virheviestin tulee mainita käsittelyssä."""
    mocker.patch("app.admin._verify_iap_jwt", return_value="pending@example.com")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "pending@example.com", "status": "pending"
    })

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "pending-jwt"},
    )
    assert response.status_code == 403
    assert "käsittelyssä" in response.json["error"]


def test_admin_list_devices_iap_denied_user(client, mocker):
    """IAP JWT + Firestore-status 'denied' → 403, virheviestin tulee mainita evätty."""
    mocker.patch("app.admin._verify_iap_jwt", return_value="denied@example.com")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "denied@example.com", "status": "denied"
    })

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "denied-jwt"},
    )
    assert response.status_code == 403
    assert "evätty" in response.json["error"]


def test_admin_list_devices_iap_invalid_jwt(client, mocker):
    """Väärä/vanhautunut IAP JWT (verify palauttaa None) → 401."""
    mocker.patch("app.admin._verify_iap_jwt", return_value=None)

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "tampered-jwt"},
    )
    assert response.status_code == 401


def test_admin_bootstrap_admin_always_authorized(client, mocker):
    """Bootstrap-admin (jaakko.korhonen@gmail.com) saa aina pääsyn — Firestore-tilasta riippumatta."""
    mocker.patch("app.admin._verify_iap_jwt", return_value="jaakko.korhonen@gmail.com")
    # Vaikka upsert_user palauttaisi pending-tilan, bootstrap-admin pääsee läpi
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "jaakko.korhonen@gmail.com", "status": "pending"
    })

    response = client.get(
        "/admin/devices",
        headers={"X-Goog-IAP-JWT-Assertion": "bootstrap-jwt"},
    )
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Google OAuth ID Token autentikaatio
# ---------------------------------------------------------------------------

def test_admin_google_oauth_token_authorized(client, mocker):
    """Google OAuth ID Token + Firestore-status 'authorized' → 200 OK."""
    mocker.patch("app.admin._verify_google_oauth_token", return_value="test.user@falko.fi")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "test.user@falko.fi", "status": "authorized"
    })

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer google-id-token-abc123"},
    )
    assert response.status_code == 200


def test_admin_google_oauth_token_pending(client, mocker):
    """Google OAuth ID Token + Firestore-status 'pending' → 403."""
    mocker.patch("app.admin._verify_google_oauth_token", return_value="newuser@example.com")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "newuser@example.com", "status": "pending"
    })

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer google-id-token-new"},
    )
    assert response.status_code == 403
    assert "käsittelyssä" in response.json["error"]


def test_admin_google_oauth_token_denied(client, mocker):
    """Google OAuth ID Token + Firestore-status 'denied' → 403."""
    mocker.patch("app.admin._verify_google_oauth_token", return_value="blocked@example.com")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "blocked@example.com", "status": "denied"
    })

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer google-id-token-blocked"},
    )
    assert response.status_code == 403
    assert "evätty" in response.json["error"]


# ---------------------------------------------------------------------------
# DANGER-komentojen roolitarkistus
# OWASP ASVS v4.0 §4.1.2: kaikki toiminnot vaativat roolitarkistuksen
# ---------------------------------------------------------------------------

# Parametrisointi valittu pytest.mark.parametrize:lla erilläisten
# test-funktioiden sijaan: testit ovat identtisiä rakenteeltaan,
# vain syöte vaihtuu. Tämä välttää copy-paste-testilogiikan.
# Llähde: pytest docs 8.x “Parametrizing fixtures and test functions”;
# Okken, B. (2022). Python Testing with pytest, 2nd ed., luku 4.
@pytest.mark.parametrize("danger_command", [
    "EraseDevice",    # pyyhkii laitteen — peruuttamaton
    "ShutDownDevice", # sammuttaa eikä käynnistä automaattisesti
])
def test_send_command_danger_user_role_returns_403(client, mocker, danger_command):
    """User-rooli yrittaa DANGER-komentoa → 403 Forbidden.

    Verifikoi: Principle of Least Privilege (NIST SP 800-53 AC-6).
    User-roolilla on oikeus vain ei-destruktiivisiin komentoihin.
    """
    # Autentikaatio: IAP JWT läpäisee require_auth:n
    mocker.patch("app.admin._verify_iap_jwt", return_value="user@falko.fi")
    # Rooli: 'user' — ei oikeutta DANGER-komentoihin
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "user@falko.fi", "status": "authorized", "role": "user"
    })
    mocker.patch("app.admin.get_user", return_value={
        "email": "user@falko.fi", "status": "authorized", "role": "user"
    })
    # _get_authenticated_email käyttää samaa IAP-polkua — mockataan myös
    mocker.patch("app.admin._verify_iap_jwt", return_value="user@falko.fi")

    response = client.post(
        "/admin/devices/test-udid/command",
        json={"command_type": danger_command},
        headers={"X-Goog-IAP-JWT-Assertion": "user-jwt"},
    )

    assert response.status_code == 403, (
        f"Odotettiin 403 kun user-rooli yritti {danger_command!r}, "
        f"saatiin {response.status_code}"
    )
    # Virheviesti kertoo miksi — ei vain 'Forbidden'
    assert "admin" in response.json["error"].lower(), (
        "Virheviestin pitää mainita admin-vaatimus"
    )


@pytest.mark.parametrize("danger_command", [
    "EraseDevice",
    "ShutDownDevice",
])
def test_send_command_danger_admin_role_returns_202(client, mocker, danger_command):
    """Admin-rooli voi ajaa DANGER-komennon → 202 Accepted.

    Negatiivisen testin pari: varmistaa että oikea rooli pääsee läpi.
    Pelkkä 403-testi ei riitä — 400-taso voi johtua myös allowlist-virheestä.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="admin@falko.fi")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "admin@falko.fi", "status": "authorized", "role": "admin"
    })
    mocker.patch("app.admin.get_user", return_value={
        "email": "admin@falko.fi", "status": "authorized", "role": "admin"
    })

    response = client.post(
        "/admin/devices/test-udid/command",
        json={"command_type": danger_command},
        headers={"X-Goog-IAP-JWT-Assertion": "admin-jwt"},
    )

    assert response.status_code == 202, (
        f"Admin-roolin piti saada 202 komennolla {danger_command!r}, "
        f"saatiin {response.status_code}: {response.json}"
    )
    assert response.json["command_type"] == danger_command


def test_send_command_safe_user_role_returns_202(client, mocker):
    """User-rooli voi ajaa turvallisia komentoja (DeviceLock) → 202.

    Varmistaa että roolitarkistus ei blokkaa kaikkia komentoja —
    vain _DANGER_COMMANDS-setissä olevat.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="user@falko.fi")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "user@falko.fi", "status": "authorized", "role": "user"
    })

    response = client.post(
        "/admin/devices/test-udid/command",
        json={"command_type": "DeviceLock"},
        headers={"X-Goog-IAP-JWT-Assertion": "user-jwt"},
    )

    assert response.status_code == 202


def test_send_command_unknown_returns_400(client, mocker):
    """Tuntematon command_type (ei allowlistissä) → 400 Bad Request.

    Verifikoi allowlist-validointi (OWASP ASVS v4.0 §5.1.3).
    Roolia ei tarkisteta — allowlist on ensimmäinen tarkistus.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="admin@falko.fi")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "admin@falko.fi", "status": "authorized", "role": "admin"
    })

    response = client.post(
        "/admin/devices/test-udid/command",
        json={"command_type": "MaliciousCommand"},
        headers={"X-Goog-IAP-JWT-Assertion": "admin-jwt"},
    )

    assert response.status_code == 400
    # Vastauksen tulee sisältää sallittujen komentojen lista (helpottaa debuggausta)
    assert "allowed" in response.json


def test_send_command_missing_command_type_returns_400(client, mocker):
    """Tyhjä body ilman command_type-kentää → 400 Bad Request.

    Boundary test: tarkistaa että pakollinen kenttä validoidaan
    ennen allowlist- tai roolitarkistusta.
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="admin@falko.fi")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "admin@falko.fi", "status": "authorized", "role": "admin"
    })

    response = client.post(
        "/admin/devices/test-udid/command",
        json={},  # command_type puuttuu kokonaan
        headers={"X-Goog-IAP-JWT-Assertion": "admin-jwt"},
    )

    assert response.status_code == 400
    assert "command_type" in response.json["error"]


def test_send_command_device_not_found_returns_404(client, mocker):
    """Olematon UDID → 404 Not Found.

    Tarkistaa että laitetarkistus tulee allowlist-tarkistuksen jälkeen
    — ei ennen sitä (järjestys on tärkeä tietoturvan kannalta:
    401 → 403 → 400 → 404, näin paljastetaan vähimmän tiedon periaatteen
    mukaisesti vain tarpeellinen tieto).
    """
    mocker.patch("app.admin._verify_iap_jwt", return_value="admin@falko.fi")
    mocker.patch("app.admin.upsert_user", return_value={
        "email": "admin@falko.fi", "status": "authorized", "role": "admin"
    })
    # Korvataan conftest:n get_device — laite ei löydy
    mocker.patch("app.admin.get_device", return_value=None)

    response = client.post(
        "/admin/devices/ei-olemassa-udid/command",
        json={"command_type": "DeviceLock"},
        headers={"X-Goog-IAP-JWT-Assertion": "admin-jwt"},
    )

    assert response.status_code == 404
