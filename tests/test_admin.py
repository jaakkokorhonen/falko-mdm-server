"""Testit admin-moduulin autentikaatiolle ja laitehallintaendpointeille.

Kattaa:
  - require_auth: 401 ilman tokenia, 200 ADMIN_TOKENilla, IAP JWT -polut
  - Uusi Firestore-pohjainen pääsyoikeus: authorized / pending / denied
  - Bootstrap-admin (jaakko.korhonen@gmail.com) saa aina pääsyn
"""
import pytest
import os

# Asetetaan testien aikainen ADMIN_TOKEN testiympäristömuuttujaksi
os.environ["ADMIN_TOKEN"] = "test-admin-token-123"


# ---------------------------------------------------------------------------
# require_auth — perusautentikaatio
# ---------------------------------------------------------------------------

def test_admin_list_devices_unauthorized(client):
    """Varmistaa, että /admin/devices ilman otsakkeita palauttaa 401 Unauthorized."""
    response = client.get("/admin/devices")
    assert response.status_code == 401
    assert response.json == {"error": "Autentikaatio puuttuu tai on virheellinen"}


def test_admin_list_devices_authorized_by_admin_token(client, mocker):
    """Varmistaa, että /admin/devices toimii oikealla ADMIN_TOKEN -Bearer-tokenilla."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")

    response = client.get(
        "/admin/devices",
        headers={"Authorization": "Bearer test-admin-token-123"},
    )
    assert response.status_code == 200
    assert len(response.json["devices"]) == 2
    assert response.json["devices"][0]["udid"] == "device-1"


def test_admin_list_devices_invalid_bearer_token(client, mocker):
    """Varmistaa, että väärä Bearer-token palauttaa 401 (ei Google-token, ei ADMIN_TOKEN)."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
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
    mocker.patch("app.admin.ADMIN_TOKEN", "")   # ei ADMIN_TOKEN -matchausta
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
    mocker.patch("app.admin.ADMIN_TOKEN", "")
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
