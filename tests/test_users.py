"""Regressiotestit OIDC SSO -käyttäjähallintaendpointeille.

Kattaa:
  GET  /admin/users              — listaa käyttäjät
  POST /admin/users/<e>/authorize — hyväksy käyttäjä
  POST /admin/users/<e>/deny      — evää käyttäjä
"""
import pytest
import os

os.environ["ADMIN_TOKEN"] = "test-admin-token-123"

# Autentikointiotsake jota käytetään kaikissa testeissä
AUTH = {"Authorization": "Bearer test-admin-token-123"}


# ---------------------------------------------------------------------------
# GET /admin/users — käyttäjälista
# ---------------------------------------------------------------------------

def test_list_users_unauthorized(client):
    """Ilman tokenia /admin/users palauttaa 401."""
    response = client.get("/admin/users")
    assert response.status_code == 401


def test_list_users_authorized(client, mocker):
    """ADMIN_TOKEN -tokenilla /admin/users palauttaa 200 + lista."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")

    response = client.get("/admin/users", headers=AUTH)
    assert response.status_code == 200
    body = response.json
    assert "users" in body
    assert "count" in body
    assert body["count"] == 3   # conftest palauttaa 3 mock-käyttäjää
    emails = [u["email"] for u in body["users"]]
    assert "test.user@falko.fi" in emails
    assert "pending@example.com" in emails
    assert "denied@example.com" in emails


def test_list_users_contains_all_statuses(client, mocker):
    """Palautettu lista sisältää kaikki kolme tilaa: authorized, pending, denied."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")

    response = client.get("/admin/users", headers=AUTH)
    statuses = {u["status"] for u in response.json["users"]}
    assert "authorized" in statuses
    assert "pending" in statuses
    assert "denied" in statuses


# ---------------------------------------------------------------------------
# POST /admin/users/<email>/authorize
# ---------------------------------------------------------------------------

def test_authorize_user_success(client, mocker):
    """Olemassaoleva pending-käyttäjä hyväksytään — 200, status: authorized."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
    mocker.patch("app.admin.get_user", return_value={
        "email": "pending@example.com", "status": "pending"
    })

    response = client.post(
        "/admin/users/pending%40example.com/authorize",
        headers=AUTH,
    )
    assert response.status_code == 200
    assert response.json["status"] == "authorized"
    assert response.json["email"] == "pending@example.com"


def test_authorize_user_calls_update_status(client, mocker):
    """Hyväksyminen kutsuu update_user_status oikeilla parametreillä."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
    mocker.patch("app.admin.get_user", return_value={
        "email": "pending@example.com", "status": "pending"
    })
    mock_update = mocker.patch("app.admin.update_user_status")

    client.post("/admin/users/pending%40example.com/authorize", headers=AUTH)

    mock_update.assert_called_once_with("pending@example.com", status="authorized")


def test_authorize_nonexistent_user(client, mocker):
    """Tuntematon käyttäjä → 404 Not Found."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
    mocker.patch("app.admin.get_user", return_value=None)

    response = client.post(
        "/admin/users/ghost%40example.com/authorize",
        headers=AUTH,
    )
    assert response.status_code == 404
    assert "löydy" in response.json["error"]


def test_authorize_user_unauthorized(client):
    """Ilman tokenia /authorize palauttaa 401."""
    response = client.post("/admin/users/test%40example.com/authorize")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /admin/users/<email>/deny
# ---------------------------------------------------------------------------

def test_deny_user_success(client, mocker):
    """Olemassaoleva käyttäjä evätään — 200, status: denied."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
    mocker.patch("app.admin.get_user", return_value={
        "email": "test.user@falko.fi", "status": "authorized"
    })

    response = client.post(
        "/admin/users/test.user%40falko.fi/deny",
        headers=AUTH,
    )
    assert response.status_code == 200
    assert response.json["status"] == "denied"
    assert response.json["email"] == "test.user@falko.fi"


def test_deny_user_calls_update_status(client, mocker):
    """Epääminen kutsuu update_user_status oikeilla parametreillä."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
    mocker.patch("app.admin.get_user", return_value={
        "email": "test.user@falko.fi", "status": "authorized"
    })
    mock_update = mocker.patch("app.admin.update_user_status")

    client.post("/admin/users/test.user%40falko.fi/deny", headers=AUTH)

    mock_update.assert_called_once_with("test.user@falko.fi", status="denied")


def test_deny_nonexistent_user(client, mocker):
    """Tuntematon käyttäjä → 404 Not Found."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
    mocker.patch("app.admin.get_user", return_value=None)

    response = client.post(
        "/admin/users/ghost%40example.com/deny",
        headers=AUTH,
    )
    assert response.status_code == 404


def test_deny_user_unauthorized(client):
    """Ilman tokenia /deny palauttaa 401."""
    response = client.post("/admin/users/test%40example.com/deny")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Sivutus ja reunatapaukset
# ---------------------------------------------------------------------------

def test_list_users_empty(client, mocker):
    """Tyhjä käyttäjälista → count: 0."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
    mocker.patch("app.admin.list_users", return_value=[])

    response = client.get("/admin/users", headers=AUTH)
    assert response.status_code == 200
    assert response.json["count"] == 0
    assert response.json["users"] == []
