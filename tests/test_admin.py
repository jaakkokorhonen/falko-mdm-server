import pytest
import os

# Asetetaan testien aikainen ADMIN_TOKEN testiympäristömuuttujaksi
os.environ["ADMIN_TOKEN"] = "test-admin-token-123"

def test_admin_list_devices_unauthorized(client):
    """Varmistaa, että /admin/devices ilman otsakkeita palauttaa 401 Unauthorized."""
    response = client.get("/admin/devices")
    assert response.status_code == 401
    assert response.json == {"error": "Autentikaatio puuttuu tai on virheellinen"}

def test_admin_list_devices_authorized(client, mocker):
    """Varmistaa, että /admin/devices toimii oikealla Bearer-tokenilla."""
    mocker.patch("app.admin.ADMIN_TOKEN", "test-admin-token-123")
    
    headers = {
        "Authorization": "Bearer test-admin-token-123"
    }
    response = client.get("/admin/devices", headers=headers)
    assert response.status_code == 200
    assert len(response.json["devices"]) == 2
    assert response.json["devices"][0]["udid"] == "device-1"

def test_admin_list_devices_authorized_iap(client, mocker):
    """Varmistaa, että /admin/devices sallii pääsyn oikealla IAP JWT-assertionilla."""
    mocker.patch("app.admin._verify_iap_jwt", return_value="test.user@falko.fi")
    
    headers = {
        "X-Goog-IAP-JWT-Assertion": "valid-jwt-token"
    }
    response = client.get("/admin/devices", headers=headers)
    assert response.status_code == 200
    assert len(response.json["devices"]) == 2

def test_admin_list_devices_forbidden_iap(client, mocker):
    """Varmistaa, että väärän domainin omaava IAP JWT palauttaa 403 Forbidden."""
    mocker.patch("app.admin._verify_iap_jwt", return_value="external.user@gmail.com")
    
    headers = {
        "X-Goog-IAP-JWT-Assertion": "external-jwt-token"
    }
    response = client.get("/admin/devices", headers=headers)
    assert response.status_code == 403
    assert response.json == {"error": "Käyttöoikeus evätty (vain falko.fi-käyttäjille)"}
