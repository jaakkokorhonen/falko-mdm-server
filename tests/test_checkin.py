import pytest

def test_healthz(client):
    """Varmistaa, että /healthz palauttaa 200 OK ja oikean statuksen."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}

def test_checkin_auth_missing_plist(client):
    """Varmistaa, että POST /checkin ilman dataa palauttaa 400 Bad Request."""
    response = client.post("/checkin")
    assert response.status_code == 400
    assert "error" in response.json
