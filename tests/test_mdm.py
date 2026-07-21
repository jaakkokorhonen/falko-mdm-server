import pytest

def test_mdm_endpoint_get_rejected(client):
    """Varmistaa, että GET /mdm ei ole sallittu (palauttaa 405 Method Not Allowed)."""
    response = client.get("/mdm")
    assert response.status_code == 405
