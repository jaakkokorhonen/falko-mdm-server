"""Integraatiotestit app/middleware.py -moduulille.

Kattaa:
  Rate limiting:
    - Sliding window -logiikka: pyynöt rajan sisällä hyväksytään
    - Raja ylittyy: 429 oikealla JSON-formaatilla
    - /healthz on vapautettu rate limitistä
    - X-Forwarded-For: ensimmäinen IP tunnistetaan
    - Eri IP:t eivät jaa laskuria
  Security headers:
    - Content-Security-Policy
    - X-Content-Type-Options
    - X-Frame-Options
    - Referrer-Policy
    - Permissions-Policy
    - Headerit läsnä sekä onnistumis- että virhevastauksissa
"""
import pytest
from unittest.mock import patch
import app.middleware as mw


# ---------------------------------------------------------------------------
# Apufunktiot
# ---------------------------------------------------------------------------

def _exhaust_rate_limit(client, limit, path="/healthz"):
    """Tyhjentää rate limit -ikkunan tekemällä `limit` pyyntöä annettuun polkuun."""
    for _ in range(limit):
        client.get(path)


# ---------------------------------------------------------------------------
# Security headers — smoke-taso
# ---------------------------------------------------------------------------

@pytest.mark.smoke
def test_security_headers_present_on_200(client):
    """Security headerit löytyvät onnistuneen vastauksen yhteydessä."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    assert "X-Content-Type-Options" in response.headers
    assert "X-Frame-Options" in response.headers
    assert "Referrer-Policy" in response.headers
    assert "Permissions-Policy" in response.headers


@pytest.mark.smoke
def test_security_header_csp_value(client):
    """CSP-headerin arvo sisältää 'default-src' ja 'frame-ancestors'."""
    response = client.get("/healthz")
    csp = response.headers["Content-Security-Policy"]
    assert "default-src" in csp
    assert "frame-ancestors" in csp


@pytest.mark.smoke
def test_security_header_x_content_type_options(client):
    """X-Content-Type-Options on 'nosniff'."""
    response = client.get("/healthz")
    assert response.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.smoke
def test_security_header_x_frame_options(client):
    """X-Frame-Options on 'DENY'."""
    response = client.get("/healthz")
    assert response.headers["X-Frame-Options"] == "DENY"


@pytest.mark.smoke
def test_security_header_referrer_policy(client):
    """Referrer-Policy on 'no-referrer'."""
    response = client.get("/healthz")
    assert response.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.smoke
def test_security_header_permissions_policy(client):
    """Permissions-Policy sisältää geolocation, camera ja microphone."""
    response = client.get("/healthz")
    pp = response.headers["Permissions-Policy"]
    assert "geolocation" in pp
    assert "camera" in pp
    assert "microphone" in pp


@pytest.mark.regression
def test_security_headers_present_on_404(client):
    """Security headerit löytyvät myös virhevastauksesta (404)."""
    response = client.get("/nonexistent-path-xyz")
    assert "X-Content-Type-Options" in response.headers
    assert "X-Frame-Options" in response.headers
    assert "Content-Security-Policy" in response.headers


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

@pytest.mark.smoke
def test_rate_limit_healthz_not_limited(client):
    """/healthz ei saa 429:ää vaikka kutsutaan yli rajan."""
    # Asetetaan pieni raja ja kutsutaan reilusti yli
    with patch.object(mw, "_RATE_LIMIT_REQUESTS", 3), \
         patch.object(mw, "_RATE_LIMIT_WINDOW", 60), \
         patch.dict(mw._request_counts, {}, clear=True):
        for _ in range(10):
            resp = client.get("/healthz")
            # /healthz ei saa koskaan saada 429
            assert resp.status_code != 429, "/healthz sai 429 — healthz-vapautus rikki"


@pytest.mark.regression
def test_rate_limit_allows_requests_under_limit(client):
    """Pyynöt rajan sisällä läpäistään normaalisti (ei 429)."""
    with patch.object(mw, "_RATE_LIMIT_REQUESTS", 5), \
         patch.object(mw, "_RATE_LIMIT_WINDOW", 60), \
         patch.dict(mw._request_counts, {}, clear=True):
        for i in range(5):
            resp = client.get(
                "/admin/devices",
                headers={"X-Forwarded-For": "10.0.0.1"},
            )
            assert resp.status_code != 429, f"Pyyntö {i+1}/5 hylättiin ennenaikaisesti"


@pytest.mark.regression
def test_rate_limit_returns_429_when_exceeded(client):
    """Raja ylittyy: seuraava pyyntö saa 429."""
    with patch.object(mw, "_RATE_LIMIT_REQUESTS", 3), \
         patch.object(mw, "_RATE_LIMIT_WINDOW", 60), \
         patch.dict(mw._request_counts, {}, clear=True):
        for _ in range(3):
            client.get("/admin/devices", headers={"X-Forwarded-For": "10.0.0.2"})
        resp = client.get("/admin/devices", headers={"X-Forwarded-For": "10.0.0.2"})
        assert resp.status_code == 429


@pytest.mark.regression
def test_rate_limit_429_response_format(client):
    """429-vastaus on JSON jolla on 'error'-avain."""
    with patch.object(mw, "_RATE_LIMIT_REQUESTS", 1), \
         patch.object(mw, "_RATE_LIMIT_WINDOW", 60), \
         patch.dict(mw._request_counts, {}, clear=True):
        client.get("/admin/devices", headers={"X-Forwarded-For": "10.0.0.3"})
        resp = client.get("/admin/devices", headers={"X-Forwarded-For": "10.0.0.3"})
        assert resp.status_code == 429
        data = resp.get_json()
        assert data is not None, "Vastaus ei ole JSON"
        assert "error" in data, f"JSON-vastauksesta puuttuu 'error'-avain: {data}"


@pytest.mark.regression
def test_rate_limit_x_forwarded_for_first_ip(client):
    """X-Forwarded-For: ensimmäinen IP tunnistetaan, ei koko otsikon arvo."""
    with patch.object(mw, "_RATE_LIMIT_REQUESTS", 2), \
         patch.object(mw, "_RATE_LIMIT_WINDOW", 60), \
         patch.dict(mw._request_counts, {}, clear=True):
        # Kaksi pyyntöä IP:ltä 10.10.10.1 (proxy-ketjun ensimmäinen)
        for _ in range(2):
            client.get(
                "/admin/devices",
                headers={"X-Forwarded-For": "10.10.10.1, 172.16.0.1, 10.0.0.1"},
            )
        # Kolmas sama ensimmäinen IP -> 429
        resp = client.get(
            "/admin/devices",
            headers={"X-Forwarded-For": "10.10.10.1, 172.16.0.1, 10.0.0.1"},
        )
        assert resp.status_code == 429


@pytest.mark.regression
def test_rate_limit_different_ips_independent(client):
    """Eri IP-osoitteiden laskurit ovat toisistaan riippumattomia."""
    with patch.object(mw, "_RATE_LIMIT_REQUESTS", 2), \
         patch.object(mw, "_RATE_LIMIT_WINDOW", 60), \
         patch.dict(mw._request_counts, {}, clear=True):
        # Tyhjennä IP A:n kiintiö
        for _ in range(2):
            client.get("/admin/devices", headers={"X-Forwarded-For": "192.168.1.1"})
        # IP B ei ole käyttänyt yhtään — sen pitää päästä läpi
        resp = client.get("/admin/devices", headers={"X-Forwarded-For": "192.168.1.2"})
        assert resp.status_code != 429, "IP B hylättiin vaikka se ei ole ylittänyt rajaa"


@pytest.mark.regression
def test_rate_limit_security_headers_on_429(client):
    """Security headerit ovat läsnä myös 429-vastauksessa."""
    with patch.object(mw, "_RATE_LIMIT_REQUESTS", 1), \
         patch.object(mw, "_RATE_LIMIT_WINDOW", 60), \
         patch.dict(mw._request_counts, {}, clear=True):
        client.get("/admin/devices", headers={"X-Forwarded-For": "10.0.0.99"})
        resp = client.get("/admin/devices", headers={"X-Forwarded-For": "10.0.0.99"})
        assert resp.status_code == 429
        assert "X-Content-Type-Options" in resp.headers
        assert "X-Frame-Options" in resp.headers
