"""Yksikkötestit app/apns.py -moduulille.

Kaikki ulkoiset kutsut (httpx, JWT, ympäristömuuttujat) on mockattu.
Testaa: JWT-token cache, send_push onnistuminen, virhetilanteet.
"""
import pytest
import time
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Apufunktio: asetetaan tarvittavat env-muuttujat
# ---------------------------------------------------------------------------

APNS_ENV = {
    "APNS_TEAM_ID": "TEAMID1234",
    "APNS_KEY_ID": "KEYID12345",
    "APNS_PRIVATE_KEY": "-----BEGIN EC PRIVATE KEY-----\nMOCKKEY\n-----END EC PRIVATE KEY-----",
}


# ---------------------------------------------------------------------------
# send_push — onnistuminen
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_send_push_returns_true_on_http_200(mocker, monkeypatch):
    """send_push palauttaa True kun APNs vastaa 200."""
    for k, v in APNS_ENV.items():
        monkeypatch.setenv(k, v)

    # Mock JWT-tokenin generointi
    mocker.patch("app.apns.jwt.encode", return_value="mock-jwt-token")
    # Mock httpx-vastaus
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_client = MagicMock()
    mock_client.post.return_value = mock_response
    mocker.patch("app.apns._get_http_client", return_value=mock_client)
    # Nollataan token cache
    mocker.patch("app.apns._apns_token_cache", None)

    from app.apns import send_push
    result = send_push(
        push_token="deadbeef" * 8,
        push_magic="magic",
        topic="com.apple.mgmt.External.test",
        sandbox=True,
    )
    assert result is True
    mock_client.post.assert_called_once()


# ---------------------------------------------------------------------------
# send_push — APNs-virhetilaneet
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_send_push_returns_false_on_http_410(mocker, monkeypatch):
    """send_push palauttaa False kun APNs palauttaa 410 (token vanhentunut)."""
    for k, v in APNS_ENV.items():
        monkeypatch.setenv(k, v)

    mocker.patch("app.apns.jwt.encode", return_value="mock-jwt-token")
    mock_response = MagicMock()
    mock_response.status_code = 410
    mock_client = MagicMock()
    mock_client.post.return_value = mock_response
    mocker.patch("app.apns._get_http_client", return_value=mock_client)
    mocker.patch("app.apns._apns_token_cache", None)

    from app.apns import send_push
    result = send_push("deadbeef" * 8, "magic", "com.apple.mgmt.External.test", sandbox=True)
    assert result is False


@pytest.mark.regression
def test_send_push_returns_false_on_http_400(mocker, monkeypatch):
    """send_push palauttaa False kun APNs palauttaa 400."""
    for k, v in APNS_ENV.items():
        monkeypatch.setenv(k, v)

    mocker.patch("app.apns.jwt.encode", return_value="mock-jwt-token")
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_client = MagicMock()
    mock_client.post.return_value = mock_response
    mocker.patch("app.apns._get_http_client", return_value=mock_client)
    mocker.patch("app.apns._apns_token_cache", None)

    from app.apns import send_push
    result = send_push("deadbeef" * 8, "magic", "com.apple.mgmt.External.test")
    assert result is False


# ---------------------------------------------------------------------------
# send_push — verkkovirhe
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_send_push_returns_false_on_network_error(mocker, monkeypatch):
    """send_push palauttaa False verkkovirheen (httpx.RequestError) sattuessa."""
    import httpx
    for k, v in APNS_ENV.items():
        monkeypatch.setenv(k, v)

    mocker.patch("app.apns.jwt.encode", return_value="mock-jwt-token")
    mock_client = MagicMock()
    mock_client.post.side_effect = httpx.RequestError("timeout")
    mocker.patch("app.apns._get_http_client", return_value=mock_client)
    mocker.patch("app.apns._apns_token_cache", None)

    from app.apns import send_push
    result = send_push("deadbeef" * 8, "magic", "com.apple.mgmt.External.test")
    assert result is False


# ---------------------------------------------------------------------------
# send_push — puuttuvat ympäristömuuttujat
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_send_push_returns_false_when_env_missing(mocker, monkeypatch):
    """send_push palauttaa False kun APNS_TEAM_ID puuttuu."""
    # Poistetaan kaikki APNS-env-muuttujat
    for k in APNS_ENV:
        monkeypatch.delenv(k, raising=False)
    # Nollataan token cache jotta generoidaan uusi
    mocker.patch("app.apns._apns_token_cache", None)
    mocker.patch("app.apns._get_http_client", return_value=MagicMock())

    from app.apns import send_push
    result = send_push("deadbeef" * 8, "magic", "com.apple.mgmt.External.test")
    assert result is False


# ---------------------------------------------------------------------------
# JWT-token cache
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_get_apns_token_cached_on_second_call(mocker, monkeypatch):
    """_get_apns_token palauttaa cachetun tokenin ilman uutta jwt.encode-kutsua."""
    for k, v in APNS_ENV.items():
        monkeypatch.setenv(k, v)

    mock_encode = mocker.patch("app.apns.jwt.encode", return_value="cached-token")
    # Nollataan cache
    import app.apns as apns_module
    apns_module._apns_token_cache = None

    from app.apns import _get_apns_token
    t1 = _get_apns_token()
    t2 = _get_apns_token()
    assert t1 == t2 == "cached-token"
    # jwt.encode kutsuttu vain kerran — toinen palautus tuli cachesta
    assert mock_encode.call_count == 1


@pytest.mark.regression
def test_get_apns_token_refreshed_after_ttl(mocker, monkeypatch):
    """_get_apns_token generoi uuden tokenin kun TTL on kulunut."""
    for k, v in APNS_ENV.items():
        monkeypatch.setenv(k, v)

    mock_encode = mocker.patch("app.apns.jwt.encode", side_effect=["token-old", "token-new"])
    import app.apns as apns_module
    # Asetetaan vanha token joka on jo vanhentunut
    apns_module._apns_token_cache = ("token-old", time.time() - 60 * 60)  # 60 min sitten

    from app.apns import _get_apns_token
    result = _get_apns_token()
    assert result == "token-new"
    assert mock_encode.call_count == 1  # uusi generointi
