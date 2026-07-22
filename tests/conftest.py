"""Yhteiset pytest-fixturet kaikille testitiedostoille.

Fixturehierarkia:
  app        → Flask-sovellus testitilassa (LOCAL_DEV=1, ei oikeaa SECRET_KEY:tä)
  client     → Flask test_client app-fixturesta
  mock_db    → kaikki app.admin.*-DB-funktiot korvattu MagicMock-objekteilla
  admin_user_record   → Firestore-käyttäjäobjekti admin-roolille
  regular_user_record → Firestore-käyttäjäobjekti user-roolille

Mocking-strategia:
  Ulkoiset riippuvuudet (Firestore, IAP JWT, OAuth, APNs, Secret Manager)
  mockataan AINA testeissä — CI-ympäristössä ei ole pääsyä GCP-palveluihin.
  Mockaukset tehdään mahdollisimman lähellä kutsupaikkaa (app.admin.*)
  eikä kirjaston tasolla — tämä tekee testeistä robustimpia refaktorointia
  vastaan.

Ref: pytest fixtures best practices — https://docs.pytest.org/en/stable/reference/fixtures.html
Ref: CONTRIBUTING.md §Fixture-käyttö
"""
import pytest
from unittest.mock import MagicMock, patch
from main import create_app


# ---------------------------------------------------------------------------
# Sovellus- ja HTTP-client-fixturet
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    """Luo Flask-sovelluksen testitilassa.

    LOCAL_DEV=1 aktivoituu jotta SECRET_KEY-vaatimus ei estä käynnistystä.
    SECRET_KEY generoidaan väliaikaiseksi (secrets.token_urlsafe) — tämä on
    tarkoituksellista: testisessioiden ei tarvitse persistoida.

    Yields:
        Flask-sovellus (ei käynnissä, vain WSGI-objekti).
    """
    with patch.dict('os.environ', {
        'LOCAL_DEV': '1',
        # BOOTSTRAP_ADMIN_EMAIL tyhjäksi — bootstrap-admin-testit asettavat sen itse
        'BOOTSTRAP_ADMIN_EMAIL': '',
    }):
        yield create_app()


@pytest.fixture()
def client(app):
    """Flask test_client HTTP-pyyntöjen lähettämiseen ilman verkkoyhteyttä.

    Args:
        app: app-fixture.

    Returns:
        FlaskClient-instanssi.
    """
    return app.test_client()


# ---------------------------------------------------------------------------
# Käyttäjäobjekti-fixturet (Firestore-vasteet)
# ---------------------------------------------------------------------------

@pytest.fixture()
def admin_user_record():
    """Simuloi Firestoren käyttäjäobjektia admin-roolilla.

    Käytetään patch('app.admin.get_user', return_value=admin_user_record)
    -tyyppisissä testeissä jotka testaavat require_admin-dekoraattoria.

    Returns:
        dict joka vastaa Firestoren users-dokumentin rakennetta.
    """
    return {
        'email': 'admin@falko.fi',
        'role': 'admin',
        'status': 'authorized',
    }


@pytest.fixture()
def regular_user_record():
    """Simuloi Firestoren käyttäjäobjektia user-roolilla.

    Käytetään testeissä jotka varmistavat että user-rooli ei pääse
    DANGER-komentoihin tai /users-endpointteihin.

    Returns:
        dict joka vastaa Firestoren users-dokumentin rakennetta.
    """
    return {
        'email': 'user@falko.fi',
        'role': 'user',
        'status': 'authorized',
    }


# ---------------------------------------------------------------------------
# DB-mock-fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_db(monkeypatch):
    """Korvaa kaikki app.admin.*-DB-funktiot MagicMock-objekteilla.

    Tämä estää oikeat Firestore-kutsut CI-ympäristössä. Kaikki mock-metodit
    ovat MagicMock-oletusarvoja — yksittäinen testi voi ylikirjoittaa
    haluamansa (esim. mock_db.get_device.return_value = {...}).

    Args:
        monkeypatch: pytest-fixture moduulitason symbolien korvaamiseen.

    Returns:
        MagicMock-objekti jossa get_device, enqueue_command, list_devices,
        send_push, get_user, upsert_user, list_users, update_user_status
        -attribuutit.
    """
    mock = MagicMock()

    # Laite jota useimmat testit käyttävät oletuksena
    mock.get_device.return_value = {
        'udid': 'TEST-UDID-0001',
        'serial': 'C02XG0JJHTD6',
        'model': 'MacBookPro18,1',
        'status': 'enrolled',
    }
    # Kaksielementtinen laitelista list_devices-kutsulle
    mock.list_devices.return_value = (
        [
            {'udid': 'device-1', 'serial': 'C02AA111', 'status': 'enrolled'},
            {'udid': 'device-2', 'serial': 'C02BB222', 'status': 'enrolled'},
        ],
        None,  # next_page_token
    )
    # enqueue_command palauttaa komento-ID:n
    mock.enqueue_command.return_value = 'cmd-uuid-abcd'

    # Monkeypatch: korvataan app.admin-moduulissa käytetyt nimet
    monkeypatch.setattr('app.admin.get_device',          mock.get_device)
    monkeypatch.setattr('app.admin.enqueue_command',     mock.enqueue_command)
    monkeypatch.setattr('app.admin.list_devices',        mock.list_devices)
    monkeypatch.setattr('app.admin.send_push',           mock.send_push)
    monkeypatch.setattr('app.admin.get_user',            mock.get_user)
    monkeypatch.setattr('app.admin.upsert_user',         mock.upsert_user)
    monkeypatch.setattr('app.admin.list_users',          mock.list_users)
    monkeypatch.setattr('app.admin.update_user_status',  mock.update_user_status)

    return mock
