# Contributing — falko-mdm-server

Kiitos kiinnostuksesta! Tämä dokumentti kuvaa käytännöt koodin kirjoittamiseen,
kommentointiin, testaukseen ja repositorion rakenteen ylläpitoon.

---

## Tämän repon vastuu

`falko-mdm-server` vastaa yksinomaan **backend-palvelimen** elinkaaren hallinnasta:

- **Issuet:** Kaikki server-puolen bugi-ilmoitukset, tietoturvalöydökset ja
  arkkitehtuurimuutokset kirjataan **tähän repoon**. Älä avaa server-issueita
  `falko-mdm-ui`- tai `falko-device-onboarding`-repoihin.
- **Deployment-skriptit:** `deploy.sh`, `cloudbuild.yaml` ja `Dockerfile`
  kuuluvat tähän repoon. Ne deployvat **ainoastaan** tämän repon Cloud Run
  -palvelun. UI:n tai onboarding-skriptien deployment on niiden omien repojen
  vastuulla.
- **Terraform:** `terraform/`-kansio hallitsee tämän palvelun GCP-resurssit:
  Cloud Run -palvelu, Firestore-säännöt, Secret Manager -salaisuudet ja
  tähän palveluun liittyvät IAM-oikeudet. Firebase Hosting tai UI-resurssit
  eivät kuulu tänne.
- **Ympäristömuuttujat:** `IAP_AUDIENCE`, `GOOGLE_OAUTH_CLIENT_ID`, `SECRET_KEY`,
  `APNS_KEY_SECRET`, `BOOTSTRAP_ADMIN_EMAIL` — näiden hallinta on tämän repon
  Cloud Run -konfiguraatiossa ja Secret Managerissa.

### Reporajat lyhyesti

| Asia | Tämä repo | falko-mdm-ui | falko-device-onboarding |
|---|---|---|---|
| Server-bugi tai SEC-issue | ✅ | ❌ | ❌ |
| UI-bugi tai UX-issue | ❌ | ✅ | ❌ |
| Onboarding-skripti tai mobileconfig | ❌ | ❌ | ✅ |
| Cloud Run deploy | ✅ | ❌ | ❌ |
| Firebase Hosting deploy | ❌ | ✅ | ❌ |
| GCP Secret Manager (server-salaisuudet) | ✅ | ❌ | ❌ |

---

## Repositorion rakenne

```
falko-mdm-server/
├── app/
│   ├── __init__.py          # Tyhjä — merkitsee app/-kansion Python-paketiksi
│   ├── admin.py             # /admin/* -endpointit (IAP-suojattu)
│   ├── apns.py              # Apple Push Notification Service -herätys
│   ├── checkin.py           # Apple MDM Check-In (/checkin)
│   ├── db.py                # Firestore-abstraktio (laitteet + komentojono)
│   └── mdm.py               # Apple MDM Command endpoint (/mdm PUT)
├── tests/                   # Yksikkö- ja integraatiotestit (pytest)
│   ├── conftest.py          # Yhteiset fixturet: app-instanssi, mock-DB, mock-auth
│   ├── test_admin.py        # /admin/* -endpointit
│   ├── test_apns.py         # APNs push -logiikka
│   ├── test_checkin.py      # MDM Check-In -endpointit
│   ├── test_db.py           # Firestore-abstraktio
│   ├── test_mdm.py          # MDM Command -endpointit
│   ├── test_mdm_unit.py     # Yksikkötestit MDM-apufunktioille (ei Flask-kontekstia)
│   ├── test_middleware.py   # Rate limiting ja security headers
│   └── test_users.py        # Käyttäjähallinta (/admin/users/*)
├── main.py
├── pyproject.toml           # pytest + coverage -konfiguraatio
└── requirements.txt
```

### Periaatteet

- **Infrastructure as Code (IaC) Ensin:** Kaikki pilviresurssit hallitaan
  **yksinomaan Terraformilla** (`terraform/`-kansio).
- **Yksi tiedosto = yksi vastuu.** `db.py` koskee vain Firestore-operaatioita,
  `apns.py` vain APNs-yhteyttä jne.
- **Uusi toiminnallisuus = uusi Blueprint.** Jos tulee esim. VPP-integraatio,
  se saa oman `app/vpp.py`-tiedoston.
- **Testit peilaavat `app/`-rakennetta.** `tests/test_admin.py` testaa `app/admin.py`-koodia.

---

## Yksikkötestit

### Työkalut

| Työkalu | Rooli | Asennus |
|---|---|---|
| **pytest** | Testien ajaminen | `pip install pytest` |
| **pytest-flask** | Flask `test_client` -fixture automaattisesti | `pip install pytest-flask` |
| **pytest-cov** | Kattavuusraportti | `pip install pytest-cov` |
| **unittest.mock** | Riippuvuuksien mockaus (stdlib, ei erillistä asennusta) | — |

Kaikki testikirjastot löytyvät `requirements.txt`:stä. Asenna ne komennolla:

```bash
pip install -r requirements.txt
```

### Testipyramidi

Noudatamme testipyramidia (Fowler 2012, Martin 2019):

```
          /‾‾‾‾‾‾‾‾‾‾‾\
         /  E2E (vähän)  \
        /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
       / Integraatio (jonkin  \
      /  verran: HTTP-pyynöt  \
     /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
    /   Yksikkö (eniten):       \
   /    logiikka, apufunktiot    \
  /________________________________\
```

- **Yksikkötestit** (`test_mdm_unit.py`, `test_apns.py`): testaavat yksittäisiä
  funktioita ilman Flask-kontekstia tai verkkoyhteyksiä. Kaikki ulkoiset
  riippuvuudet (Firestore, Secret Manager, APNs HTTP) mockataan.
- **Integraatiotestit** (`test_admin.py`, `test_checkin.py`, `test_mdm.py`
  jne.): testaavat HTTP-endpointteja `test_client`:n kautta. DB ja ulkoiset
  palvelut mockataan — ei oikeaa Firestorea CI:ssä.
- **E2E-testit:** Ei tässä repossa. Staging-ympäristön smoke-testit ovat
  erillinen asia.

### Testien ajaminen

```bash
# Kaikki testit
pytest tests/ -v

# Yksittäinen tiedosto
pytest tests/test_admin.py -v

# Yksittäinen testi nimen perusteella
pytest tests/test_admin.py -k "test_danger_command_requires_admin" -v

# Kattavuusraportti (HTML)
pytest tests/ --cov=app --cov-report=html
# → avaa htmlcov/index.html selaimessa

# Kattavuus terminaaliin (nopea tarkistus)
pytest tests/ --cov=app --cov-report=term-missing
```

### Kattavuustavoite

| Moduuli | Minimikattavuus | Huomio |
|---|---|---|
| `app/admin.py` | 80 % | Auth-polut, DANGER-komennot, 403/401 |
| `app/apns.py` | 75 % | Token cache, Secret Manager fallback |
| `app/checkin.py` | 80 % | Authenticate, TokenUpdate, CheckOut |
| `app/db.py` | 70 % | Kaikki CRUD-operaatiot mockatusti |
| `app/mdm.py` | 80 % | Komennon haku, NotNow, tyhjä jono |
| `app/middleware.py` | 85 % | Rate limit, security headers |

Kattavuustavoite tarkistetaan CI:ssä (`cloudbuild.yaml`). PR ei mene läpi
jos kattavuus putoaa alle 75 %:n (`--cov-fail-under=75`).

> **Miksi 75–80 % eikä 100 %?** 100 %:n kattavuus voi johtaa
> merkityksettömiin testeihin jotka kasvattavat lukua mutta eivät löydä
> vikoja (Inozemtseva & Holmes 2014, ICSE). Tavoite on testata
> kaikki haarautumispisteet ja tietoturvapolut — ei jokainen lokiviesti.

### Nimeämiskäytäntö

Testifunktion nimi kertoo: **mitä testataan**, **millä syötteellä**, **mikä on odotettu tulos**.

```python
# Muoto: test_<asia>_<tilanne>_<odotus>
def test_send_command_danger_user_role_returns_403():     ...
def test_send_command_danger_admin_role_returns_200():    ...
def test_rate_limiter_over_limit_returns_429():           ...
def test_iap_jwt_missing_returns_401():                   ...
def test_apns_token_cache_reuses_within_ttl():            ...
```

### Fixture-käyttö (`conftest.py`)

Yhteiset fixturet ovat `tests/conftest.py`:ssä. Älä toista setUp-koodia
jokaisessa testitiedostossa.

```python
# tests/conftest.py — esimerkki fixture-rakenteesta
import pytest
from unittest.mock import patch, MagicMock
from main import create_app

@pytest.fixture()
def app():
    """Flask-sovellus testitilassa.
    LOCAL_DEV=1 jotta SECRET_KEY-vaatimus ei estä käynnistystä.
    """
    with patch.dict('os.environ', {'LOCAL_DEV': '1'}):
        yield create_app()

@pytest.fixture()
def client(app):
    """Flask test_client — lähettää HTTP-pyyntöjä ilman verkkoyhteyttä."""
    return app.test_client()

@pytest.fixture()
def mock_db(monkeypatch):
    """Korvaa kaikki db.*-funktiot MagicMock-objekteilla.
    Estää oikeat Firestore-kutsut CI-ympäristössä.
    """
    mock = MagicMock()
    monkeypatch.setattr('app.admin.get_device', mock.get_device)
    monkeypatch.setattr('app.admin.enqueue_command', mock.enqueue_command)
    return mock

@pytest.fixture()
def auth_user_headers():
    """HTTP-otsakkeet jotka läpäisevät require_auth:n user-roolilla.
    Käyttää BOOTSTRAP_ADMIN_EMAIL-logiikan ulkopuolista käyttäjää.
    """
    return {'X-Goog-IAP-JWT-Assertion': 'FAKE_USER_JWT'}

@pytest.fixture()
def auth_admin_headers():
    """HTTP-otsakkeet admin-roolille."""
    return {'X-Goog-IAP-JWT-Assertion': 'FAKE_ADMIN_JWT'}
```

### Mocking-strategia

Tässä projektissa on kolme ulkoista riippuvuutta jotka **aina** mockataan testeissä:

**1. Firestore (`app/db.py`)**
```python
# Käytä monkeypatch-fixturia tai unittest.mock.patch
with patch('app.admin.get_device', return_value={'udid': 'TEST', 'status': 'enrolled'}):
    resp = client.get('/admin/devices/TEST')
    assert resp.status_code == 200
```

**2. Google IAP / OAuth token-verifiointi**
```python
# _verify_iap_jwt ja _verify_google_oauth_token palauttavat sähköpostin
# — mock ohjaa autentikaation halutulle käyttäjälle
with patch('app.admin._verify_iap_jwt', return_value='user@falko.fi'), \
     patch('app.admin.get_user', return_value={'role': 'user', 'status': 'authorized'}):
    resp = client.get('/admin/devices', headers={'X-Goog-IAP-JWT-Assertion': 'x'})
    assert resp.status_code == 200
```

**3. APNs ja Secret Manager (`app/apns.py`)**
```python
# Patch httpx-asiakas — ei oikeita APNs-kutsuja testissä
with patch('app.apns._get_http_client') as mock_http:
    mock_http.return_value.post.return_value.status_code = 200
    result = send_push('TOKEN', 'MAGIC', 'com.apple.mdm')
    assert result is True
```

### Tietoturvatestien minimivaatimukset

Jokaisen `app/admin.py`-muutoksen yhteydessä seuraavat testit **täytyy** olla
kunnossa (OWASP ASVS v4.0 §4.1 — Access Control):

```python
# 1. Autentikoimaton pyyntö → 401
def test_list_devices_no_auth_returns_401(client):
    resp = client.get('/admin/devices')
    assert resp.status_code == 401

# 2. User-rooli yrittää DANGER-komentoa → 403
def test_erase_device_user_role_returns_403(client, mock_db):
    with patch('app.admin._get_authenticated_email', return_value='user@falko.fi'), \
         patch('app.admin.get_user', return_value={'role': 'user', 'status': 'authorized'}):
        resp = client.post(
            '/admin/devices/TEST-UDID/command',
            json={'command_type': 'EraseDevice'}
        )
        assert resp.status_code == 403

# 3. Tuntematon komento → 400 (allowlist-validointi)
def test_unknown_command_returns_400(client, mock_db):
    with patch('app.admin._get_authenticated_email', return_value='admin@falko.fi'), \
         patch('app.admin.get_user', return_value={'role': 'admin', 'status': 'authorized'}):
        resp = client.post(
            '/admin/devices/TEST-UDID/command',
            json={'command_type': 'MaliciousCommand'}
        )
        assert resp.status_code == 400

# 4. Rate limit ylittyy → 429
def test_rate_limit_exceeded_returns_429(client):
    for _ in range(61):  # RATE_LIMIT_REQUESTS = 60
        client.get('/admin/devices')
    resp = client.get('/admin/devices')
    assert resp.status_code == 429
```

### Mitä EI testata

- Flask-frameworkin omaa logiikkaa (routing, request parsing)
- Google-kirjastojen sisäistä toimintaa (`id_token.verify_token`)
- Firestore SDK:n sisäistä toimintaa
- `atexit`-kutsuja tai logging-formatteria

---

## Koodin kommentointi

### Filosofia

> Kommentoi **miksi**, ei **mitä**. Koodi kertoo jo mitä tapahtuu.
> Kommentti kertoo miksi se tapahtuu.

```python
# HUONO — selittää mitä koodi tekee (selvää koodista itsestään)
udid = data.get("UDID", "unknown")  # haetaan UDID datasta

# HYVÄ — selittää miksi valinta on tehty
udid = data.get("UDID", "unknown")  # Apple ei takaa UDID-kentän läsnäoloa Authenticate-viestissä
```

### Moduulit — docstring heti tiedoston alussa

Jokaisessa `app/`-tiedostossa tulee olla moduulitason docstring, joka kertoo:
1. Mitä moduuli tekee
2. Endpointit (jos Blueprint)
3. Linkit Apple-dokumentaatioon (MDM-protokollaan liittyvissä)

```python
"""Apple MDM Check-In endpoint (/checkin).

Käsittelee viestit:
  - Authenticate  — laitteen ensimmäinen yhteydenotto
  - TokenUpdate   — APNs push token päivittyy
  - CheckOut      — laite poistuu MDM-hallinnasta

Apple MDM Protocol Reference:
https://developer.apple.com/documentation/devicemanagement/check-in
"""
```

### Funktiot — docstring + tyyppimerkinnät

Kaikissa julkisissa funktioissa (ei `_`-alkuiset) tulee olla docstring ja
Python-tyyppimerkinnät (`->`, parametrityypit).

```python
def send_push(push_token: str, push_magic: str, topic: str, sandbox: bool = False) -> bool:
    """Lähettää MDM push-herätyksen laitteelle.

    Args:
        push_token: Laitteen APNs push token (hex-string)
        push_magic: Laitteen push magic string (saatu TokenUpdate-viestistä)
        topic:      APNs topic (esim. com.apple.mgmt.External.XXXX)
        sandbox:    True = käytä APNs sandbox -ympäristöä (kehitys)

    Returns:
        True jos push lähetettiin onnistuneesti, False muuten.
    """
```

Yksityiset apufunktiot (`_`-alkuiset) voivat käyttää lyhyttä yhden rivin docstringiä:

```python
def _build_command_plist(command_type: str, cmd_uuid: str, payload: dict | None = None) -> bytes:
    """Rakentaa MDM-komentovastausplistin."""
```

### Inline-kommentit — vain ei-ilmeisiin asioihin

```python
# Muoto: "accounts.google.com:jaakko@falko.fi"
email = user_header.split("accounts.google.com:")[1]

# MDM push payload on aina muotoa {"mdm": "<PushMagic>"} — Apple MDM spec s. 34
body = {"mdm": push_magic}

# NotNow tarkoittaa: laite ei juuri nyt pysty, ei virhetilaa
if status == "NotNow":
    ...
```

### TODO / FIXME -merkinnät

```python
# TODO(jaakko): Lisää Firestore-transaktio dequeue_command-funktioon (race condition)
# FIXME: APNs-token cachetaan moduulitasolla mutta ei ole thread-safe
# NOTE: Apple rajoittaa JWT-tokenin uusimistiheyttä — älä muuta 50 min -raja-arvoa
```

---

## Infrastruktuuri ja Terraform (IaC First)

1. **Infrastruktuuri kuuluu koodiin (`terraform/`):** Kaikki GCP-resurssit,
   ympäristömuuttujat, IAM-oikeudet ja Secret Manager -salaisuudet määritellään
   **yksinomaan `terraform/`-kansion `.tf`-tiedostoihin**.
2. **Terraform-koodin laatuvaatimukset:**
   - Kaikilla resurssilohkoilla tulee olla selventävä kommentti.
   - Suorita `terraform fmt` ennen jokaista committia.
   - Varmista `checkov -d terraform/` -tietoturvaskannauksen läpäisy.

---

## Kehitysympäristö

```bash
# 1. Kloonaa ja asenna riippuvuudet
git clone https://github.com/jaakkokorhonen/falko-mdm-server
cd falko-mdm-server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Ympäristömuuttujat paikalliseen ajoon
export LOCAL_DEV=1
export GCP_PROJECT=your-project-id
export APNS_TEAM_ID=XXXXXXXXXX
export APNS_KEY_ID=XXXXXXXXXX
export APNS_KEY_SECRET=projects/your-project/secrets/apns-key/versions/latest

# 3. Käynnistä kehitysserveri
python main.py

# 4. Aja testit (perus)
pytest tests/ -v

# 5. Aja testit kattavuusraportilla
pytest tests/ --cov=app --cov-report=term-missing --cov-fail-under=75
```

> **Huom:** Tuotantoympäristössä `IAP_AUDIENCE`, `GOOGLE_OAUTH_CLIENT_ID` ja
> `SECRET_KEY` ovat pakollisia. Palvelin ei käynnisty ilman niitä (paitsi
> `LOCAL_DEV=1` -tilassa).

---

## Deployment

```bash
# Manuaalinen deploy (käytä vain hätätilanteessa — normaali polku on CI/CD)
bash deploy.sh

# CI/CD: Google Cloud Build triggeröityy automaattisesti main-haaroituksesta
# Katso: cloudbuild.yaml
```

---

## Commit-käytännöt

Käytetään [Conventional Commits](https://www.conventionalcommits.org/) -muotoa:

| Tyyppi | Käyttö |
|---|---|
| `feat:` | Uusi toiminnallisuus |
| `fix:` | Bugikorjaus |
| `docs:` | Vain dokumentaatiomuutos |
| `refactor:` | Koodirakenne muuttuu, toiminta ei |
| `test:` | Testien lisäys tai korjaus |
| `chore:` | Riippuvuuspäivitys, CI-konfiguraatio |
| `security:` | Tietoturvakorjaus |

Esimerkit:
```
feat: lisää EraseDevice-komento admin-API:iin
fix: korjaa APNs JWT-tokenin cache-logiikka
security: verifioi IAP JWT-allekirjoitus google-auth-kirjastolla
test: lisää DANGER-komentojen roolitarkistustestit
docs: päivitä CONTRIBUTING.md testausohjeistuksella
```

---

## Pull Request -käytäntö

1. Tee muutokset omaan feature-haaraan: `git checkout -b feat/oma-ominaisuus`
2. Varmista että `pytest tests/ --cov=app --cov-fail-under=75` läpäisee
3. Varmista että uusi toiminnallisuus sisältää vastaavan testin
4. Päivitä `README.md` jos lisäät ympäristömuuttujan tai endpointin
5. Avaa PR `main`-haaraan — kuvaile muutoksen **miksi**, ei pelkästään mitä

---

## Tietoturvakäytännöt

- **Ei salaisuuksia koodissa.** Kaikki avaimet, tokenit ja tunnukset ympäristömuuttujina tai Secret Managerissa.
- **IAP ennen kaikkea.** Admin-endpointit eivät saa olla saavutettavissa ilman IAP-suojausta.
- **Riippuvuudet pinnattuina.** `requirements.txt` käyttää tarkkoja versioita (`==`).
- **Lokit ilman arkaluonteisia tietoja.** Älä loki koko push_token-arvoa tai käyttäjän sähköpostia `INFO`-tasolla — käytä osittaista maskauksia: `push_token[:16]`.
