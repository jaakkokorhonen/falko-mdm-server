# Contributing — falko-mdm-server

Kiitos kiinnostuksesta! Tämä dokumentti kuvaa käytännöt koodin kirjoittamiseen,
kommentointiin ja repositorion rakenteen ylläpitoon.

---

## Repositorion rakenne

```
falko-mdm-server/
├── app/
│   ├── __init__.py          # Tyhjä — merkitsee app/-kansion Python-paketiksi
│   ├── admin.py             # /admin/* -endpointit (IAP-suojattu)
│   ├── apns.py              # Apple Push Notification Service -herätys
│   ├── checkin.py           # Apple MDM Check-In (/checkin)
│   ├── db.py                # Firestore-abstraktio (laitteet + komantojono)
│   └── mdm.py               # Apple MDM Command endpoint (/mdm PUT)
├── tests/                   # Yksikkötestit (pytest)
│   ├── __init__.py
│   ├── test_admin.py
│   ├── test_checkin.py
│   └── test_mdm.py
├── .gcloudignore            # Cloud Build -ohitus
├── cloudbuild.yaml          # Google Cloud Build -pipeline
├── deploy.sh                # Manuaalinen deploy-skripti
├── Dockerfile               # Container-image
├── main.py                  # Flask-sovelluksen sisääntulopiste
├── requirements.txt         # Pinnatut Python-riippuvuudet
├── CONTRIBUTING.md          # Tämä tiedosto
└── README.md
```

### Periaatteet

- **Infrastructure as Code (IaC) Ensin:** Kaikki pilviresurssit (Cloud Run, Firestore, Secret Manager, IAM, Monitoring, DNS) hallitaan **yksinomaan Terraformilla** (`terraform/`-kansio). Mitään GCP-resursseja ei luoda tai muokata manuaalisesti Google Cloud Consolesta tai gcloud-CLI-komennoilla tuotanto/staging-ympäristöissä.
- **Yksi tiedosto = yksi vastuu.** `db.py` koskee vain Firestore-operaatioita,
  `apns.py` vain APNs-yhteyttä jne. Älä lisää liiketoimintalogiikkaa `db.py`:hyn
  tai tietokantakutsuja `admin.py`:hyn.
- **Uusi toiminnallisuus = uusi Blueprint.** Jos tulee esim. VPP-integraatio,
  se saa oman `app/vpp.py`-tiedoston ja Blueprint-rekisteröinnin `main.py`:ssä.
- **Testit peilaavat `app/`-rakennetta.** `tests/test_admin.py` testaa `app/admin.py`-koodia.

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

Käytä standardimuotoa niin että ne löytyvät hakemalla:

```python
# TODO(jaakko): Lisää Firestore-transaktio dequeue_command-funktioon (race condition)
# FIXME: APNs-token cachetetaan modulitasolla mutta ei ole thread-safe
# NOTE: Apple rajoittaa JWT-tokenin uusimistiheyttä — älä muuta 50 min -raja-arvoa
```

---

## Infrastruktuuri ja Terraform (IaC First)

Tässä repositoriossa noudatetaan tiukkaa **"IaC First"** -periaatetta:

1. **Infrastruktuuri kuuluu koodiin (`terraform/`):**
   - Jos uusi ominaisuus vaatii GCP-resurssin, ympäristömuuttujan, IAM-oikeuden, Secret Manager -salaisuuden, Cloud Run -muutoksen tai lokitus/hälytyssäännön, se **määritellään aina `terraform/`-kansion `.tf`-tiedostoihin**.
   - Älä dokumentoi teknisiin ohjeisiin manuaalisia `gcloud ...` -komentoja resursseille — kirjoita vastaava `resource "google_..."` Terraformiin ja määrittele muuttujat `variables.tf`:ssä.

2. **Terraform-koodin laatuvaatimukset:**
   - Kaikilla resurssilohkoilla tulee olla selventävä kommentti (*miksi* resurssi on olemassa ja *mikä* sen tietoturvavaikutus on).
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
pip install pytest pytest-flask  # testikirjastot

# 2. Ympäristömuuttujat paikalliseen ajoon
export GCP_PROJECT=your-project-id
export APNS_TEAM_ID=XXXXXXXXXX
export APNS_KEY_ID=XXXXXXXXXX
export APNS_PRIVATE_KEY="$(cat path/to/key.p8)"

# 3. Käynnistä kehitysserveri
python main.py

# 4. Aja testit
pytest tests/ -v
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
docs: päivitä CONTRIBUTING.md kommentointikäytännöillä
```

---

## Pull Request -käytäntö

1. Tee muutokset omaan feature-haaraan: `git checkout -b feat/oma-ominaisuus`
2. Varmista että `pytest tests/` läpäisee
3. Päivitä `README.md` jos lisäät ympäristömuuttujan tai endpointin
4. Avaa PR `main`-haaraan — kuvaile muutoksen **miksi**, ei pelkästään mitä

---

## Tietoturvakäytännöt

- **Ei salaisuuksia koodissa.** Kaikki avaimet, tokenit ja tunnukset ympäristömuuttujina.
- **IAP ennen kaikkea.** Admin-endpointit eivät saa olla saavutettavissa ilman IAP-suojausta.
  Katso [README: Tietoturvaperiaate](./README.md#tietoturvaperiaate-iap-rajaa-luottamuksen-cloud-runiin).
- **Riippuvuudet pinnattuina.** `requirements.txt` käyttää tarkkoja versioita (`==`). Päivitykset
  tehdään tietoisesti, ei automaattisesti.
- **Lokit ilman arkaluonteisia tietoja.** Älä loki koko push_token-arvoa tai käyttäjän sähköpostia
  `INFO`-tasolla — käytä osittaista maskauksia: `push_token[:16]`.
