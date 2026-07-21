# falko-mdm-server

Minimalistinen Apple MDM -palvelin Falkon laitehallintaan.  
Pyörii Google Cloud Runilla, tallentaa laitetiedot Firestoreen.

Toimii yhdessä [falko-device-onboarding](https://github.com/jaakkokorhonen/falko-device-onboarding) -repon kanssa.

---

## Tietoturvaperiaate: IAP ja OIDC

Tämä palvelin pyörii Cloud Runilla ja käyttää Firestorea. Molemmat ovat jo Googlen luottamuspiirissä. Admin-rajapinta on suojattu **Identity-Aware Proxy (IAP)** -tasolla, mikä korvaa perinteisen token-pohjaisen tunnistautumisen Google Workspace OIDC -istunnoilla:

- **OIDC käyttöliittymässä (UI):** Käyttöliittymässä ei tarvitse olla omaa kirjautumistoiminnallisuutta tai kirjastoa. Kun käyttäjä menee selaimella admin-UI-osoitteeseen, Google IAP sieppaa pyynnön verkkokerroksessa ja ohjaa kirjautumattoman käyttäjän Googlen Workspace OIDC -kirjautumissivulle.
- **Istunnon välitys (Cookies):** Onnistuneen kirjautumisen jälkeen selain saa Googlen istuntoevästeen. Kaikki käyttöliittymästä palvelimelle tehtävät API-pyynnöt kulkevat `credentials: 'include'` -asetuksella, jolloin selain liittää evästeen pyyntöihin automaattisesti.
- **Identiteetin välitys palvelimelle (Headers):** IAP tarkistaa pyynnöt verkkokerroksessa, riisuu arkaluontoiset evästeet ja välittää pyynnön Flask-sovellukselle lisäten luotetut otsakkeet:
  * `X-Goog-Authenticated-User-Email` — käyttäjän sähköpostiosoite (muodossa `accounts.google.com:jaakko@falko.fi`).
  * `X-Goog-Authenticated-User-Id` — uniikki käyttäjä-ID.
  * `X-Goog-IAP-JWT-Assertion` — Googlen allekirjoittama kryptografinen JWT-varmenne.
- **Domain-rajoitus:** Flask-palvelin (`app/admin.py`) lukee sähköpostin otsakkeesta ja varmistaa, että sen loppuosa on `@falko.fi`. Muut pyynnöt hylätään automaattisesti.

> **Periaate:** Kun infrastruktuuri on jo GCP:ssä, autentikaatio kuuluu infrastruktuuriin — ei sovelluskoodiin.

### IAP:n aktivointi

```bash
# Aktivoi IAP Cloud Run -palvelulle
gcloud services enable iap.googleapis.com

# Salli pääsy vain Falkon Workspace-domainille
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --member="domain:falko.fi" \
  --role="roles/iap.httpsResourceAccessor"
```

---

## Arkkitehtuuri

```
iPhone/Mac
  │
  ├── POST /checkin   → Authenticate / TokenUpdate / CheckOut
  └── PUT  /mdm       → Komennon pollaus

Admin (IAP-suojattu: vain @falko.fi)
  └── GET/POST /admin/devices/*  → Laitelistaus ja komennot
                                    ↑
                              X-Goog-Authenticated-User-Email

Google IAP ──► Cloud Run ──► Firestore
                                └── devices/{udid}/
                                        ├── laitetiedot
                                        └── commands/{id}   ← komentojen jono
```

---

## Ympäristömuuttujat

| Muuttuja | Pakollinen | Kuvaus |
|---|---|---|
| `GCP_PROJECT` | Kyllä | GCP-projektin tunnus |
| `SECRET_KEY` | Kyllä | Flaskin session-salaisuus |
| `APNS_TEAM_ID` | APNs-pushin | Apple Developer Team ID |
| `APNS_KEY_ID` | APNs-pushin | APNs-avaimen Key ID |
| `APNS_PRIVATE_KEY` | APNs-pushin | APNs .p8-avain PEM-muodossa (rivinvaihto `\n`) |
| `APNS_SANDBOX` | Ei | `true` = sandbox-APNs (kehitys) |


Aseta Cloud Runiin:
```bash
gcloud run services update falko-mdm-server \
  --region=europe-north1 \
  --set-secrets=APNS_PRIVATE_KEY=falko-apns-key:latest \
  --set-env-vars=GCP_PROJECT=YOUR_PROJECT_ID,APNS_TEAM_ID=XXXXXXXXXX,APNS_KEY_ID=XXXXXXXXXX
```

---

## Deploy

### 1. Esivaatimukset

```bash
# Aktivoi GCP-palvelut
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com firestore.googleapis.com iap.googleapis.com

# Luo Artifact Registry
gcloud artifacts repositories create falko \
  --repository-format=docker \
  --location=europe-north1

# Luo Firestore-tietokanta (Native mode)
gcloud firestore databases create --region=europe-north1
```

### 2. Manuaalinen deploy

```bash
gcloud run deploy falko-mdm-server \
  --source . \
  --region=europe-north1 \
  --allow-unauthenticated \
  --set-env-vars=GCP_PROJECT=$(gcloud config get-value project)
```

### 3. CI/CD (Cloud Build)

Luo trigger GitHub-reposta:
```bash
gcloud builds triggers create github \
  --repo-name=falko-mdm-server \
  --repo-owner=jaakkokorhonen \
  --branch-pattern='^main$' \
  --build-config=cloudbuild.yaml
```

---

## Admin API

Admin-endpointit on suojattu IAP:lla (`domain:falko.fi`). Suorissa API-kutsuissa
(CI, skriptit) käytetään `Authorization: Bearer <ADMIN_TOKEN>` -fallbackia.

### Laitteiden listaus
```bash
# IAP-autentikoitu selain hoitaa tokenin automaattisesti
# Skriptikäyttö:
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://falko-mdm-server-xxx-lm.a.run.app/admin/devices
```

### Komennon lähettäminen

```bash
# Laitteen lukitseminen
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command_type": "DeviceLock"}' \
  https://falko-mdm-server-xxx-lm.a.run.app/admin/devices/<UDID>/command

# APNs herätys (laite hakee komennon heti)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://falko-mdm-server-xxx-lm.a.run.app/admin/devices/<UDID>/push
```

### Tuetut MDM-komennot

| command_type | Toiminto |
|---|---|
| `DeviceInformation` | Laitetietojen kysely |
| `DeviceLock` | Lukitsee laitteen välittömästi |
| `EraseDevice` | Pyyhkii laitteen |
| `InstallApplication` | Sovellusasennus (vaatii VPP) |
| `RestartDevice` | Uudelleenkäynnistys |
| `ShutDownDevice` | Sammutus |
| `EnableRemoteDesktop` | Etätyöpöytä päälle |
| `DisableRemoteDesktop` | Etätyöpöytä pois |

---

## APNs-avainparin hankkiminen

1. [developer.apple.com](https://developer.apple.com) → Certificates, Identifiers & Profiles → Keys
2. Luo avain, valitse **Apple Push Notifications service (APNs)**
3. Lataa `.p8`-tiedosto (vain kerran ladattavissa)
4. Tallenna `Key ID` ja `Team ID`
5. Muunna sisältö Cloud Run -secretiksi:
   ```bash
   gcloud secrets create falko-apns-key --data-file=AuthKey_XXXXXXXXXX.p8
   ```

---

## Julkaisu (Deploy)

Voit julkaista palvelimen ja luoda tarvittavan GCP-infrastruktuurin manuaalisesti:

```bash
chmod +x deploy.sh
./deploy.sh
```

### Avaimet ja ympäristömuuttujat
Skripti tarkistaa Secret Managerin ja kysyy tarvittaessa polun paikalliseen APNs-avaintiedostoon (`.p8`), jonka se lataa turvallisesti pilveen. Se kysyy myös Apple **Team ID** ja **Key ID** -tunnukset ja asettaa ne Cloud Runin ympäristömuuttujiksi sekä generoi satunnaisen Flask `SECRET_KEY`-avaimen.

---

## Verkkotunnuksen vahvistus (mdm-api.falko.fi)

Google Cloud Run vaatii, että vahvistat domainisi (`falko.fi`) omistajuuden Google Search Consolessa ennen kuin domain-mäppäys voidaan ottaa käyttöön:

1. Aja komento `gcloud domains verify falko.fi` avataksesi Search Consolen selaimeen.
2. Lisää tarvittaessa Search Consolen antama `google-site-verification` -tietue (TXT) domainisi DNS-vyöhykkeelle (`falko-fi-zone` `froide`-projektissa).
3. Kun omistajuus on vahvistettu, skripti pystyy luomaan mäppäyksen.
4. Lisää CNAME-tietue: `mdm-api.falko.fi` -> `ghs.googlehosted.com.` DNS-hallinnassasi.

---

## macOS MDM Onboarding & Apple Push (APNs)

macOS-laitteiden MDM-rekisteröinti vaatii **laiteprofiilin** (`FalkoMDMEnrollment.mobileconfig`), joka löytyy [falko-device-onboarding](https://github.com/jaakkokorhonen/falko-device-onboarding) -repositoriosta.

### 1. MDM Vendor -oikeuksien hakeminen (Apple)
Apple vaatii MDM-palvelimelta push-tunnuksen (Topic). Tämän saamiseksi sinun tulee olla osa Applen MDM Vendor -ohjelmaa:
1. Lähetä pyyntö osoitteessa: **[developer.apple.com/contact](https://developer.apple.com/contact)** (Valitse *Certificates, Identifiers, and Provisioning Profiles*).
2. Pyydä oikeutta luoda **MDM CSR Signing Certificate** (MDM Vendor program). Hyväksyntä kestää yleensä muutaman arkipäivän.

### 2. MDM Push -sertifikaatin luonti
1. Kun oikeudet on myönnetty, luo varmennepyyntö Keychainilla (Mac) ja luo Developer-portaalissa **MDM CSR Signing Certificate**.
2. Allekirjoita varmennepyyntö ja lataa se Applen Push-portaaliin: **[identity.apple.com/pushcert](https://identity.apple.com/pushcert)**.
3. Lataa valmis push-sertifikaatti, lue sen `Topic`-tunnus (UID-kenttä, esim. `com.apple.mgmt.External.xxxxxx`) ja sijoita se `FalkoMDMEnrollment.mobileconfig` -tiedoston `<key>Topic</key>`-kenttään.

### 3. Profiilin asennus laitteeseen
Avaa profiili laitteellasi:
```bash
open FalkoMDMEnrollment.mobileconfig
```
Mene kohtaan **System Settings -> Privacy & Security -> Profiles** ja suorita asennus loppuun ylläpitäjän tunnuksilla.

---

## Huomioita tuotantokäyttöön

- **TLS pakollinen** — Apple MDM vaatii HTTPS:n. Cloud Run tarjoaa tämän automaattisesti.
- **Julkinen pääsy** — Cloud Run -palvelun täytyy olla julkinen (`--allow-unauthenticated`), jotta laitteet voivat ottaa yhteyttä `/checkin` ja `/mdm` reitteihin. Admin-rajapinnat (`/admin/*`) on suojattu kooditasolla Google IAP JWT-assertion tarkistuksella.
- **Firestore-indeksit** — `commands`-kokoelman `status + created_at` -compositeindeksi tarvitaan jos laitteilla on paljon komentoja jonossa. Luo Firestore-konsolissa.

---

## CI/CD & DevSecOps -testausputki

Järjestelmässä on käytössä kaksivaiheinen build- ja tietoturvatestausputki:

### 1. Kooditason testaus (GitHub Actions)
Jokaisesta commitista ja Pull Requestistä main-haaraan ajetaan automaattinen laadun- ja tietoturvanvarmistus:
*   **Yksikkötestit (`pytest`)**: Ajaa `tests/test_routes.py` -tiedoston testit mockatulla tietokannalla. Voit ajaa ne myös paikallisesti: `./scripts/run_tests.sh`.
*   **Secret Scanning (`gitleaks`)**: Estää salaisten avainten tai salasanojen pushaamisen koodiin.
*   **SAST (`bandit`)**: Skannaa Python-koodin haavoittuvuuksien varalta.
*   **SCA (`pip-audit`)**: Tarkastaa, ettei asennetuissa Python-kirjastoissa ole tunnettuja haavoittuvuuksia (CVE).
*   **IaC-skannaus (`checkov`)**: Varmistaa, että Terraform-tiedostot noudattavat tietoturvasuosituksia.

### 2. Julkaisu pilveen (Google Cloud Build)
Kun koodi yhdistetään `main`-haaraan, GCP Cloud Build hoitaa automaattisen julkaisun:
1.  **Kääntäminen:** Kääntää Docker-kuvan ja pushaa sen Artifact Registryyn.
2.  **Kontin skannaus:** GCP:n **Artifact Analysis** skannaa uuden kontin tietoturvahaavoittuvuudet heti pushauksen jälkeen.
3.  **Infrastruktuuri:** Ajaa Terraform-koodin (`terraform apply`) päivittäen palvelimet ja muutokset pilvessä.

#### Cloud Build -muuttujat (Substitutions)
Määritä Cloud Build Triggerissä seuraavat käyttäjän määrittämät muuttujat salaisuuksien välittämiseksi Terraformille:
*   `_APNS_TEAM_ID` (Apple Developer Team ID)
*   `_APNS_KEY_ID` (APNs Key ID)
*   `_SECRET_KEY` (Flask session secret key)

---

## Tuotantoympäristön arkkitehtuuri (Terraform)

Terraform-hakemisto (`terraform/`) luo tuotantovalmiin, tietoturvallisen ja vikasietoisen infrastruktuurin:
- **Tietoturva (Cloud Armor):** Rajaa ja rajoittaa pyyntömäärät tasoon 100 req/min per IP-osoite (`security.tf`).
- **Verkko (VPC Egress & Cloud NAT):** Kaikki ulospäin suuntautuva liikenne (mukaan lukien yhteys Applen APNs-palveluun) ohjataan Serverless VPC Access Connectorin ja Cloud NAT -yhdyskäytävän kautta kiinteillä IP-osoitteilla (`network.tf`).
- **Tietojen palautus (PITR & Varmuuskopiot):** Firestorelle on otettu käyttöön Point-in-Time Recovery (PITR) sekä päivittäiset automaattiset varmuuskopiot (`main.tf`).
- **Audit-logitus (BigQuery):** Kaikki järjestelmän audit-tapahtumat ohjataan Log Sinkingin kautta automaattisesti BigQueryyn tallennettavaksi (`main.tf`).
- **Valvonta (Cloud Monitoring):** Kriittisistä virheistä ja APNs-varmenteen vanhentumisesta on luotu logipohjaiset hälytysrajat ilman sähköpostihälytyksiä (`monitoring.tf`).


