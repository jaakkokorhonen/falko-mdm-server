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

## Huomioita tuotantokäyttöön

- **TLS pakollinen** — Apple MDM vaatii HTTPS:n. Cloud Run tarjoaa tämän automaattisesti.
- **IAP ennen tuotantoon vientiä** — aktivoi IAP ja poista `--allow-unauthenticated` deploy-komennosta kun admin-UI on käytössä.
- **Profiilin allekirjoitus** — `FalkoMDMEnrollment.mobileconfig` täytyy allekirjoittaa koodisertifikaatilla ennen jakelua (macOS 13+). Käytä `openssl smime` tai Appleʼn `profiles` -työkalua.
- **MDM-sertifikaatti** — Tämä serveri käyttää JWT-autentikaatiota (token-based MDM). Jos haluat sertifikaattipohjaisen MDM:n, lisää TLS-asiakasvarmennuksen käsittely `/checkin`-endpointiin.
- **Firestore-indeksit** — `commands`-kokoelman `status + created_at` -compositeindeksi tarvitaan jos laitteilla on paljon komentoja jonossa. Luo Firestore-konsolissa.
