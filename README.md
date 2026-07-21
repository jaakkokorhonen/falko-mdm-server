# falko-mdm-server

Minimalistinen Apple MDM -palvelin Falkon laitehallintaan.  
Pyörii Google Cloud Runilla, tallentaa laitetiedot Firestoreen.

Toimii yhdessä [falko-device-onboarding](https://github.com/jaakkokorhonen/falko-device-onboarding) -repon kanssa.

---

## Tietoturvaperiaate: IAP rajaa luottamuksen Cloud Runiin

Tämä palvelin pyörii Cloud Runilla ja käyttää Firestorea. Molemmat ovat jo Googlen luottamuspiirissä. Kun admin-rajapinta suojataan **Identity-Aware Proxy (IAP)** -tasolla, luottamusta ei tarvitse jakaa eikä laajentaa:

- Pyyntö ei koskaan saavuta Flask-sovellusta jos käyttäjä ei ole autentikoitu — autentikaatio tapahtuu Googlen verkkokerroksessa ennen Cloud Runia.
- Workspace-domainirajaus (`domain:falko.fi`) on yksi IAM-sääntö, ei sovelluskoodi. Buginen tai puuttuva `@require_login`-decorator ei voi jättää aukkoa.
- Staattinen `ADMIN_TOKEN` on jaettu salaisuus jonka vuotaminen avaa koko admin-rajapinnan. IAP korvaa sen Googlen allekirjoittamalla per-pyyntö-identiteetillä (`X-Goog-Authenticated-User-Email`).
- Hyökkäyspinta pysyy samana kuin ilman UI:ta — IAP ei lisää uusia luottamussuhteita, se ainoastaan rajaa pääsyn olemassaolevaan.

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

IAP:n aktivoinnin jälkeen Flask lukee kirjautuneen käyttäjän suoraan otsakeesta:

```python
# app/admin.py — korvaa require_token-decoratorin
user_email = request.headers.get("X-Goog-Authenticated-User-Email", "")
# Muoto: "accounts.google.com:jaakko@falko.fi"
```

> **Huom:** `ADMIN_TOKEN`-ympäristömuuttuja jää fallback-mekanismiksi API-kutsuihin
> (esim. CI/CD-pipeline, `curl`-testaus) joissa selainkäyttäjän OAuth-flow ei ole käytännöllinen.
> Tuotannossa admin-UI kulkee aina IAP:n kautta.

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
| `ADMIN_TOKEN` | Fallback | Bearer-token skripti/CI-käyttöön. IAP-aktivoinnin jälkeen admin-UI ei tarvitse tätä. |
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
