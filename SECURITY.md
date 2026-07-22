# Security Policy — Falko MDM Server

## Tuetut versiot

| Versio | Tuki |
|--------|------|
| main   | ✅ aktiivinen |

## Haavoittuvuuden ilmoittaminen

Ilmoita tietoturvaongelmat yksityisesti: `security@falko.fi`
Tai GitHub Security Advisories: Settings → Security → Advisories → New draft advisory.

Älä julkaise haavoittuvuutta julkisena GitHub-issuena.

## Tietoturva-arkkitehtuuri

- **Admin API (`/admin/*`)** suojattu 100% Google OIDC OAuth 2.0 ID Token -verifioinnilla ja IAP JWT:llä.
  Google ID Token vahvistetaan kryptografisesti Googlen julkisilla RSA-avaimilla (`google-auth`-kirjasto).
- **Firestore Access Control (`users/{email}`):** Jokaisen todennetun pyynnön kohdalla verifioidaan luvitusstatus Firestoresta (`authorized` / `pending` / `denied`).
- **MDM/CheckIn endpointit:** Apple-laitteiden yhteys laitesertifikaatilla ja push-magic -tunnisteella.
- **Zero-Trust & No Admin Token Fallbacks:** Palvelimella ei ole manuaalisia Admin Token -salanoja — kaikki pääsy vaatii vahvistetun Google SSO -identiteetin.

### Syötteen validointi

- UDID validoidaan regex-mallilla ennen Firestore-kirjoitusta (`^[A-Z0-9][A-Z0-9-]{18,38}[A-Z0-9]$`).
  Ref: Fleet MDM CVE-2026-34385 — malformed UDID johti odottamattomiin Firestore-polkuihin.
- `command_type` validoidaan allowlist-listaa vasten ennen Apple MDM -protokollaviestien lähetystä.
  Ref: OWASP ASVS v4.0 §5.1.3 — Positive server-side input validation.

### Security headers

`app/middleware.py` lisää jokaiseen vastaukseen:
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`

### Rate limiting

In-memory sliding window (60 pyyntöä / 60 s per IP). Tuotannossa
suositellaan Redis-pohjaista `flask-limiter`-ratkaisua jos Cloud Run
skaalaa useampaan instanssiin.

### Salaisuuksien hallinta

Kaikki salaisuudet (APNS_PRIVATE_KEY, ADMIN_TOKEN, SECRET_KEY) tallennetaan
Google Cloud Secret Manageriin. Niitä ei kirjata logeihin.

## Tunnetut rajoitteet

- `list_devices` käyttää in-memory Firestore-sivutusta — ei skaalaudu yli 500 laitteen
  ilman Redis-välimuistia tai CDN-välimuistia.
- APNs rate limiting on in-memory — ei jaettu Cloud Run -instanssien välillä.
