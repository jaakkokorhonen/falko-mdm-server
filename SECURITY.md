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

### Autentikaatio

- **Admin API** (`/admin/*`) suojattu Google Identity-Aware Proxy (IAP) JWT:llä.
  JWT verifioidaan kryptografisesti Googlen julkisilla avaimilla (ES256).
  Ref: https://cloud.google.com/iap/docs/signed-headers-howto
- **MDM/CheckIn endpointit** eivät vaadi käyttäjäautentikaatiota — ne on tarkoitettu
  Apple-laitteiden käyttöön. Laitteen identiteetti perustuu TLS-asiakassertifikaattiin
  (MDM Identity Certificate, sisältyy mobileconfig-profiiliin).
- **ADMIN_TOKEN** on tarkoitettu vain CI/CD- ja skriptikäyttöön.
  Käytä vähintään 32-merkkistä satunnaista arvoa: `openssl rand -base64 32`

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
