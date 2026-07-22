# CHANGELOG

Kaikki merkittävät muutokset tässä projektissa dokumentoidaan tähän tiedostoon.
Formaatti perustuu [Keep a Changelog](https://keepachangelog.com/fi/1.0.0/) -suositukseen.

## [v0.0.1] - 2026-07-22

### Lisätty
- **Google OIDC / SSO Autentikaatio:** Google OAuth ID Token verifiointi `require_auth`-dekoraattorissa (`google-auth`-kirjasto).
- **Rooli- ja luvitusjärjestelmä (Firestore):**
  - Automaattinen rekisteröinti `pending`-tilaan uusille käyttäjille.
  - Oikeuksien tarkistus `users/{email}` Firestore-kokoelmasta (`authorized` / `pending` / `denied`).
  - Bootstrap-admin (`jaakko.korhonen@gmail.com`) jolla on aina suora pääsy järjestelmään.
- **Käyttäjähallinta API (Admin Endpoints):**
  - `GET /admin/users` — Kaikkien kirjautuneiden käyttäjien ja heidän luvitustilojensa listaus.
  - `POST /admin/users/<email>/authorize` — Käyttäjän hyväksyminen (`authorized`).
  - `POST /admin/users/<email>/deny` — Käyttäjän evääminen (`denied`).
- **Automaattinen CI/CD & Testaus:**
  - DevSecOps CI -pipeline (`devsecops.yml`) haavoittuvuusskannauksilla (Bandit, pip-audit, Checkov, Gitleaks).
  - 26 kattavaa Pytest-yksikkö- ja regressiotestiä (`test_admin.py`, `test_users.py`, `test_checkin.py`, `test_mdm.py`) koodikattavuusraportilla (`pytest-cov`).

### Poistettu
- **Admin Token Fallback:** Poistettu perinteinen salasana-pohjainen `ADMIN_TOKEN` kokonaan backendistä tietoturvan parantamiseksi. Palvelu vaatii nyt 100% OIDC Google SSO -tunnistautumisen.
