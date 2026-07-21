# falko-mdm-server — Toteutussuunnitelma

> Päivitetty: 2026-07-22  
> Tila: aktiivinen kehitys  
> Infra: Google Cloud Run · Cloud SQL (Firestore) · Cloud Build · Terraform

---

## Arkkitehtuuriyhteenveto

Palvelin on Python/Flask-sovellus, joka ajetaan Cloud Run -kontainerissa.
Autentikointi ja pääsynhallinta toteutetaan **sovellustasolle** — ei IAP:iin eikä
infrastruktuurikerrokseen nojaten. Sovellus sisältää oman rate limiting- ja
security header -kerroksen (`app/middleware.py`).

```
[Apple-laite]
      │  HTTPS / MDM-protokolla
      ▼
[Cloud Run: falko-mdm-server]
      ├── middleware.py   (rate limiting, security headers)
      ├── checkin.py      (TokenUpdate / Authenticate / CheckOut)
      ├── mdm.py          (komennot, payload-muodostus)
      ├── db.py           (Firestore-operaatiot)
      └── apns.py         (APNs push-herätykset)
      │
      ▼
[Firestore]          [APNs]
```

Terraform-konfiguraatio sijaitsee hakemistossa `terraform/` ja kattaa:
`main.tf` · `network.tf` · `security.tf` · `dns.tf` · `monitoring.tf` ·
`providers.tf` · `variables.tf` · `outputs.tf`

---

## Avoimet issuet ja toteutusjärjestys

Issuet on ryhmitelty neljään vaiheeseen. Kukin vaihe on itsenäinen mutta
seuraava vaihe hyötyy edellisen valmistumisesta.

### Vaihe 1 — Testipohja (smoke + yksikötestit)

**Tavoite:** saada perussuoja ennen muita muutoksia.

| Issue | Otsikko | Label |
|-------|---------|-------|
| [#7](https://github.com/jaakkokorhonen/falko-mdm-server/issues/7) | Laajenna `test_checkin.py` (TokenUpdate · Authenticate · CheckOut) | `testing` |
| [#8](https://github.com/jaakkokorhonen/falko-mdm-server/issues/8) | Korvaa minimaalinen `test_mdm.py` oikealla testipaketilla | `testing` |
| [#12](https://github.com/jaakkokorhonen/falko-mdm-server/issues/12) | Lisää yksikkötestit `middleware.py`:lle (rate limiting · security headers) | `testing` |

Vaihe 1 tuottaa: toimivat smoke-testit `/healthz`-, `/checkin`- ja `/mdm`-poluille
sekä middleware-invarianttien (429, security headers, healthz-vapautus) testit.

### Vaihe 2 — Moduulitason yksikkötestit

**Tavoite:** kattaa korkean teknisen riskin moduulit ennen coverage-mittausta.

| Issue | Otsikko | Label |
|-------|---------|-------|
| [#9](https://github.com/jaakkokorhonen/falko-mdm-server/issues/9) | Lisää yksikkötestit `db.py`, `apns.py`, `mdm.py` | `testing` |

Lisää tiedostot:
- `tests/test_db.py`
- `tests/test_apns.py`
- `tests/test_mdm_unit.py`

Kaikki ulkoiset riippuvuudet (Firestore, APNs, verkko) mockataan.

### Vaihe 3 — Coverage ja CI-integraatio

**Tavoite:** tehdä kattavuus näkyväksi ja pakolliseksi CI:ssä.

| Issue | Otsikko | Label |
|-------|---------|-------|
| [#10](https://github.com/jaakkokorhonen/falko-mdm-server/issues/10) | Ota käyttöön coverage-konfiguraatio ja CI-raportointi | `testing` `ci` |

Muutokset:
- `pyproject.toml` — `[tool.pytest.ini_options]` ja `[tool.coverage.run]`
- `cloudbuild.yaml` — coverage-ajo ja raja-arvon tarkistus

Esimerkki `pyproject.toml`-lisäyksestä:

```toml
[tool.coverage.run]
branch = true
source = ["app"]

[tool.coverage.report]
show_missing = true
fail_under = 70
```

### Vaihe 4 — Regressiostrategia ja pytest-markerit

**Tavoite:** erottaa nopeat PR-testit laajemmista regressioajoista.

| Issue | Otsikko | Label |
|-------|---------|-------|
| [#11](https://github.com/jaakkokorhonen/falko-mdm-server/issues/11) | Määritä riskipohjainen regressiotestisarja ja ajotasot | `testing` `ci` |

Testimarkerit (`pyproject.toml`):

```toml
[tool.pytest.ini_options]
markers = [
  "smoke: nopeat signaalitestit, ajetaan joka PR:ssä",
  "regression: laajempi sarja, ajetaan main-mergessä",
  "slow: raskaat integraatiotestit, ajetaan nightly",
]
```

CI-ajotasot (`cloudbuild.yaml`):

```yaml
# PR-triggerit
- name: 'python:3.12'
  entrypoint: pytest
  args: ['-m', 'smoke', '--tb=short']

# main-haara
- name: 'python:3.12'
  entrypoint: pytest
  args: ['-m', 'smoke or regression', '--cov=app', '--cov-fail-under=70']

# nightly (erillinen trigger)
- name: 'python:3.12'
  entrypoint: pytest
  args: ['-m', 'smoke or regression or slow', '--cov=app', '--cov-report=xml']
```

---

## Terraform-deployment-suunnitelma

Olemassaoleva `terraform/`-rakenne kattaa infrastruktuurin. Testikehityksen
yhteydessä ei tarvita Terraform-muutoksia — muutokset kohdistuvat sovellus-
ja CI-kerrokseen.

### Nykyiset Terraform-resurssit

| Tiedosto | Vastuu |
|----------|--------|
| `terraform/main.tf` | Cloud Run -palvelu, Cloud Build -triggerit, Artifact Registry |
| `terraform/network.tf` | VPC, Serverless VPC Connector, Cloud NAT |
| `terraform/security.tf` | IAM-roolit, Secret Manager -viittaukset |
| `terraform/dns.tf` | Cloud DNS -tietueet |
| `terraform/monitoring.tf` | Alerting policies, uptime checks, log-pohjaiset mittarit |
| `terraform/variables.tf` | Ympäristömuuttujat (project\_id, region, jne.) |
| `terraform/outputs.tf` | Cloud Run URL, DNS-tietueet |

### Terraform-muutokset testikehitykseen

Testikehitys (issuet #7–#12) ei edellytä inframuutoksia. Terraform pysyy
nykytilassaan. Seuraavat muutokset tehdään vain sovellus- ja CI-tasolla:

```
cloudbuild.yaml     ← coverage-ajo, pytest-markerit, fail_under
pyproject.toml      ← pytest-konfiguraatio, coverage-asetukset
tests/              ← uudet testitiedostot
```

### Tulevat Terraform-laajennukset (backlog)

Jos projekti laajenee, seuraavat resurssit voidaan lisätä `terraform/`-kansioon:

```hcl
# terraform/testing.tf (tuleva)

# Cloud Build -triggeri nightly-ajoille
resource "google_cloudbuild_trigger" "nightly_regression" {
  name        = "falko-mdm-server-nightly"
  description = "Nightly: kaikki testit + coverage-raportti"

  schedule {
    schedule = "0 2 * * *"  # 02:00 UTC
  }

  filename = "cloudbuild.yaml"

  substitutions = {
    _TEST_MARKER = "smoke or regression or slow"
    _COVERAGE_FAIL_UNDER = "75"
  }
}
```

---

## Deployment-polku issueista tuotantoon

```
Issue avattu
    │
    ▼
PR luotu feature-branchista
    │  CI ajaa: pytest -m smoke (nopea signaali)
    │
    ▼
Code review + hyväksyntä
    │
    ▼
Merge → main
    │  CI ajaa: pytest -m "smoke or regression" + coverage ≥ 70 %
    │  Cloud Build: docker build → push → Cloud Run deploy
    │
    ▼
Nightly (automaattinen)
    │  CI ajaa: kaikki testit + coverage XML -raportti
    │
    ▼
Tuotanto (Cloud Run)
```

### Issueiden status → deployment-valmius

| Issue | Valmistuessa | Deployment-ehto |
|-------|-------------|-----------------|
| #7 | `test_checkin.py` kattaa check-in-polut | smoke-tagi mergeissä |
| #8 | `test_mdm.py` kattaa MDM-komennot | smoke-tagi mergeissä |
| #12 | `test_middleware.py` kattaa rate limiting + security headers | smoke-tagi mergeissä |
| #9 | `test_db.py`, `test_apns.py`, `test_mdm_unit.py` luotu | regression-tagi main-haussa |
| #10 | coverage ≥ 70 %, CI failaa alle rajan | pakollinen CI-ehto |
| #11 | pytest-markerit + CI-ajotasot konfiguroitu | nightly-triggeri aktiivinen |

---

## Viitteet

- [CONTRIBUTING.md](../CONTRIBUTING.md) — kehityskäytännöt
- [cloudbuild.yaml](../cloudbuild.yaml) — CI-konfiguraatio
- [terraform/](../terraform/) — infrastruktuuri
- Apple MDM Protocol Reference — TokenUpdate, Authenticate, CheckOut
- pytest-cov dokumentaatio — branch coverage, fail\_under
