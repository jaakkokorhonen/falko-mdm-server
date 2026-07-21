# ============================================================
# variables.tf — Terraform-muuttujat Falko MDM -serverille
#
# Kaikki ympäristökohtaiset arvot, salaisuudet ja säädettävät
# parametrit määritellään tässä. Älä kovakoodaa arvoja muihin
# .tf-tiedostoihin — käytä aina var.* -viittausta.
#
# Sensitiiviset muuttujat (secret_key, apns_*) välitetään
# Cloud Build -pipelinen kautta $_SUBSTITUTION-mekanismilla.
# Ne eivät koskaan tallennu Terraform state -tiedostoon
# selkokielisinä — secret_key on merkitty sensitive=true.
# ============================================================

# ------------------------------------------------------------
# GCP-projekti ja alue
# ------------------------------------------------------------

variable "gcp_project_id" {
  type        = string
  description = "GCP-projekti, johon MDM-taustajärjestelmä asennetaan."
  default     = "falko-mdm"
}

variable "gcp_region" {
  type        = string
  description = "GCP-alue (region) palveluille. Cloud Run ja VPC sijaitsevat tässä alueessa."
  default     = "europe-north1"
  # europe-north1 = Finland (Helsinki). Valittu GDPR-vaatimuksista:
  # laitedata pysyy EU:n sisällä. Firestoren sijainti on erikseen
  # määritelty main.tf:ssä (europe-west3 / Frankfurt).
}

# ------------------------------------------------------------
# DNS-projekti (erillinen GCP-projekti falko.fi -vyöhykkeelle)
# ------------------------------------------------------------

variable "dns_project_id" {
  type        = string
  description = "GCP-projekti, jossa falko.fi Cloud DNS -vyöhyke sijaitsee. Eri projekti kuin MDM-palvelin."
  default     = "froide"
  # DNS-vyöhyke on 'froide'-projektissa koska se jakautuu useamman
  # palvelun kesken. providers.tf määrittelee erillisen google-providerin
  # tätä projektia varten (alias = "dns_project").
}

variable "dns_zone_name" {
  type        = string
  description = "Cloud DNS -vyöhykkeen nimi 'dns_project_id'-projektissa."
  default     = "falko-fi-zone"
}

# ------------------------------------------------------------
# APNs-tunnisteet (Apple Push Notification service)
# ------------------------------------------------------------

variable "apns_team_id" {
  type        = string
  description = "Apple Developer Team ID (10 merkkiä, esim. STQ5U5TZR2). Löytyy Apple Developer -portaalista."
  # Ei default-arvoa — pakollinen, välitetään Cloud Build -substitutionista.
}

variable "apns_key_id" {
  type        = string
  description = "APNs-avainten Key ID (10 merkkiä, esim. AU467BS82C). Luodaan Apple Developer -portaalissa."
  # Ei default-arvoa — pakollinen, välitetään Cloud Build -substitutionista.
}

variable "apns_sandbox" {
  type        = string
  description = "Käytetäänkö APNs sandbox -ympäristöä. 'true' kehitykseen, 'false' tuotantoon."
  default     = "false"
  # Tämä muuttuja välitetään Cloud Run -konttiin APNS_SANDBOX-ympäristömuuttujana.
  # apns.py lukee arvon: sandbox = os.environ.get("APNS_SANDBOX", "false") == "true"
  # APNs sandbox: api.sandbox.push.apple.com
  # APNs tuotanto: api.push.apple.com
}

# ------------------------------------------------------------
# Flask-sovelluksen asetukset
# ------------------------------------------------------------

variable "secret_key" {
  type        = string
  description = "Flaskin SECRET_KEY istuntojen ja CSRF-tokenien suojaamiseen. Generoi komennolla: python -c 'import secrets; print(secrets.token_hex(32))'"
  sensitive   = true
  # sensitive=true estää arvon tulostumisen Terraform-suorituksen lokiin.
  # Välitetään Cloud Build -substitutionista $_SECRET_KEY.
}

variable "flask_env" {
  type        = string
  description = "Flaskin suoritusympäristö: 'production' tai 'development'. Vaikuttaa debuggaukseen ja virheilmoituksiin."
  default     = "production"
  # TÄRKEÄ: Pidä tuotannossa aina 'production'. 'development'-tila avaa
  # Werkzeug-debuggerin, joka on kriittinen tietoturva-aukko julkisessa palvelussa.
  validation {
    condition     = contains(["production", "development", "testing"], var.flask_env)
    error_message = "flask_env täytyy olla 'production', 'development' tai 'testing'."
  }
}

# ------------------------------------------------------------
# Container-asetukset
# ------------------------------------------------------------

variable "container_image" {
  type        = string
  description = "Käytettävä Docker-kuva Artifact Registrystä. Muoto: REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG"
  # Esimerkki: europe-north1-docker.pkg.dev/falko-mdm/falko/mdm-server:latest
  # Arvo päivitetään automaattisesti Cloud Build -pipelinen toimesta.
}

variable "container_port" {
  type        = number
  description = "Portti, jossa Flask-sovellus kuuntelee kontin sisällä. Dockerfile ja Cloud Run käyttävät tätä arvoa."
  default     = 8080
  # Cloud Run odottaa oletuksena porttia 8080. Dockerfile EXPOSEaa tämän portin.
  # Muuta vain jos Dockerfile:ssa muutetaan vastaavasti.
}

# ------------------------------------------------------------
# Rate Limiting -asetukset (Cloud Armor + sovelluskerros)
# ------------------------------------------------------------

variable "cloud_armor_rate_limit_requests" {
  type        = number
  description = "Cloud Armor (infratason): Suurin sallittu pyyntömäärä per IP per ikkuna. Ylitys saa HTTP 429."
  default     = 100
  # Tämä on infrastruktuuritason suoja ennen kuin pyyntö saapuu Cloud Runiin.
  # Arvo on korkeampi kuin sovelluskerroksen raja koska se on ensimmäinen puolustuslinja.
  # Sovellustason raja (middleware.py): 60 pyyntöä / 60 sekuntia per IP.
  # Viite: OWASP API Security Top 10 (2023) API4:2023 Unrestricted Resource Consumption.
}

variable "cloud_armor_rate_limit_window_sec" {
  type        = number
  description = "Cloud Armor: Aikaikkuna sekunteina, jonka aikana raja lasketaan."
  default     = 60
  # 60 sekuntia = 1 minuutti. Vastaa sovelluskerroksen _RATE_LIMIT_WINDOW-vakiota (middleware.py).
}
}
