# ==============================================================================
# main.tf — Falko MDM Backend — Cloud Run & GCP -infrastruktuurin päämääritelmät
#
# Arkkitehtuuri, Tietoturva & IaC-periaatteet:
#   1. Infrastructure as Code (IaC First): Kaikki pilviresurssit (Cloud Run v2, Firestore Native,
#      Secret Manager, IAM-roolit, BigQuery Audit Logging, Domain Mappings) hallitaan
#      yksinomaan tässä koodikannassa.
#   2. Zero-Trust & 100% Google OIDC Auth: Palvelimella ei ole kiinteitä salasanoja tai Admin Tokens -avaimia.
#      Kaikki hallinta-endpointit (`/admin/*`) suojataan sovellustasolla (`app/admin.py`) vahvistamalla
#      kryptografisesti Google OAuth ID Token ja Firestore `users/{email}` luvitus.
#   3. Principle of Least Privilege: Cloud Run ajetaan omalla Service Accountilla (`falko-mdm-run-sa`),
#      jolle myönnetään vain minimitason IAM-oikeudet (Secret Accessor, Datastore User, Log Writer).
#   4. Pysyvä MDM-tietovarasto: Firestore toimii ainoana datavarastona laite- ja komento-entiteeteille,
#      varustettuna Point-In-Time-Recovery (PITR) -toiminnolla ja päivittäisillä varmuuskopioilla.
#
# Riippuvuudet:
#   network.tf  — VPC Access Connector (google_vpc_access_connector.connector)
#   security.tf — Cloud Armor -tietoturvakäytäntö (google_compute_security_policy.rate_limit_policy)
#   variables.tf — Kaikki var.* -muuttujat ja ympäristöasetukset
# ==============================================================================

# ------------------------------------------------------------
# Firestore-tietokanta
# ------------------------------------------------------------

# Firestore on Falko MDM:n ainoa pysyvä tietovarasto.
# Se tallentaa laitteet, MDM-komennot ja käyttäjät.
# Importoi olemassaoleva tietokanta komennolla:
#   terraform import google_firestore_database.database "(default)"
resource "google_firestore_database" "database" {
  project = var.gcp_project_id
  name    = "(default)"

  # europe-west3 = Frankfurt. Valittu koska Firestore ei tue europe-north1:tä
  # (Firestoren aluevalinta on rajoitettu — katso GCP-dokumentaatio).
  # MDM-data kulkee europe-north1 (Cloud Run) -> europe-west3 (Firestore),
  # mikä lisää latensseja ~10ms. Hyväksytty kompromissi saatavuuden vuoksi.
  location_id = "europe-west3"

  type = "FIRESTORE_NATIVE"

  # Point-in-time recovery mahdollistaa tietokannan palautuksen 7 päivän
  # aikaikkunassa. Suojaa accidentaalisilta massakirjoitusvirheiltä.
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
}

# Päivittäinen varmuuskopio — säilytys 7 päivää (604800 sekuntia).
# Varmuuskopiot ovat Firestore-sisäisiä (ei Cloud Storage).
# Palauta: gcloud firestore backups restore --backup=BACKUP_ID
resource "google_firestore_backup_schedule" "daily_backup" {
  project   = var.gcp_project_id
  database  = google_firestore_database.database.name
  retention = "604800s" # 7 vrk
  daily_recurrence {}
}

# ------------------------------------------------------------
# Secret Manager — APNs-yksityisavain
# ------------------------------------------------------------

# APNs-yksityisavain (.p8) tallennetaan Secret Manageriin,
# ei ympäristömuuttujiin selkokielisenä. Cloud Run lukee sen
# ajonaikaisesti secret_key_ref-mekanismilla (ks. container env-lohko).
# Avain syötetään Secret Manageriin manuaalisesti:
#   gcloud secrets versions add falko-apns-key --data-file=AuthKey_XXXX.p8
resource "google_secret_manager_secret" "apns_key" {
  project   = var.gcp_project_id
  secret_id = "falko-apns-key"

  # auto-replikointi: GCP valitsee replikointialueen automaattisesti.
  # Manuaalinen replikointi (esim. vain europe-north1) ei ole tarpeen
  # koska Secret Manager on globaali ja SLA riittää tälle käyttötapaukselle.
  replication {
    auto {}
  }
}

# ------------------------------------------------------------
# Service Account + IAM
# ------------------------------------------------------------

# Cloud Run -palvelu ajetaan tällä Service Accountilla.
# Principle of least privilege: myönnetään vain tarvittavat roolit.
resource "google_service_account" "run_sa" {
  project      = var.gcp_project_id
  account_id   = "falko-mdm-run-sa"
  display_name = "Cloud Run Service Account for Falko MDM"
}

# Oikeus lukea APNs-avainta Secret Managerista.
# Ilman tätä Cloud Run ei pysty käynnistymään (APNS_PRIVATE_KEY-injektio epäonnistuu).
resource "google_secret_manager_secret_iam_member" "apns_key_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.apns_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run_sa.email}"
}

# Oikeus lukea ja kirjoittaa Firestoreen (datastore.user sisältää molemmat).
# Käytetään project-tason roolia koska Firestore ei tue resurssikohtaisia
# IAM-rooleja samalla tavalla kuin Cloud Storage.
resource "google_project_iam_member" "firestore_user" {
  project = var.gcp_project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.run_sa.email}"
}

# Oikeus kirjoittaa Cloud Logging -lokeja.
# Sovellus kirjoittaa audit-tapahtumat strukturoituina JSON-lokeina,
# jotka Log Router Sink ohjaa BigQueryyn (ks. audit_sink alla).
resource "google_project_iam_member" "log_writer" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.run_sa.email}"
}

# ------------------------------------------------------------
# Cloud Run -palvelu
# ------------------------------------------------------------

resource "google_cloud_run_v2_service" "mdm_server" {
  project  = var.gcp_project_id
  name     = "falko-mdm-server"
  location = var.gcp_region

  # INGRESS_TRAFFIC_ALL: sekä suorat HTTPS-pyynnöt että Cloud Load Balancing.
  # Laitteen MDM-checkin tapahtuu suoraan Cloud Run -URL:iin tai
  # domain mappingin kautta (mdm-api.falko.fi).
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.run_sa.email

    # VPC-liitäntä mahdollistaa Cloud Runista lähtevän liikenteen reitittämisen
    # yksityisen VPC:n kautta NAT:lle. Tarvitaan APNs-yhteydelle:
    # APNs (api.push.apple.com) vaatii lähtevän TCP 443 -liikenteen,
    # ja Cloud NAT antaa kiinteän ulospäin menevän IP-osoitteen.
    # ALL_TRAFFIC: myös Google API -liikenne kulkee VPC:n kautta
    # (estää suoran internet-yhteyden varmistamatta NAT-reitistystä).
    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "ALL_TRAFFIC"
    }

    containers {
      # container_image päivitetään jokaisella Cloud Build -ajolla.
      # Muoto: europe-north1-docker.pkg.dev/falko-mdm/falko/mdm-server:latest
      image = var.container_image

      ports {
        # Dockerfile EXPOSE ja Gunicorn-käynnistys käyttävät tätä porttia.
        # Cloud Run kuuntelee automaattisesti PORT-ympäristömuuttujaa,
        # mutta container_port varmistaa että konfiguraatio on eksplisiittinen.
        container_port = var.container_port
      }

      # -- Ympäristömuuttujat --
      # Kaikki sovelluksen ajonaikaiset asetukset välitetään tässä.
      # Salaisuudet (APNS_PRIVATE_KEY) välitetään secret_key_ref:llä,
      # ei selkokielisinä arvoina.

      env {
        # GCP-projektin ID Firestore-asiakkaalle.
        # db.py: client = firestore.Client(project=os.environ["GCP_PROJECT"])
        name  = "GCP_PROJECT"
        value = var.gcp_project_id
      }

      env {
        # Apple Developer Team ID APNs JWT-tokenin luomiseen.
        # apns.py: team_id = os.environ["APNS_TEAM_ID"]
        name  = "APNS_TEAM_ID"
        value = var.apns_team_id
      }

      env {
        # APNs-avaimen Key ID JWT-tokenin kid-kenttään.
        # apns.py: key_id = os.environ["APNS_KEY_ID"]
        name  = "APNS_KEY_ID"
        value = var.apns_key_id
      }

      env {
        # APNs-ympäristö: 'true' = sandbox (kehitys), 'false' = tuotanto.
        # apns.py: sandbox = os.environ.get("APNS_SANDBOX", "false") == "true"
        # Tuotannossa: api.push.apple.com
        # Kehityksessä: api.sandbox.push.apple.com
        name  = "APNS_SANDBOX"
        value = var.apns_sandbox
      }

      env {
        # Flaskin SECRET_KEY istuntojen ja CSRF-tokenien allekirjoitukseen.
        # middleware.py käyttää tätä session-cookien kryptaukseen.
        # TÄRKEÄ: Muutos invalidoi kaikki olemassaolevat sessiot.
        name  = "SECRET_KEY"
        value = var.secret_key
      }

      env {
        # Flaskin suoritusympäristö. Tuotannossa aina 'production'.
        # 'development'-tila aktivoisi Werkzeug-debuggerin — älä käytä tuotannossa.
        name  = "FLASK_ENV"
        value = var.flask_env
      }

      env {
        # APNs-yksityisavain (.p8) haetaan Secret Managerista ajonaikaisesti.
        # Cloud Run injektoi arvon APNS_PRIVATE_KEY-muuttujaan.
        # apns.py: private_key = os.environ["APNS_PRIVATE_KEY"].replace("\\n", "\n")
        # Avain tallennettava Secret Manageriin ennen ensimmäistä deploy-ajoa:
        #   gcloud secrets versions add falko-apns-key --data-file=AuthKey_XXXX.p8
        name = "APNS_PRIVATE_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.apns_key.secret_id
            version = "latest"
          }
        }
      }
    }
  }
}

# Sallitaan julkinen pääsy Cloud Run -palveluun.
# MDM-protokolla vaatii että laitteet voivat ottaa yhteyden ilman autentikaatiota:
#   - /checkin: laitteiden rekisteröityminen (ei auth mahdollista ennen rekisteröitymistä)
#   - /mdm:    MDM-komennon haku (autentikoitu laitesertifikaatilla sovelluskerroksessa)
# Admin-rajapinnan (/api/*) suojaus hoidetaan sovelluskerroksessa (middleware.py + admin.py).
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  project  = var.gcp_project_id
  location = google_cloud_run_v2_service.mdm_server.location
  name     = google_cloud_run_v2_service.mdm_server.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ------------------------------------------------------------
# Domain Mapping
# ------------------------------------------------------------

# Liittää mdm-api.falko.fi -domainin Cloud Run -palveluun.
# Google hallitsee TLS-sertifikaatin automaattisesti (Let's Encrypt tai Google-managed).
# DNS-CNAME (mdm-api.falko.fi -> ghs.googlehosted.com) on määritelty dns.tf:ssä.
# HUOM: Domain Mapping vaatii domain-omistuksen verifioinnin Google Search Consolessa.
resource "google_cloud_run_domain_mapping" "api_mapping" {
  project  = var.gcp_project_id
  location = var.gcp_region
  name     = "mdm-api.falko.fi"

  metadata {
    namespace = var.gcp_project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.mdm_server.name
  }
}

# ------------------------------------------------------------
# BigQuery — Audit-lokit
# ------------------------------------------------------------

# BigQuery Dataset audit-lokeille.
# Sovellus kirjoittaa event_type=audit -lokit Cloud Loggingiin,
# jotka Log Router Sink (alla) ohjaa tähän datasettiin.
# Lokidata on saatavilla SQL-kyselyillä forensiikkaa ja raportointia varten.
resource "google_bigquery_dataset" "audit_dataset" {
  # checkov:skip=CKV_GCP_81:Google-managed encryption keys (default) are sufficient and preferred over CSEK/CMEK for simplicity and cost
  project    = var.gcp_project_id
  dataset_id = "mdm_audit_logs"

  # "EU" = multi-region EU. Data pysyy Euroopassa (GDPR).
  # Yksittäinen alue (europe-north1) ei ole saatavilla BigQueryssa.
  location = "EU"
}

# Log Router Sink ohjaa Cloud Run -palvelun audit-lokit BigQueryyn.
# Filtteri poimii vain rivit joissa:
#   - resource.type = cloud_run_revision (Cloud Run -palvelu)
#   - service_name = falko-mdm-server (vain tämä palvelu)
#   - jsonPayload.event_type = audit (sovelluksen eksplisiittiset audit-tapahtumat)
# Muut lokit (DEBUG, INFO ilman audit-tagia) eivät mene BigQueryyn.
resource "google_logging_project_sink" "audit_sink" {
  project     = var.gcp_project_id
  name        = "mdm-audit-logs-sink"
  destination = "bigquery.googleapis.com/projects/${var.gcp_project_id}/datasets/${google_bigquery_dataset.audit_dataset.dataset_id}"

  filter = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.mdm_server.name}\" AND jsonPayload.event_type=\"audit\""

  # unique_writer_identity: Log Router luo erillisen service accountin
  # kirjoitusoikeuksia varten. IAM-oikeus myönnetään sink_bq_writer -resurssissa.
  unique_writer_identity = true
}

# Myönnetään Log Router Sinkin automaattiselle service accountille
# BigQuery dataEditor -rooli jotta se voi kirjoittaa tauluihin.
# writer_identity on muodossa serviceAccount:service-XXXXX@...
resource "google_project_iam_member" "sink_bq_writer" {
  project = var.gcp_project_id
  role    = "roles/bigquery.dataEditor"
  member  = google_logging_project_sink.audit_sink.writer_identity
}
