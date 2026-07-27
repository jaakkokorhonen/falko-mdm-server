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

resource "google_firestore_database" "database" {
  project = var.gcp_project_id
  name    = "(default)"

  location_id = "europe-west3"
  type = "FIRESTORE_NATIVE"

  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
}

resource "google_firestore_backup_schedule" "daily_backup" {
  project   = var.gcp_project_id
  database  = google_firestore_database.database.name
  retention = "604800s"
  daily_recurrence {}
}

# ------------------------------------------------------------
# Secret Manager — APNs-yksityisavain
# ------------------------------------------------------------

resource "google_secret_manager_secret" "apns_key" {
  project   = var.gcp_project_id
  secret_id = "falko-apns-key"

  replication {
    auto {}
  }
}

# ------------------------------------------------------------
# Service Account + IAM
# ------------------------------------------------------------

resource "google_service_account" "run_sa" {
  project      = var.gcp_project_id
  account_id   = "falko-mdm-run-sa"
  display_name = "Cloud Run Service Account for Falko MDM"
}

resource "google_secret_manager_secret_iam_member" "apns_key_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.apns_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run_sa.email}"
}

resource "google_project_iam_member" "firestore_user" {
  project = var.gcp_project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.run_sa.email}"
}

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

  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.run_sa.email

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "ALL_TRAFFIC"
    }

    containers {
      image = var.container_image

      ports {
        container_port = var.container_port
      }

      env {
        name  = "GCP_PROJECT"
        value = var.gcp_project_id
      }

      env {
        name  = "APNS_TEAM_ID"
        value = var.apns_team_id
      }

      env {
        name  = "APNS_KEY_ID"
        value = var.apns_key_id
      }

      env {
        name  = "APNS_SANDBOX"
        value = var.apns_sandbox
      }

      env {
        name  = "SECRET_KEY"
        value = var.secret_key
      }

      env {
        name  = "FLASK_ENV"
        value = var.flask_env
      }

      env {
        name = "APNS_PRIVATE_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.apns_key.secret_id
            version = "latest"
          }
        }
      }

      # KMS-avainpolku komentojen allekirjoitukseen (Issue #44, #56).
      # HUOM: Polku osoittaa koko crypto_key-resurssiin ilman cryptoKeyVersions-suffiksia.
      # KMS käyttää automaattisesti primaariversiota allekirjoitukseen,
      # jolloin rotation_period (90 pv) toimii ilman manuaalisia muuttujapäivityksiä.
      # Jos polku sisältäisi /cryptoKeyVersions/1, rotaatio ei toimisi automaattisesti.
      env {
        name  = "FALKO_KMS_KEY_PATH"
        value = "projects/${var.gcp_project_id}/locations/${var.gcp_region}/keyRings/falko-mdm-keyring/cryptoKeys/falko-command-signing-key"
      }
    }
  }
}

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

resource "google_bigquery_dataset" "audit_dataset" {
  # checkov:skip=CKV_GCP_81:Google-managed encryption keys (default) are sufficient and preferred over CSEK/CMEK for simplicity and cost
  project    = var.gcp_project_id
  dataset_id = "mdm_audit_logs"
  location = "EU"
}

resource "google_logging_project_sink" "audit_sink" {
  project     = var.gcp_project_id
  name        = "mdm-audit-logs-sink"
  destination = "bigquery.googleapis.com/projects/${var.gcp_project_id}/datasets/${google_bigquery_dataset.audit_dataset.dataset_id}"

  filter = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.mdm_server.name}\" AND jsonPayload.event_type=\"audit\""

  unique_writer_identity = true
}

resource "google_project_iam_member" "sink_bq_writer" {
  project = var.gcp_project_id
  role    = "roles/bigquery.dataEditor"
  member  = google_logging_project_sink.audit_sink.writer_identity
}

# ============================================================
# KMS-resurssit komentojen allekirjoitusta varten (Issue #44, #56)
# ============================================================

resource "google_kms_key_ring" "keyring" {
  project  = var.gcp_project_id
  name     = "falko-mdm-keyring"
  location = var.gcp_region
}

resource "google_kms_crypto_key" "command_signing_key" {
  name     = "falko-command-signing-key"
  key_ring = google_kms_key_ring.keyring.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  # Automaattinen avainrotaatio 90 pv välein (Issue #56).
  # Uusi avainversio tulee primaariksi ja FALKO_KMS_KEY_PATH (joka ei sisällä
  # /cryptoKeyVersions/-suffiksia) osoittaa aina uusimpaan primaariversioon.
  # Vanhoilla versioilla allekirjoitetut komennot voidaan silti verifioida
  # koska key_version tallennetaan Firestoreen jokaisen komennon yhteydessä.
  rotation_period = "7776000s" # 90 päivää
}

resource "google_kms_crypto_key_iam_member" "run_sa_kms_signer" {
  crypto_key_id = google_kms_crypto_key.command_signing_key.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.run_sa.email}"
}

# ============================================================
# Firebase Ruleset & Release (Firestore Security Rules deployment, Issue #57)
# ============================================================

resource "google_firebaserules_ruleset" "firestore" {
  project = var.gcp_project_id
  source {
    files {
      name    = "firestore.rules"
      content = file("${path.module}/../firestore.rules")
    }
  }
}

resource "google_firebaserules_release" "firestore" {
  project      = var.gcp_project_id
  name         = "cloud.firestore"
  ruleset_name = google_firebaserules_ruleset.firestore.name
}
