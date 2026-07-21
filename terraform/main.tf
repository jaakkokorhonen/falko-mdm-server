# Firestore-tietokannan alustus (jos ei vielä alustettu projektissa)
# Huom: Jos tietokanta on jo luotu, tämä voidaan tuoda tilaan komennolla:
# terraform import google_firestore_database.database "(default)"
resource "google_firestore_database" "database" {
  project     = var.gcp_project_id
  name        = "(default)"
  location_id = "europe-west3" # Firestoren sijainti (esim. europe-west3 / eur3)
  type        = "FIRESTORE_NATIVE"
}

# Secret Manager -salaisuus APNs-avaimelle
resource "google_secret_manager_secret" "apns_key" {
  project   = var.gcp_project_id
  secret_id = "falko-apns-key"

  replication {
    auto {}
  }
}

# Cloud Run -palvelun ajonaikainen Service Account
resource "google_service_account" "run_sa" {
  project      = var.gcp_project_id
  account_id   = "falko-mdm-run-sa"
  display_name = "Cloud Run Service Account for Falko MDM"
}

# Myönnetään Service Accountille oikeus lukea APNs-avainta Secret Managerista
resource "google_secret_manager_secret_iam_member" "apns_key_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.apns_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run_sa.email}"
}

# Myönnetään Service Accountille oikeus lukea ja kirjoittaa Firestoreen
resource "google_project_iam_member" "firestore_user" {
  project = var.gcp_project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.run_sa.email}"
}

# Myönnetään Service Accountille oikeus kirjoittaa lokeja
resource "google_project_iam_member" "log_writer" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.run_sa.email}"
}

# Cloud Run -palvelu
resource "google_cloud_run_v2_service" "mdm_server" {
  project  = var.gcp_project_id
  name     = "falko-mdm-server"
  location = var.gcp_region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.run_sa.email

    containers {
      image = var.container_image

      ports {
        container_port = 8080
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
        name  = "SECRET_KEY"
        value = var.secret_key
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
    }
  }
}

# Sallitaan julkinen pääsy (allUsers -> run.invoker) Cloud Run -palveluun laitteiden checkiniä varten
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  project    = var.gcp_project_id
  location   = google_cloud_run_v2_service.mdm_server.location
  name       = google_cloud_run_v2_service.mdm_server.name
  role       = "roles/run.invoker"
  member     = "allUsers"
}

# Cloud Run Domain Mapping aliverkkotunnukselle mdm-api.falko.fi
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

# BigQuery Dataset audit-logeille
resource "google_bigquery_dataset" "audit_dataset" {
  project    = var.gcp_project_id
  dataset_id = "mdm_audit_logs"
  location   = "EU"
}

# Log Router Sink, joka ohjaa audit-lokit BigQueryyn
resource "google_logging_project_sink" "audit_sink" {
  project                = var.gcp_project_id
  name                   = "mdm-audit-logs-sink"
  destination            = "bigquery.googleapis.com/projects/${var.gcp_project_id}/datasets/${google_bigquery_dataset.audit_dataset.dataset_id}"
  filter                 = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.mdm_server.name}\" AND jsonPayload.event_type=\"audit\""
  unique_writer_identity = true
}

# Annetaan Log Router Sink -kirjoittajalle oikeudet kirjoittaa BigQueryyn
resource "google_project_iam_member" "sink_bq_writer" {
  project = var.gcp_project_id
  role    = "roles/bigquery.dataEditor"
  member  = google_logging_project_sink.audit_sink.writer_identity
}
