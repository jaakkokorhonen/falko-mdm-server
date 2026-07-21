# 1. Log-based Metric erääntyvistä tai virheellisistä APNs-sertifikaateista
resource "google_logging_metric" "apns_expiry_warning" {
  project = var.gcp_project_id
  name    = "mdm/apns_expiry_warning"
  filter  = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"falko-mdm-server\" AND severity>=WARNING AND textPayload:\"APNs certificate\" AND (textPayload:\"expire\" OR textPayload:\"expiry\" OR textPayload:\"erääntyy\")"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# 2. Log-based Metric kriittisistä sovellusvirheistä (severity >= ERROR)
resource "google_logging_metric" "server_errors" {
  project = var.gcp_project_id
  name    = "mdm/server_errors"
  filter  = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"falko-mdm-server\" AND severity>=ERROR"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# 3. Log-based Metric epäilyttävistä IAP-autentikaatiovirheistä (admin-sivut)
resource "google_logging_metric" "iap_failures" {
  project = var.gcp_project_id
  name    = "mdm/iap_failures"
  filter  = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"falko-mdm-server\" AND textPayload:\"IAP JWT-assertion\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# 4. Hälytyssääntö: APNs-sertifikaatin vanhenemisvaroitus havaittu lokissa
resource "google_monitoring_alert_policy" "apns_expiry_alert" {
  project      = var.gcp_project_id
  display_name = "MDM APNs Certificate Expiration Warning"
  combiner     = "OR"

  conditions {
    display_name = "APNs Expiry Log Count"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.apns_expiry_warning.name}\" AND resource.type=\"cloud_run_revision\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      trigger {
        count = 1
      }
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
}

# 5. Hälytyssääntö: Palvelin heittää toistuvasti virheitä (yli 5 virhettä minuutissa)
resource "google_monitoring_alert_policy" "server_error_alert" {
  project      = var.gcp_project_id
  display_name = "MDM Server High Error Rate Alert"
  combiner     = "OR"

  conditions {
    display_name = "High Error Rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.server_errors.name}\" AND resource.type=\"cloud_run_revision\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      trigger {
        count = 1
      }
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
}

# 6. Hälytyssääntö: Epäonnistuneita IAP-kirjautumisyrityksiä havaittu lokissa
resource "google_monitoring_alert_policy" "iap_failure_alert" {
  project      = var.gcp_project_id
  display_name = "MDM IAP Bypass or Auth Failure Alert"
  combiner     = "OR"

  conditions {
    display_name = "IAP Auth Failure Count"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iap_failures.name}\" AND resource.type=\"cloud_run_revision\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2
      trigger {
        count = 1
      }
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
}
