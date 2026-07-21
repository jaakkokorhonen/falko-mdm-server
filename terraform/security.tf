# Cloud Armor tietoturvakäytäntö (Security Policy) nopeusrajoituksille
# Estää brute-force ja DDoS -hyökkäykset laitteiden checkin ja mdm reitteihin.
# checkov:skip=CKV_GCP_73:Cloud Armor Log4j protection is not needed since the service runs in a python sandbox without Java log4j dependencies
resource "google_compute_security_policy" "rate_limit_policy" {
  project     = var.gcp_project_id
  name        = "mdm-rate-limit-policy"
  description = "Nopeusrajoitukset (Rate Limiting) Falko MDM:n julkisille rajapinnoille"

  # Oletussääntö: Salli kaikki liikenne
  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Salli kaikki liikenne oletuksena"
  }

  # Nopeusrajoitussääntö (Throttling): Max 100 pyyntöä per IP-osoite minuutissa
  rule {
    action   = "throttle"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
      exceed_action = "deny(429)"
      enforce_on_key = "IP"
    }
    description = "Rajoita pyyntömäärät tasoon 100 req/min per IP-osoite"
  }
}
