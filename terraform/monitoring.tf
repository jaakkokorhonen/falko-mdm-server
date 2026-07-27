# ============================================================
# monitoring.tf — Cloud Logging -metriikat ja hälytyssäännöt
#
# Kaikki metriikat perustuvat lokipohjaisiin mittareihin
# (log-based metrics). Hälytyssäännöt käyttävät näitä mittareita.
#
# Hälytysarkkitehtuuri:
#   Sovellus kirjoittaa lokeja (severity + textPayload/jsonPayload)
#   -> Cloud Logging kerää lokit
#   -> Log-based metric laskee täsmäävät rivit
#   -> Alert Policy laukaisee hälytyksen raja-arvon ylittyessä
#   -> (Notification Channel — konfiguroitu GCP-konsolissa, ei Terraformissa)
#
# Huom: Notification Channeleja (sähköposti, PagerDuty, Slack) ei
# hallita Terraformissa koska ne sisältävät henkilökohtaisia yhteystietoja.
# Lisää kanavat manuaalisesti GCP Monitoringin kautta ja liitä ne
# alert policy -resursseihin notification_channels-listalla.
# ============================================================

# ------------------------------------------------------------
# Log-based Metric 1: APNs-sertifikaatin vanhenemisvaroitus
# ------------------------------------------------------------
# apns.py kirjoittaa WARNING-tason lokin kun se havaitsee
# sertifikaatin vanhenemiseen liittyviä merkkijonoja:
#   logger.warning("APNs certificate will expire/expiry/erääntyy ...")
# Tämä metriikka laskee näiden lokirivien määrän.
resource "google_logging_metric" "apns_expiry_warning" {
  project = var.gcp_project_id
  name    = "mdm/apns_expiry_warning"

  # Filtteri: Cloud Run -revisio, oikea palvelu, WARNING tai korkeampi,
  # sisältää "APNs certificate" ja jokin vanhenemissana.
  filter = join(" AND ", [
    "resource.type=\"cloud_run_revision\"",
    "resource.labels.service_name=\"falko-mdm-server\"",
    "severity>=WARNING",
    "textPayload:\"APNs certificate\"",
    "(textPayload:\"expire\" OR textPayload:\"expiry\" OR textPayload:\"erääntyy\")",
  ])

  metric_descriptor {
    # DELTA: lasketaan muutos edellisestä mittauspisteestä (ei kumulatiivinen).
    # Sopii tapahtumamäärille joissa nollakohta on aina uusi mittausväli.
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# ------------------------------------------------------------
# Log-based Metric 2: Palvelinvirheet (severity >= ERROR)
# ------------------------------------------------------------
# Kattaa kaikki sovellustason virheet: 500-vastaukset, käsittelemättömät
# poikkeukset, Firestore-virheet, APNs-virheet jne.
# apns.py: logger.error("APNs push epäonnistui: ...")
# checkin.py, mdm.py, admin.py: logger.exception(...)
resource "google_logging_metric" "server_errors" {
  project = var.gcp_project_id
  name    = "mdm/server_errors"

  filter = join(" AND ", [
    "resource.type=\"cloud_run_revision\"",
    "resource.labels.service_name=\"falko-mdm-server\"",
    "severity>=ERROR",
  ])

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# ------------------------------------------------------------
# Log-based Metric 3: Sovelluskerroksen autentikaatiovirheet
# ------------------------------------------------------------
# Falko MDM käyttää sovelluskerroksen JWT-autentikaatiota (middleware.py
# ja admin.py) — ei Google IAP:ia. Tämä metriikka seuraa epäonnistuneita
# autentikaatioyrityksiä admin-rajapinnoilla.
#
# Sovellus kirjoittaa logiin tekstin "auth" + "fail" tai "401" tai "403"
# epäonnistuneen autentikaation yhteydessä:
#   logger.warning("auth fail: ...")  tai  logger.warning("401 ...")
#
# Jos lyhyessä ajassa tulee paljon autentikaatiovirheitä, se voi viitata
# credential stuffing -hyökkäykseen tai väärin konfiguroidulle clientille.
resource "google_logging_metric" "auth_failures" {
  project = var.gcp_project_id
  name    = "mdm/auth_failures"

  # Filtteri: WARNING+ taso, sisältää autentikaatioepäonnistumiseen
  # viittaavan tekstin. Tarkenna tätä jos sovellus kirjoittaa
  # standardimuotoisempia audit-lokeja (jsonPayload.event_type = "auth_failure").
  filter = join(" AND ", [
    "resource.type=\"cloud_run_revision\"",
    "resource.labels.service_name=\"falko-mdm-server\"",
    "severity>=WARNING",
    "(textPayload:\"auth\" OR jsonPayload.event_type=\"auth_failure\")",
    "(textPayload:\"fail\" OR textPayload:\"401\" OR textPayload:\"403\" OR textPayload:\"unauthorized\")",
  ])

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# ------------------------------------------------------------
# Alert Policy 1: APNs-sertifikaatin vanhenemisvaroitus
# ------------------------------------------------------------
# Laukaisee välittömästi kun edes yksi varoitusloki havaitaan.
# APNs-sertifikaatti on kriittinen — ilman sitä laitteet eivät
# saa push-herätyksiä ja MDM-komennot eivät etene.
# Sertifikaatti uusitaan Apple Developer -portaalissa ja Secret
# Manageriin päivitetään uusi versio manuaalisesti.
resource "google_monitoring_alert_policy" "apns_expiry_alert" {
  project      = var.gcp_project_id
  display_name = "MDM APNs Certificate Expiration Warning"

  # OR: hälytys laukaisee jos MIKÄ TAHANSA ehto täyttyy.
  # Tässä on vain yksi ehto, joten OR/AND ei merkitse eroa.
  combiner = "OR"

  conditions {
    display_name = "APNs Expiry Log Count > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.apns_expiry_warning.name}\" AND resource.type=\"cloud_run_revision\""
      duration        = "60s" # Hälytys laukaisee 60 sekunnin jälkeen kun ehto on täyttynyt
      comparison      = "COMPARISON_GT"
      threshold_value = 0 # Yksikin varoitusloki riittää hälyttämään
      trigger {
        count = 1 # Yksi datapiste riittää laukaisemaan
      }
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE" # Laskee tapahtumia per sekunti
      }
    }
  }
}

# ------------------------------------------------------------
# Alert Policy 2: Korkea virhetahti
# ------------------------------------------------------------
# Laukaisee kun ERROR-tason lokeja kertyy yli 5 minuutin aikana.
# Kynnys 5 on tarkoituksellisesti matala — yksittäinen virhe
# ei laukaise hälytystä, mutta toistuva virhetilanne kyllä.
# Säädä threshold_value tarpeen mukaan liikennemäärän kasvaessa.
resource "google_monitoring_alert_policy" "server_error_alert" {
  project      = var.gcp_project_id
  display_name = "MDM Server High Error Rate Alert"
  combiner     = "OR"

  conditions {
    display_name = "ERROR-lokeja yli 5 / min"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.server_errors.name}\" AND resource.type=\"cloud_run_revision\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5 # > 5 virhettä 60 sekunnin mittausikkunassa
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

# ------------------------------------------------------------
# Alert Policy 3: Autentikaatiovirheet
# ------------------------------------------------------------
# Hälyttää jos admin-rajapinnan autentikaatiovirheitä havaitaan
# enemmän kuin 2 lyhyessä ajassa.
# Voi viitata:
#   - Credential stuffing -hyökkäykseen
#   - Väärin konfiguroidulle MDM-clientille
#   - Kirjautumisongelmaan legitiimille käyttäjälle
# Kynnys 2 on matala: väärä salasana kerran tai kahdesti voi olla
# inhimillinen virhe, kolmas yritys on jo hälyttävä.
resource "google_monitoring_alert_policy" "auth_failure_alert" {
  project      = var.gcp_project_id
  display_name = "MDM Application Auth Failure Alert"
  combiner     = "OR"

  conditions {
    display_name = "Auth-virheitä yli 2 / min"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.auth_failures.name}\" AND resource.type=\"cloud_run_revision\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2 # > 2 auth-epäonnistumista 60 sekunnin ikkunassa
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


# ------------------------------------------------------------
# Linux MDM Tietoturvahälytykset (Issue #44 / Koodikatselmus)
# ------------------------------------------------------------
resource "google_logging_metric" "linux_security_violations" {
  project = var.gcp_project_id
  name    = "mdm/linux_security_violations"

  filter = join(" AND ", [
    "resource.type=\"cloud_run_revision\"",
    "resource.labels.service_name=\"falko-mdm-server\"",
    "severity>=WARNING",
    "(textPayload:\"Command signature verification failed\" OR textPayload:\"Replay attack detected\")",
  ])

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "linux_security_alert" {
  project      = var.gcp_project_id
  display_name = "Linux MDM Security Violation Alert"
  combiner     = "OR"

  conditions {
    display_name = "Linux-tietoturvaloukkauksia yli 0 / min"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.linux_security_violations.name}\" AND resource.type=\"cloud_run_revision\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0 # Mikä tahansa allekirjoitusvirhe tai replay-yritys laukaisee hälytyksen
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

