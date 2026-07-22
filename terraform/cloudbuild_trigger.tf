# cloudbuild_trigger.tf — Cloud Build -triggerit IaC:nä
#
# Määrittää Cloud Build -triggerit Terraformilla, joten koko CI/CD-putki
# on koodia eikä manuaalisesti konfiguroitu GCP Consolessa.
#
# Triggerit:
#   1. main-deploy: käynnistyy kun muutokset yhdistetään main-haaraan.
#      Ajaa cloudbuild.yaml:n (build + push + terraform apply).
#
# Muuttujat (substitutions):
#   $_APNS_TEAM_ID, $_APNS_KEY_ID, $_SECRET_KEY
#   Asetetaan Cloud Build -triggerin konfiguraatiossa GCP Consolessa tai
#   gcloud CLI:llä — ne eivät tallennu tähän tiedostoon tietoturvan vuoksi.
#
# HUOM: google_cloudbuild_trigger vaatii Cloud Build API:n aktivoinnin.

resource "google_project_service" "cloudbuild" {
  project            = var.gcp_project_id
  service            = "cloudbuild.googleapis.com"
  disable_on_destroy = false
}

resource "google_cloudbuild_trigger" "main_deploy" {
  project     = var.gcp_project_id
  name        = "falko-mdm-server-main-deploy"
  description = "Käynnistyy main-haaraan yhdistettäessä: build Docker-image, push Artifact Registryyn, aja Terraform apply."

  github {
    owner = "jaakkokorhonen"
    name  = "falko-mdm-server"
    push {
      branch = "^main$"
    }
  }

  filename = "cloudbuild.yaml"

  # Substitutions: salaisuudet asetetaan GCP Consolessa tai gcloud CLI:llä,
  # ei täällä. Tässä dokumentoidaan vain muuttujanimet.
  # Aseta arvot:
  #   gcloud builds triggers update falko-mdm-server-main-deploy \
  #     --update-substitutions=_APNS_TEAM_ID=...,_APNS_KEY_ID=...,_SECRET_KEY=...
  substitutions = {
    # _APNS_TEAM_ID ja _APNS_KEY_ID: Apple Developer -portaalin arvot.
    # _SECRET_KEY: Flaskin SECRET_KEY, generoi: python -c 'import secrets; print(secrets.token_hex(32))'
    # Placeholder-arvot — korvattava ennen ensimmäistä ajoa.
    _APNS_TEAM_ID = "REPLACE_WITH_REAL_VALUE"
    _APNS_KEY_ID  = "REPLACE_WITH_REAL_VALUE"
    _SECRET_KEY   = "REPLACE_WITH_REAL_VALUE"
  }

  depends_on = [google_project_service.cloudbuild]
}

output "cloudbuild_trigger_id" {
  value       = google_cloudbuild_trigger.main_deploy.trigger_id
  description = "Cloud Build -triggerin ID. Käytä tätä kun päivität substitution-arvoja gcloud CLI:llä."
}
