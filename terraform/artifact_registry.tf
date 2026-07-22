# artifact_registry.tf — Artifact Registry Docker-repositorio
#
# Falko MDM -serverin Docker-kuva tallennetaan tähän repositorioon.
# Aiemmin repositorio luotiin manuaalisesti; nyt se on hallittu Terraformilla.
#
# Repositorion osoite:
#   europe-north1-docker.pkg.dev/falko-mdm/falko/mdm-server:latest
#
# Käyttö:
#   1. Terraform luo repositorion ensimmäisellä ajolla.
#   2. Cloud Build työntää imagen tähän jokaisen main-pushin yhteydessä.
#   3. Cloud Run hakee imagen täältä (var.container_image).

resource "google_project_service" "artifact_registry" {
  project            = var.gcp_project_id
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "falko" {
  project       = var.gcp_project_id
  location      = var.gcp_region
  repository_id = "falko"
  format        = "DOCKER"
  description   = "Falko MDM -serverin Docker-kuvat"

  # Artifact Analysis skannaa kuvat automaattisesti haavoittuvuuksien varalta
  # kun Cloud Build työntää kuvan (cloudbuild.yaml vaihe 2).
  # Ei vaadi erillistä konfiguraatiota — toimii oletuksena GCP-projekteissa,
  # joissa containerscanning.googleapis.com on aktivoitu.

  depends_on = [google_project_service.artifact_registry]
}

# Annetaan Cloud Run -palvelun service accountille oikeus hakea kuvia.
# Ilman tätä Cloud Run ei pysty käynnistämään kontia.
resource "google_artifact_registry_repository_iam_member" "run_sa_reader" {
  project    = var.gcp_project_id
  location   = var.gcp_region
  repository = google_artifact_registry_repository.falko.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.run_sa.email}"
}

# Output: täydellinen imagen perusosoite (ilman tagia)
output "artifact_registry_image_base" {
  value       = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${google_artifact_registry_repository.falko.name}/mdm-server"
  description = "Docker-kuvan perusosoite Artifact Registryssä (lisää :latest tai :SHA)."
}
