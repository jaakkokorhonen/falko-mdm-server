terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Erillinen palveluntarjoaja DNS-projektille (froide)
provider "google" {
  alias   = "dns_project"
  project = var.dns_project_id
  region  = var.gcp_region
}
