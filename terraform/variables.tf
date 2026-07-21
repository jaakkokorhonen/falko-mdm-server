variable "gcp_project_id" {
  type        = string
  description = "GCP-projekti, johon MDM-taustajärjestelmä asennetaan"
  default     = "falko-mdm"
}

variable "gcp_region" {
  type        = string
  description = "GCP-alue (region) palveluille"
  default     = "europe-north1"
}

variable "dns_project_id" {
  type        = string
  description = "GCP-projekti, jossa falko.fi Cloud DNS -vyöhyke sijaitsee"
  default     = "froide"
}

variable "dns_zone_name" {
  type        = string
  description = "Cloud DNS vyöhykkeen nimi"
  default     = "falko-fi-zone"
}

variable "apns_team_id" {
  type        = string
  description = "Applen Developer Team ID (STQ5U5TZR2)"
}

variable "apns_key_id" {
  type        = string
  description = "APNs key id (AU467BS82C)"
}

variable "secret_key" {
  type        = string
  description = "Flaskin SECRET_KEY istuntojen suojaamiseen (suositellaan generoimaan vahva salasana)"
  sensitive   = true
}

variable "container_image" {
  type        = string
  description = "Käytettävä Docker-kuva Artifact Registrystä"
}
