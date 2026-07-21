# DNS-ohjaus mdm-api.falko.fi -> ghs.googlehosted.com.
# Tämä luodaan 'froide'-projektiin käyttäen providers.tf tiedostossa määriteltyä alias-palveluntarjoajaa
resource "google_dns_record_set" "mdm_api_cname" {
  provider     = google.dns_project
  project      = var.dns_project_id
  managed_zone = var.dns_zone_name
  name         = "mdm-api.falko.fi."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["ghs.googlehosted.com."]
}
