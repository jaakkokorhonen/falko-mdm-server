output "service_url" {
  value       = google_cloud_run_v2_service.mdm_server.uri
  description = "Cloud Runin oletusarvoinen URL"
}

output "custom_domain_url" {
  value       = "https://mdm-api.falko.fi"
  description = "MDM-palvelimen kustomoitu API-URL"
}

output "service_account_email" {
  value       = google_service_account.run_sa.email
  description = "Cloud Run -palvelun käyttämä palvelutili"
}

output "bigquery_audit_dataset" {
  value       = google_bigquery_dataset.audit_dataset.id
  description = "Audit-logien BigQuery-datasetin ID"
}
