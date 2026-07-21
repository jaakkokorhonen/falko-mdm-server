#!/bin/bash
# Falko MDM Server — Terraform-julkaisun käynnistysskripti
set -e

PROJECT_ID="falko-mdm"
REGION="europe-north1"
DNS_PROJECT="froide"
DNS_ZONE="falko-fi-zone"
IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/falko/mdm-server:latest"

echo "=== Falko MDM Server — Terraform Deploy ==="

# Tarkistetaan, että terraform on asennettu
if ! command -v terraform &> /dev/null; then
  echo "Virhe: Terraform-komentoa ei löydy. Asenna se ensin (esim. brew install terraform)."
  exit 1
fi

# 1. Kysytään asetukset
echo "--- Syötä vaadittavat asetukset ---"
read -r -p "Apple Team ID (esim. STQ5U5TZR2): " team_id
if [ -z "$team_id" ]; then
  echo "Virhe: Team ID vaaditaan."
  exit 1
fi

read -r -p "Apple Key ID (esim. AU467BS82C): " key_id
if [ -z "$key_id" ]; then
  echo "Virhe: Key ID vaaditaan."
  exit 1
fi

# Generoidaan Flask SECRET_KEY vahvasti
secret_key=$(python3 -c "import secrets; print(secrets.token_hex(24))")

# Siirrytään terraform-hakemistoon
cd terraform

# 2. Alustetaan ja ajetaan Terraform
echo "Alustetaan Terraform..."
terraform init

echo "Ajetaan terraform apply..."
terraform apply \
  -var="gcp_project_id=$PROJECT_ID" \
  -var="gcp_region=$REGION" \
  -var="dns_project_id=$DNS_PROJECT" \
  -var="dns_zone_name=$DNS_ZONE" \
  -var="apns_team_id=$team_id" \
  -var="apns_key_id=$key_id" \
  -var="secret_key=$secret_key" \
  -var="container_image=$IMAGE_URI"

echo ""
echo "=== Terraform Deploy suoritettu onnistuneesti! ==="
