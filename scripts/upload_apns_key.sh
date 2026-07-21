#!/bin/bash
# Falko MDM Server — APNs-avaimen latausskripti Secret Manageriin
set -e

PROJECT_ID="falko-mdm"
SECRET_NAME="falko-apns-key"

echo "=== APNs-avaimen lataus Secret Manageriin ==="

# Varmistetaan projekti
gcloud config set project "$PROJECT_ID" --quiet

# Varmistetaan, että salaisuus on olemassa (luodaan tarvittaessa, jos ei vielä luotu Terraformilla)
if ! gcloud secrets list --format="value(name)" | grep -q "$SECRET_NAME"; then
  echo "Luodaan secret '$SECRET_NAME'..."
  gcloud secrets create "$SECRET_NAME" --replication-policy="automatic"
fi

# Kysytään polku avaimeen
echo "Anna polku Apple APNs .p8 -yksityisavaintiedostoon lisätäksesi uuden version:"
read -r -p "Polku tiedostoon (esim. ~/Downloads/AuthKey_XXXXXX.p8): " key_path
key_path="${key_path/#\~/$HOME}"

if [ -f "$key_path" ]; then
  gcloud secrets versions add "$SECRET_NAME" --data-file="$key_path"
  echo "Avain lisätty onnistuneesti salaisuuden '$SECRET_NAME' uusimmaksi versioksi."
else
  echo "Virhe: Tiedostoa '$key_path' ei löydy."
  exit 1
fi
