#!/bin/bash
set -e

# Falko MDM Server — Google Cloud deployment script
# Projektille falko-mdm

PROJECT_ID="falko-mdm"
REGION="europe-north1"
SERVICE_NAME="falko-mdm-server"
REPO_NAME="falko"
DOMAIN_NAME="mdm-api.falko.fi"

echo "=== Falko MDM Server Deployment ==="
echo "Project ID: $PROJECT_ID"
echo "Region: $REGION"
echo ""

# 1. Asetetaan projekti
gcloud config set project "$PROJECT_ID"

# 2. Aktivoidaan palvelut
echo "Aktivoidaan GCP-palveluita..."
gcloud services enable \
  run.googleapis.com \
  firestore.googleapis.com \
  secretmanager.googleapis.com \
  iap.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com

# 3. Luodaan Firestore (jos ei ole vielä olemassa)
echo "Tarkistetaan Firestore-tietokantaa..."
if ! gcloud firestore databases list --format="value(name)" | grep -q "default"; then
  echo "Luodaan Firestore Native-tietokanta..."
  gcloud firestore databases create --location="$REGION" --type=firestore-native
else
  echo "Firestore-tietokanta on jo olemassa."
fi

# 4. Tarkistetaan APNs Secret
echo "Tarkistetaan Secret Manager..."
if ! gcloud secrets list --format="value(name)" | grep -q "falko-apns-key"; then
  echo "Luodaan secret 'falko-apns-key'..."
  gcloud secrets create falko-apns-key --replication-policy="automatic"
fi

# Tarkistetaan onko salaisuudesta yhtään versiota ladattuna
if ! gcloud secrets versions list falko-apns-key --limit=1 --format="value(name)" &>/dev/null; then
  echo "HUOM: Secret Managerissa ei ole vielä ladattuja versioita avaimelle 'falko-apns-key'."
  echo "Anna polku Apple APNs .p8 -yksityisavaintiedostoon lisätäksesi ensimmäisen version:"
  read -r -p "Polku tiedostoon (esim. ~/Downloads/AuthKey_XXXXXX.p8): " key_path
  # Korvataan ~ kotihakemistolla bash-yhteensopivasti
  key_path="${key_path/#\~/$HOME}"
  
  if [ -f "$key_path" ]; then
    gcloud secrets versions add falko-apns-key --data-file="$key_path"
    echo "Avain lisätty Secret Manageriin."
  else
    echo "Virhe: Tiedostoa '$key_path' ei löydy."
    echo "Deployment keskeytetty, koska Cloud Run vaatii Secret Managerissa olevan avaimen käynnistyäkseen."
    echo "Lisää avain manuaalisesti ja aja skripti uudelleen:"
    echo "gcloud secrets versions add falko-apns-key --data-file=/polku/AuthKey_XXX.p8"
    exit 1
  fi
else
  echo "Secret 'falko-apns-key' ja sen vähintään yksi aktiivinen versio on olemassa."
fi

# 5. Luodaan Artifact Registry
echo "Tarkistetaan Artifact Registry..."
if ! gcloud artifacts repositories list --location="$REGION" --format="value(name)" | grep -q "$REPO_NAME"; then
  echo "Luodaan Artifact Registry 'falko'..."
  gcloud artifacts repositories create "$REPO_NAME" \
    --repository-format=docker \
    --location="$REGION"
else
  echo "Artifact Registry on jo olemassa."
fi

# 6. Build ja Deploy Cloud Runiin
echo "Rakennetaan ja julkaistaan Cloud Run -palvelu..."
gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --region "$REGION" \
  --no-allow-unauthenticated \
  --set-secrets=APNS_PRIVATE_KEY=falko-apns-key:latest \
  --set-env-vars=GCP_PROJECT="$PROJECT_ID" \
  --min-instances=0 \
  --max-instances=10 \
  --memory=512Mi \
  --cpu=1

# 7. Aktivoidaan Google IAP ja domain-rajoitus
echo "Otetaan käyttöön Google IAP pääsy falko.fi-käyttäjille..."
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --member="domain:falko.fi" \
  --role="roles/iap.httpsResourceAccessor" || echo "Huom: IAP-sidoksen asetus epäonnistui (vaatii mahdollisesti kuormantasaajan määrityksen)."

# 8. Luodaan custom domain domain-mäppäys
echo "Luodaan domain-mäppäys: $DOMAIN_NAME -> Cloud Run..."
if ! gcloud beta run domain-mappings list --region="$REGION" --format="value(domain)" | grep -q "$DOMAIN_NAME"; then
  gcloud beta run domain-mappings create \
    --service "$SERVICE_NAME" \
    --domain "$DOMAIN_NAME" \
    --region "$REGION"
else
  echo "Domain-mäppäys $DOMAIN_NAME on jo olemassa."
fi

echo ""
echo "=== Valmis! ==="
echo "Muista asettaa DNS-tietueet domain-mäppäyksen ohjeiden mukaisesti."
