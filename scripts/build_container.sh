#!/bin/bash
# Falko MDM Server — Docker-kontin kääntäminen Cloud Buildilla
set -e

PROJECT_ID="falko-mdm"
REGION="europe-north1"
REPO_NAME="falko"
IMAGE_NAME="mdm-server"

echo "=== Kontin kääntäminen Cloud Buildilla ==="

# Asetetaan projekti
gcloud config set project "$PROJECT_ID" --quiet

# Varmistetaan, että Artifact Registry on olemassa
if ! gcloud artifacts repositories list --location="$REGION" --format="value(name)" | grep -q "$REPO_NAME"; then
  echo "Luodaan Artifact Registry '$REPO_NAME'..."
  gcloud artifacts repositories create "$REPO_NAME" \
    --repository-format=docker \
    --location="$REGION"
fi

# Rakennetaan kuva Cloud Buildilla ilman suoraa Cloud Run -julkaisua
echo "Käynnistetään Cloud Build kääntämään Docker-image..."
gcloud builds submit \
  --tag "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${IMAGE_NAME}:latest" \
  .

echo ""
echo "=== Kääntäminen valmis! ==="
echo "Kuva on ladattu Artifact Registryyn osoitteeseen:"
echo "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${IMAGE_NAME}:latest"
