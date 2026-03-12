# Security Notes for GKE Runtime

This note explains the minimum secure setup for this repository in GKE and the exact difference between local credentials and cluster runtime identity.

## 1) What to do now (to keep it working)

Use this in `.env.deploy.<env>` for GKE:

- Keep `GOOGLE_APPLICATION_CREDENTIALS` commented (or unset).
- Keep `DB_PROVIDER=firestore` only if runtime IAM is correctly granted.
- Keep `STORAGE_PROVIDER=gcs` only if bucket IAM is correctly granted.

Then redeploy:

```bash
./cloud_deploy.sh staging --yes
kubectl -n dataspace-ica rollout status deployment/dataspace-ica-api --timeout=300s
```

## 2) Why the `gcp-service-account.json` path failed

`GOOGLE_APPLICATION_CREDENTIALS=./gcp-service-account.json` works locally only if the file exists on the local filesystem.

In GKE pods, `/app/gcp-service-account.json` does not exist unless you explicitly mount it as a Kubernetes Secret volume.  
If set without mounting, runtime fails with ENOENT.

## 3) Project split (important)

In your setup, these can be different:

- Cluster project (GKE context): `globaldatacare-test`
- Runtime data/artifact project: `globaldatacare-ica-dev`

That is valid, but IAM must be explicitly granted cross-project.

## 3.1) Cross-project GCS (create bucket + grant write from cluster project)

This is the exact flow for your current topology:

- GKE cluster project: `globaldatacare-test`
- Runtime resources project: `globaldatacare-ica-dev`

```bash
# A) Create bucket in runtime project (if it does not exist)
RUNTIME_PROJECT=globaldatacare-ica-dev
REGION=europe-southwest1
BUCKET=globaldatacare-ica-dev

gcloud storage buckets create "gs://$BUCKET" \
  --project "$RUNTIME_PROJECT" \
  --location "$REGION" \
  --uniform-bucket-level-access

# B) Resolve cluster runtime identity (default node SA)
CLUSTER_PROJECT=globaldatacare-test
PROJECT_NUMBER=$(gcloud projects describe "$CLUSTER_PROJECT" --format='value(projectNumber)')
NODE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
echo "$NODE_SA"

# C) Grant bucket write permission to cluster runtime identity
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:${NODE_SA}" \
  --role="roles/storage.objectAdmin"
```

If bucket name is already taken globally, use a unique bucket name and update:
- `GCS_BUCKET_NAME`

## 4) Runtime identity options

### Option A (recommended): GKE identity, no key file

Do not set `GOOGLE_APPLICATION_CREDENTIALS`.

Grant IAM in target project/resources to the cluster runtime identity (typically default compute SA):

```bash
PROJECT_NUMBER=$(gcloud projects describe globaldatacare-test --format='value(projectNumber)')
NODE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

gcloud projects add-iam-policy-binding globaldatacare-ica-dev \
  --member="serviceAccount:${NODE_SA}" \
  --role="roles/datastore.user"

gcloud storage buckets add-iam-policy-binding gs://globaldatacare-ica-dev \
  --member="serviceAccount:${NODE_SA}" \
  --role="roles/storage.objectAdmin"
```

### Option B: JSON key file mounted into pod

Only use if you intentionally manage long-lived service account keys.

You must:

- Create K8s Secret with the JSON file.
- Mount it in `Deployment`.
- Point `GOOGLE_APPLICATION_CREDENTIALS` to mounted path.

If any of these steps is missing, runtime fails.

## 5) Networking/IP reminders

- `CLUSTER-IP` is internal-only.
- `EXTERNAL-IP` is public service endpoint.
- Pod IP (`10.x.x.x`) is private and ephemeral.
- For stable public IP, use `K8S_LOADBALANCER_IP` with a reserved IP in the cluster project/region.

## 6) Quick validation after deploy

```bash
NAMESPACE=dataspace-ica
DEPLOYMENT=dataspace-ica-api
SERVICE=dataspace-ica-api

kubectl -n "$NAMESPACE" get deployment "$DEPLOYMENT" \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'

EXTERNAL_IP="$(kubectl -n "$NAMESPACE" get svc "$SERVICE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
echo "$EXTERNAL_IP"
curl -sS "http://$EXTERNAL_IP/openapi.json" | jq '.info.version,.servers'
```
