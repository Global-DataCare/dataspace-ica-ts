# Deploy to Kubernetes (GKE)

## GKE vs Cloud Run URL behavior

This repository deploy script (`./cloud_deploy.sh`) targets **GKE** (Kubernetes), not Cloud Run.

- GKE + `Service` type `ClusterIP`: internal-only (no public URL).
- GKE + `Service` type `LoadBalancer`: public IP URL (for example `http://34.x.x.x`).
- Cloud Run: managed HTTPS URL ending in `*.run.app`.

So if you expect `*.run.app`, that is a Cloud Run deployment flow, different from `cloud_deploy.sh` in this repo.

## One-image workflow (recommended)

Build once locally, reuse that exact image for deploy (only env vars change):

```bash
./docker_build_local.sh
./docker_run.sh local
curl -sS http://localhost:3310/ | jq .
```

Deploy the same `dataspace-ica:local` image to GKE:

```bash
# uses .env.deploy.staging and pushes local image without rebuilding
./cloud_deploy.sh staging
```

`cloud_deploy.sh` expects these variables inside `.env.deploy.<env>`:
- `FIRESTORE_PROJECT_ID`
- `DEPLOY_REGION`
- `DEPLOY_SERVICE_NAME`
- `ARTIFACT_REGISTRY_NAME`
- optional: `IMAGE_TAG`, `K8S_NAMESPACE`, `K8S_CONTEXT`, `LOCAL_IMAGE`

Important:
- `cloud_deploy.sh` does not create the GCP project, billing link, bucket, or cluster for you.
- Those resources must exist (and your account must have IAM permissions) before running deploy.

## GCP bootstrap (project + billing + GCS)

Use these steps once per new environment/project.

### 1) Check active account and list billing accounts

```bash
gcloud auth list
gcloud config get-value account
gcloud beta billing accounts list
```

Example billing account id:
- `014A34-6E960C-35E085`

### 2) Create project (if not already created)

```bash
PROJECT_ID=globaldatacare-ica-dev
gcloud projects create "$PROJECT_ID" --name="GlobalDataCare ICA Dev"
```

If the project already exists, just continue.

### 3) Link billing account to project

```bash
PROJECT_ID=globaldatacare-ica-dev
BILLING_ACCOUNT_ID=014A34-6E960C-35E085

gcloud beta billing projects link "$PROJECT_ID" \
  --billing-account="$BILLING_ACCOUNT_ID"
```

### 4) Set project and ADC quota project

```bash
PROJECT_ID=globaldatacare-ica-dev

gcloud config set project "$PROJECT_ID"
gcloud auth application-default set-quota-project "$PROJECT_ID"
```

### 5) Enable required APIs

```bash
PROJECT_ID=globaldatacare-ica-dev

gcloud services enable \
  artifactregistry.googleapis.com \
  container.googleapis.com \
  firebasestorage.googleapis.com \
  firestore.googleapis.com \
  serviceusage.googleapis.com \
  --project="$PROJECT_ID"
```

### 6) Create GCS bucket for audit/doc storage

```bash
PROJECT_ID=globaldatacare-ica-dev
REGION=europe-southwest1
BUCKET=globaldatacare-ica-dev

gcloud storage buckets create "gs://$BUCKET" \
  --project="$PROJECT_ID" \
  --location="$REGION" \
  --uniform-bucket-level-access
```

### 7) Grant runtime service account access to bucket

Replace `<RUNTIME_SA_EMAIL>` with the service account used by your workload.

```bash
BUCKET=globaldatacare-ica-dev
RUNTIME_SA_EMAIL=<runtime-sa>@globaldatacare-ica-dev.iam.gserviceaccount.com

gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:$RUNTIME_SA_EMAIL" \
  --role="roles/storage.objectAdmin"
```

### 8) Minimal IAM roles for deploy operator

The account running `cloud_deploy.sh` typically needs:
- `roles/serviceusage.serviceUsageAdmin`
- `roles/artifactregistry.admin` (or repository-level write permissions)
- `roles/container.developer` (or stronger, depending on cluster policy)
- `roles/iam.serviceAccountUser` (if acting as runtime SA)

## IAM helper script (developers/groups)

To grant IAM roles for multiple developers (or a group) across billing + projects:

```bash
./scripts/iam_grant_developers.sh \
  --members "dev1@example.com,dev2@example.com" \
  --member-type user \
  --projects "globaldatacare-ica-dev,globaldatacare-test" \
  --billing-account "014A34-6E960C-35E085" \
  --org-id "<ORG_ID>" \
  --dry-run
```

Run again without `--dry-run` to apply.

Group example:

```bash
./scripts/iam_grant_developers.sh \
  --members "platform-devs@example.com" \
  --member-type group \
  --projects "globaldatacare-ica-dev,globaldatacare-test" \
  --billing-account "014A34-6E960C-35E085" \
  --org-id "<ORG_ID>"
```

The script defaults project roles to:
- `roles/container.admin`
- `roles/iam.serviceAccountUser`
- `roles/serviceusage.serviceUsageAdmin`
- `roles/artifactregistry.admin`

## Firestore bootstrap (Native mode)

If Firestore database is not initialized yet:

```bash
PROJECT_ID=globaldatacare-ica-dev
gcloud firestore databases create --project="$PROJECT_ID" --location=europe-west3 --type=firestore-native
```

Adjust location to your policy/latency needs.

## Manual fallback

If you prefer manual commands:

```bash
docker build -t dataspace-ica:local .
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/deployment.yaml
```

Then set image and rollout:

```bash
kubectl set image deployment/dataspace-ica-api api="<image-uri>"
kubectl rollout status deployment/dataspace-ica-api --timeout=180s
```

## Optional local access from cluster

```bash
kubectl port-forward svc/dataspace-ica-api 3310:80
curl -sS http://localhost:3310/ | jq .
```

## Public URL in cloud (LoadBalancer)

By default, `deploy/k8s/service.yaml` uses `ClusterIP` (internal-only), so there is no public URL.

To expose it with a public IP:

```bash
kubectl -n dataspace-ica patch svc dataspace-ica-api -p '{"spec":{"type":"LoadBalancer"}}'
kubectl -n dataspace-ica get svc dataspace-ica-api -w
```

When `EXTERNAL-IP` is assigned:

```bash
export ICA_PUBLIC_IP="$(kubectl -n dataspace-ica get svc dataspace-ica-api -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
echo "http://${ICA_PUBLIC_IP}/api-docs"
echo "http://${ICA_PUBLIC_IP}/openapi.json"
echo "http://${ICA_PUBLIC_IP}/.well-known/did.json"
```

For stable production hostname/TLS, use Ingress + DNS and set:
- `ICA_EXTERNAL_DOMAIN`
- optional `ICA_OPENAPI_SERVER_URL`
- optional DID service endpoint overrides (`ICA_DID_SERVICE_ENDPOINT`, `ICA_DCAT_SERVICE_ENDPOINT`, `ICA_DSP_DATA_SERVICE_ENDPOINT`, `ICA_DCP_ISSUER_SERVICE_ENDPOINT`)

## Optional: deploy same image to Cloud Run (`*.run.app`)

If you want the automatic `*.run.app` URL, you can deploy the same pushed image to Cloud Run.

```bash
# Values should match your push target from cloud_deploy.sh
PROJECT_ID=globaldatacare-ica-dev
REGION=europe-southwest1
SERVICE_NAME=globaldatacare-ica-dev
IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/globaldatacare/${SERVICE_NAME}:latest"

gcloud config set project "$PROJECT_ID"
gcloud run deploy "$SERVICE_NAME" \
  --image "$IMAGE_URI" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --port 3310

gcloud run services describe "$SERVICE_NAME" \
  --region "$REGION" \
  --format='value(status.url)'
```

Notes:
- Cloud Run URL is HTTPS (`https://...run.app`).
- For DID/OpenAPI host consistency, set `ICA_EXTERNAL_DOMAIN` (or `ICA_OPENAPI_SERVER_URL`) to your final domain.

## Troubleshooting

### ImagePullBackOff (403 Forbidden) pulling from Artifact Registry in another project

Symptom:
- Pod events show `ErrImagePull` / `ImagePullBackOff`
- Error includes `failed to fetch oauth token ... 403 Forbidden`

Cause:
- Cluster runs in project A (for example `globaldatacare-test`)
- Image is stored in Artifact Registry project B (for example `globaldatacare-ica-dev`)
- Node service account from project A has no `artifactregistry.reader` on project B.

Copy/paste fix:

```bash
# ---- adjust if needed ----
CLUSTER_PROJECT=globaldatacare-test
IMAGE_PROJECT=globaldatacare-ica-dev
AR_REGION=europe-southwest1
AR_REPOSITORY=globaldatacare
NAMESPACE=dataspace-ica
DEPLOYMENT=dataspace-ica-api
# --------------------------

# 1) Resolve default node SA (when GKE cluster uses default compute SA)
PROJECT_NUMBER=$(gcloud projects describe "$CLUSTER_PROJECT" --format='value(projectNumber)')
NODE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
echo "NODE_SA=$NODE_SA"

# 2) Grant pull permission (project-level, simplest)
gcloud projects add-iam-policy-binding "$IMAGE_PROJECT" \
  --member="serviceAccount:${NODE_SA}" \
  --role="roles/artifactregistry.reader"

# 2b) Optional tighter scope (repository-level) instead of project-level:
# gcloud artifacts repositories add-iam-policy-binding "$AR_REPOSITORY" \
#   --location="$AR_REGION" \
#   --project="$IMAGE_PROJECT" \
#   --member="serviceAccount:${NODE_SA}" \
#   --role="roles/artifactregistry.reader"

# 3) Restart rollout and wait
kubectl -n "$NAMESPACE" rollout restart deployment/"$DEPLOYMENT"
kubectl -n "$NAMESPACE" rollout status deployment/"$DEPLOYMENT" --timeout=300s
kubectl -n "$NAMESPACE" get pods -o wide
```

If an old pod is stuck in `Terminating`:

```bash
kubectl -n dataspace-ica get pods -o wide --sort-by=.metadata.creationTimestamp
# replace OLD_POD_NAME with the real pod name (do not include <>)
kubectl -n dataspace-ica delete pod OLD_POD_NAME --grace-period=0 --force
kubectl -n dataspace-ica rollout status deployment/dataspace-ica-api --timeout=300s
```

### CreateContainerConfigError after image pull is fixed

Symptom:
- Pods are created but stay in `CreateContainerConfigError`
- Rollout output is stuck at `1 old replicas are pending termination...`

Common cause in this project:
- Container image runs as user `node` (uid 1000)
- Pod only had `runAsNonRoot: true` without explicit numeric UID/GID in pod security context

Fix applied in repo:
- [`deploy/k8s/deployment.yaml`](/Users/fernando/GITS/gdc-workspace/dataspace-ica-cli/deploy/k8s/deployment.yaml) now sets:
  - `runAsNonRoot: true`
  - `runAsUser: 1000`
  - `runAsGroup: 1000`
  - `fsGroup: 1000`

If cluster is already running old manifest, patch in place:

```bash
kubectl -n dataspace-ica patch deployment dataspace-ica-api --type='merge' -p '{
  "spec":{"template":{"spec":{"securityContext":{
    "runAsNonRoot":true,
    "runAsUser":1000,
    "runAsGroup":1000,
    "fsGroup":1000
  }}}}
}'
kubectl -n dataspace-ica rollout restart deployment/dataspace-ica-api
kubectl -n dataspace-ica rollout status deployment/dataspace-ica-api --timeout=300s
```

To inspect exact failure reason in events:

```bash
kubectl -n dataspace-ica get pods -l app=dataspace-ica-api -o wide
kubectl -n dataspace-ica describe pod POD_NAME | sed -n '/Events:/,$p'
```
