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

Deploy the same locally built `dataspace-ica:<package-version>` image to GKE:

```bash
# uses .env.deploy.staging and pushes local image without rebuilding
./cloud_deploy.sh staging

# staging-v2 environment with separate K8S resource names and IP
./cloud_deploy.sh st-v2
```

Versioning note:
- Keep the stable staging v1 Kubernetes names under the `dataspace-ica-*` prefix.
- Use the package/image tag to represent the release line (`0.4.x` for staging v1, `0.5.x` for v2).
- Only the coexistence environment gets a suffix in K8S names, for example `dataspace-ica-api-st-v2`.
- After cutover, v2 can run again under the canonical `dataspace-ica-*` names in staging/production.

`cloud_deploy.sh` always triggers a deployment restart so updated runtime secrets/env are applied even when image tag stays the same.

`cloud_deploy.sh` expects these variables inside `.env.deploy.<env>`:
- `FIRESTORE_PROJECT_ID`
- `DEPLOY_REGION`
- `DEPLOY_SERVICE_NAME`
- `ARTIFACT_REGISTRY_NAME`
- optional: `IMAGE_TAG`, `K8S_NAMESPACE`, `K8S_CONTEXT`, `LOCAL_IMAGE`, `K8S_LOADBALANCER_IP`, `GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT`, `K8S_APP_NAME`, `K8S_SERVICE_NAME`, `K8S_CONFIGMAP_NAME`, `K8S_SECRET_NAME`, `K8S_SERVICE_ACCOUNT_NAME`

Recommended:
- Set `IMAGE_TAG` explicitly (for example `0.4.2`) to keep deploys aligned with the package version.

Important:
- `cloud_deploy.sh` does not create the GCP project, billing link, bucket, or cluster for you.
- Those resources must exist (and your account must have IAM permissions) before running deploy.
- If `GOOGLE_APPLICATION_CREDENTIALS` is set in `.env.deploy.<env>`, `cloud_deploy.sh` validates that the pointed file exists locally and that its `project_id` matches `FIRESTORE_PROJECT_ID`.
- The deployment uses Kubernetes ServiceAccount `dataspace-ica-runtime`. If `GCP_WORKLOAD_IDENTITY_SERVICE_ACCOUNT` is set, `cloud_deploy.sh` annotates that KSA with `iam.gke.io/gcp-service-account=<GSA>`.

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

Cross-project note:
- If GKE cluster runs in project A and bucket is in project B, grant bucket IAM in project B to the runtime identity from project A.
- For default GKE node identity:

```bash
CLUSTER_PROJECT=globaldatacare-test
PROJECT_NUMBER=$(gcloud projects describe "$CLUSTER_PROJECT" --format='value(projectNumber)')
NODE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

gcloud storage buckets add-iam-policy-binding "gs://globaldatacare-ica-dev" \
  --member="serviceAccount:${NODE_SA}" \
  --role="roles/storage.objectAdmin"
```

### 8) Minimal IAM roles for deploy operator

The account running `cloud_deploy.sh` typically needs:
- `roles/serviceusage.serviceUsageAdmin`
- `roles/artifactregistry.admin` (or repository-level write permissions)
- `roles/container.developer` (or stronger, depending on cluster policy)
- `roles/iam.serviceAccountUser` (if acting as runtime SA)

### 8.1) Runtime identity for Firestore and GCS

The pod may start successfully and still fail at runtime if its workload identity does not have access to Firestore/GCS.

Required model:

- local development = JSON file
- cloud/GKE = Workload Identity

Create or reuse a runtime GSA in the runtime project:

```bash
gcloud iam service-accounts create dataspace-ica-runtime \
  --project globaldatacare-ica-dev \
  --display-name="dataspace-ica runtime"
```

Grant runtime IAM:

```bash
gcloud projects add-iam-policy-binding globaldatacare-ica-dev \
  --member="serviceAccount:dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com" \
  --role="roles/datastore.user"

gcloud storage buckets add-iam-policy-binding gs://globaldatacare-ica-dev \
  --member="serviceAccount:dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"
```

This repo uses Kubernetes Service Account `dataspace-ica-runtime`.

If Workload Identity is not enabled yet on the cluster, enable it first:

```bash
gcloud container clusters update gdc-unid-southwest \
  --project globaldatacare-test \
  --zone europe-southwest1-a \
  --workload-pool=globaldatacare-test.svc.id.goog
```

Then bind KSA -> GSA:

```bash
kubectl annotate serviceaccount dataspace-ica-runtime \
  -n dataspace-ica \
  iam.gke.io/gcp-service-account=dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com \
  --overwrite

gcloud iam service-accounts add-iam-policy-binding \
  dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com \
  --project globaldatacare-ica-dev \
  --member="serviceAccount:globaldatacare-test.svc.id.goog[dataspace-ica/dataspace-ica-runtime]" \
  --role="roles/iam.workloadIdentityUser"
```

Do not keep this in `.env.deploy.staging`:

```bash
GOOGLE_APPLICATION_CREDENTIALS=./gcp-service-account.json
```

Redeploy after the binding:

```bash
./cloud_deploy.sh staging --yes
kubectl -n dataspace-ica rollout restart deployment/dataspace-ica-api
kubectl -n dataspace-ica rollout status deployment/dataspace-ica-api --timeout=240s
```

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
docker build -t dataspace-ica:0.4.2 .
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

By default, `deploy/k8s/service.yaml` uses `LoadBalancer`, so GKE allocates a public external IP.

To check assigned public IP:

```bash
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

### Post-deploy quick checks

Use this checklist after every deploy:

```bash
NAMESPACE=dataspace-ica

# Runtime status
kubectl -n "$NAMESPACE" get pods -o wide
kubectl -n "$NAMESPACE" get svc dataspace-ica-api -o wide

# Public IP (empty when still pending)
EXTERNAL_IP="$(kubectl -n "$NAMESPACE" get svc dataspace-ica-api -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
echo "$EXTERNAL_IP"

# Deployed image in the running Deployment
kubectl -n "$NAMESPACE" get deployment dataspace-ica-api -o jsonpath='{.spec.template.spec.containers[0].image}'; echo

# API and discovery checks
curl -sS "http://$EXTERNAL_IP/" | jq .
curl -sS "http://$EXTERNAL_IP/openapi.json" | jq '.info.version, .servers'
curl -sS "http://$EXTERNAL_IP/.well-known/did.json" | jq '.id'
```

### Check deployed version (quick command)

```bash
NAMESPACE=dataspace-ica
DEPLOYMENT=dataspace-ica-api
SERVICE=dataspace-ica-api

echo "Image in deployment:"
kubectl -n "$NAMESPACE" get deployment "$DEPLOYMENT" \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'

EXTERNAL_IP="$(kubectl -n "$NAMESPACE" get svc "$SERVICE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
echo "Public IP: $EXTERNAL_IP"
curl -sS "http://$EXTERNAL_IP/openapi.json" | jq '.info.version,.servers'
```

Notes:
- `CLUSTER-IP` (service internal IP) is not public.
- `EXTERNAL-IP` is the public service entrypoint.
- Pod IPs (`10.x.x.x`) are private and can change on restarts.

### Static public IP (recommended)

Reserve a regional static IP in the same region as your GKE service:

```bash
PROJECT_ID=globaldatacare-ica-dev
REGION=europe-southwest1
IP_NAME=dataspace-ica-lb-ip

gcloud compute addresses create "$IP_NAME" \
  --region "$REGION" \
  --project "$PROJECT_ID"

gcloud compute addresses describe "$IP_NAME" \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --format='value(address)'
```

Set that value in `.env.deploy.<env>`:

```env
K8S_LOADBALANCER_IP=<RESERVED_IP>
```

Then deploy:

```bash
./cloud_deploy.sh staging
```

The deploy script patches `Service.spec.loadBalancerIP` automatically when `K8S_LOADBALANCER_IP` is set.

Important:
- The static IP must belong to the **cluster project** (the project of your current `kubectl` GKE context), not necessarily the image/artifact project.
- The static IP must be in the same region as the LoadBalancer service.
- If `EXTERNAL-IP` stays `<pending>`, run:

```bash
kubectl -n dataspace-ica describe svc dataspace-ica-api
```

Check events for messages like "requested IP is not reserved" or project/region mismatch.

## Optional: GCE Ingress + TLS

`cloud_deploy.sh` also supports a GCE `Ingress` frontend instead of exposing the API directly with `Service` type `LoadBalancer`.

Supported modes:
- `K8S_MANAGED_CERT_NAME` + `K8S_INGRESS_HOST` for domain-based TLS managed by Google
- `K8S_PRE_SHARED_CERT_NAME` for IP-first or domain-based TLS using an existing self-managed GCP SSL certificate
- `K8S_TLS_SECRET_NAME` for a Kubernetes TLS `Secret`

Only one TLS mode can be active at a time.

Useful env vars in `.env.deploy.<env>`:

```env
K8S_INGRESS_ENABLED=true
K8S_SERVICE_TYPE=NodePort
K8S_INGRESS_HOST=
K8S_INGRESS_STATIC_IP_NAME=ica-st-v2-ip
K8S_MANAGED_CERT_NAME=
K8S_PRE_SHARED_CERT_NAME=ica-st-v2-ip-cert
K8S_TLS_SECRET_NAME=
K8S_DISABLE_HTTP=false
```

IP-first staging pattern:
- leave `K8S_INGRESS_HOST=` empty
- reserve a **global** static IP in the **cluster project**
- upload a self-managed SSL certificate in GCP
- set `K8S_PRE_SHARED_CERT_NAME`

Example:

```bash
gcloud compute addresses create ica-st-v2-ip --global --project globaldatacare-test
gcloud compute ssl-certificates create ica-st-v2-ip-cert \
  --certificate=/path/to/tls.crt \
  --private-key=/path/to/tls.key \
  --global \
  --project globaldatacare-test
```

Then deploy:

```bash
./cloud_deploy.sh st-v2 --yes
```

Check ingress provisioning:

```bash
kubectl -n dataspace-ica get ingress dataspace-ica-api-st-v2 -w
kubectl -n dataspace-ica describe ingress dataspace-ica-api-st-v2
```

Notes:
- GCE `Ingress` uses a **global** static IP, unlike the regional `LoadBalancer` service IP.
- `K8S_INGRESS_STATIC_IP_NAME` must belong to the **cluster project**, not necessarily the Firestore/runtime project.
- If you want a browser-trusted certificate for an IP, provision that certificate separately and upload it as a GCP self-managed SSL certificate, or switch to a domain-based managed certificate flow.
- For the full list of real staging failures seen in `st-v2` and how they were fixed, see [`docs/troubleshooting-gke-ip-staging.md`](../../docs/troubleshooting-gke-ip-staging.md).

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

### Warning: active project does not match ADC quota project

Symptom during deploy:
- `WARNING: Your active project does not match the quota project in your local Application Default Credentials file.`

Fix:

```bash
PROJECT_ID=globaldatacare-ica-dev
gcloud config set project "$PROJECT_ID"
gcloud auth application-default set-quota-project "$PROJECT_ID"
```

### Error: `GOOGLE_APPLICATION_CREDENTIALS` file does not exist in pod

Symptom in API response/logs:
- `The file at ./gcp-service-account.json does not exist ... /app/gcp-service-account.json`

Cause:
- `GOOGLE_APPLICATION_CREDENTIALS` was set from local env file into Kubernetes runtime secret.
- In GKE, that local file path is not present inside the container unless explicitly mounted.

Fix (recommended for GKE):
- Remove/comment `GOOGLE_APPLICATION_CREDENTIALS` from `.env.deploy.<env>`.
- Redeploy so pod uses workload/node identity ADC instead of local file path.

```bash
./cloud_deploy.sh staging --yes
kubectl -n dataspace-ica rollout status deployment/dataspace-ica-api --timeout=300s
```

If you still get permission errors after removing it, grant IAM to the runtime identity used by the cluster (typically default compute SA) on the target project/resources:
- Firestore: `roles/datastore.user` (project with Firestore DB)
- GCS bucket (audit): `roles/storage.objectAdmin` on `gs://<bucket>`

### Warning: Docker config contains credHelpers entry

Symptom:
- `Your config file .../.docker/config.json contains credential helper entries ...`

Meaning:
- Informational. `gcloud auth configure-docker` is registering/confirming the Artifact Registry credential helper.
- This is expected and not a deploy error.

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
