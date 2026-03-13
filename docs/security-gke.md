# Security Notes for GKE Runtime

This note explains the minimum secure setup for this repository in GKE and the exact difference between local credentials and cluster runtime identity.

## 1) Runtime model: local vs cloud

This repository now uses two different authentication models on purpose:

- local development: `GOOGLE_APPLICATION_CREDENTIALS=./gcp-service-account.json`
- cloud/GKE: Workload Identity

For GKE:

- do not set `GOOGLE_APPLICATION_CREDENTIALS` in `.env.deploy.<env>`
- use `DB_PROVIDER=firestore`
- use `STORAGE_PROVIDER=gcs`
- grant Firestore/GCS IAM to the workload identity

The pod can be healthy and still fail at runtime if that workload identity does not have permissions on Firestore/GCS.

## 2) Why the `gcp-service-account.json` path failed

`GOOGLE_APPLICATION_CREDENTIALS=./gcp-service-account.json` works locally only if the file exists on the local filesystem.

In GKE pods, `/app/gcp-service-account.json` does not exist unless you explicitly mount it as a Kubernetes Secret volume.  
If set without mounting, runtime fails with ENOENT.

## 3) Project split (important)

In your setup, these can be different:

- Cluster project (GKE context): `globaldatacare-test`
- Runtime data/artifact project: `globaldatacare-ica-dev`

That is valid, but IAM must be explicitly granted cross-project.

## 4) What cloud runtime needs

### 4.1) Create or reuse a Google Service Account in the runtime project

Use a dedicated runtime GSA in `globaldatacare-ica-dev`:

```bash
gcloud iam service-accounts create dataspace-ica-runtime \
  --project globaldatacare-ica-dev \
  --display-name="dataspace-ica runtime"
```

If it already exists, reuse:

`dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com`

### 4.2) Grant Firestore and GCS permissions to that GSA

```bash
gcloud projects add-iam-policy-binding globaldatacare-ica-dev \
  --member="serviceAccount:dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com" \
  --role="roles/datastore.user"

gcloud storage buckets add-iam-policy-binding gs://globaldatacare-ica-dev \
  --member="serviceAccount:dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"
```

### 4.3) Enable Workload Identity on the cluster

If this is not enabled, the binding below fails and the pod cannot assume the GSA.

```bash
gcloud container clusters update gdc-unid-southwest \
  --project globaldatacare-test \
  --zone europe-southwest1-a \
  --workload-pool=globaldatacare-test.svc.id.goog
```

This cluster update may stay in `Updating ...` for several minutes.

Check later with:

```bash
gcloud container clusters describe gdc-unid-southwest \
  --project globaldatacare-test \
  --zone europe-southwest1-a \
  --format="yaml(workloadIdentityConfig,workloadPool,location,name)"
```

Expected after enablement:

- `workloadIdentityConfig.workloadPool: globaldatacare-test.svc.id.goog`

### 4.4) Bind the Kubernetes Service Account to the Google Service Account

This repo now uses Kubernetes Service Account `dataspace-ica-runtime`, not `default`.

Annotate the KSA:

```bash
kubectl annotate serviceaccount dataspace-ica-runtime \
  -n dataspace-ica \
  iam.gke.io/gcp-service-account=dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com \
  --overwrite
```

Allow impersonation from the cluster workload pool:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  dataspace-ica-runtime@globaldatacare-ica-dev.iam.gserviceaccount.com \
  --project globaldatacare-ica-dev \
  --member="serviceAccount:globaldatacare-test.svc.id.goog[dataspace-ica/dataspace-ica-runtime]" \
  --role="roles/iam.workloadIdentityUser"
```

Here:

- `globaldatacare-test` = cluster project
- `dataspace-ica` = Kubernetes namespace
- `dataspace-ica-runtime` = Kubernetes Service Account

### 4.5) What must not be in `.env.deploy.staging`

Do not set this in GKE runtime env:

```bash
GOOGLE_APPLICATION_CREDENTIALS=./gcp-service-account.json
```

That path exists on your laptop, not inside the pod.

### 4.6) Redeploy

```bash
./cloud_deploy.sh staging --yes
kubectl -n dataspace-ica rollout restart deployment/dataspace-ica-api
kubectl -n dataspace-ica rollout status deployment/dataspace-ica-api --timeout=240s
```

## 5) Fallback if Workload Identity is not enabled yet

If you do not enable Workload Identity, the pod keeps trying to use the node identity.

That may or may not work depending on IAM granted to the node pool service account, but it no longer depends on any local JSON file being injected into the pod.

## 6) Networking/IP reminders

- `CLUSTER-IP` is internal-only.
- `EXTERNAL-IP` is public service endpoint.
- Pod IP (`10.x.x.x`) is private and ephemeral.
- For stable public IP, use `K8S_LOADBALANCER_IP` with a reserved IP in the cluster project/region.

## 7) Quick validation after deploy

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
