# Discovery Export Runbook (GlobalDataCare + ProcureData)

Complete operational guide for:

1. exporting historical VCs from Firestore,
2. downloading PDFs referenced by VCs,
3. regenerating VCs from local PDFs.

## 0) Prerequisites

- Be inside the `dataspace-ica-ts` repository.
- Have IAM permissions for Firestore and GCS in each project.
- Have ADC authentication active.
- For deterministic export: run a local ICA instance (for example `http://localhost:8010`).
- For real deterministic regeneration: use the same seed/key configuration as
  the target environment.

### 0.1 ICA deterministic keys (required for v2)

Before regenerating deterministic VCs, ICA must start with these variables:

- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE=<secret>`
- `ICA_VC_PRIVATE_KEY_SEED_CONFIG=17:8:1:48`
- `ICA_VC_PRIVATE_KEY_SEED_SALT=ica-seed-salt-v1`
- `ICA_VC_SEED_ALG=ES384`
- `ICA_SELF_SIGN_TEST=true`

Reference files:

- GlobalDataCare v1: `.env.deploy.staging`
- ProcureData: `.env.deploy.procuredata`

Example (without printing secrets):

```bash
# GlobalDataCare v1
set -a
source .env.deploy.staging
set +a

# ProcureData
set -a
source .env.deploy.procuredata
set +a
```

Minimal validation before regeneration:

```bash
env | rg '^ICA_VC_PRIVATE_KEY_SEED_|^ICA_VC_SEED_ALG|^ICA_SELF_SIGN_TEST'
```

## 1) Base login

```bash
gcloud auth application-default login
gcloud config set project <YOUR_PROJECT_ID>
```

Minimal template:

```bash
node scripts/export-discovery-vcs.mjs \
  --project <YOUR_PROJECT_ID> \
  --prefix <dev|st-v2|...> \
  --tenant ica \
  --outdir discovery
```

## 2) GlobalDataCare (`globaldatacare-ica-dev`)

### 2.1 Historical export

```bash
gcloud config set project globaldatacare-ica-dev

node scripts/export-discovery-vcs.mjs \
  --project globaldatacare-ica-dev \
  --prefix dev \
  --tenant ica \
  --namespace globaldatacare \
  --outdir discovery
```

Output:

- `discovery/globaldatacare/ica/organization/...`
- `discovery/globaldatacare/ica/organization-representative/...`
- `discovery/logs/globaldatacare-ica-dev/...`

### 2.2 PDF download

```bash
node scripts/download-discovery-pdfs.mjs \
  --project globaldatacare-ica-dev \
  --namespace globaldatacare \
  --discovery-root discovery \
  --gcs-bucket globaldatacare-ica-dev \
  --gcs-audit-prefix ica-audit \
  --gcs-ipfs-prefix ipfs
```

Output:

- PDFs: `discovery/globaldatacare-ica-dev/pdfs/...`
- logs: `discovery/logs/globaldatacare-ica-dev/...`

### 2.3 Deterministic export

```bash
node scripts/export-discovery-vcs-deterministic.mjs \
  --base http://localhost:8010 \
  --tenant ica \
  --jurisdiction ES \
  --sector health-care \
  --resource contract \
  --namespace globaldatacare \
  --pdf-root discovery/globaldatacare-ica-dev/pdfs \
  --outdir discovery-deterministic \
  --project globaldatacare-ica-dev
```

## 3) ProcureData (`procuredata-test`)

### 3.1 Historical export

```bash
gcloud config set project procuredata-test

node scripts/export-discovery-vcs.mjs \
  --project procuredata-test \
  --prefix st-v2 \
  --tenant ica \
  --namespace procuredata \
  --outdir discovery
```

Output:

- `discovery/procuredata/ica/organization/...`
- `discovery/procuredata/ica/organization-representative/...`
- `discovery/logs/procuredata-test/...`

### 3.2 PDF download

```bash
node scripts/download-discovery-pdfs.mjs \
  --project procuredata-test \
  --namespace procuredata \
  --discovery-root discovery \
  --gcs-bucket procuredata-test-ica \
  --gcs-audit-prefix st-v2-ica-audit \
  --gcs-ipfs-prefix st-v2-ipfs
```

### 3.3 Deterministic export

```bash
node scripts/export-discovery-vcs-deterministic.mjs \
  --base http://localhost:8010 \
  --tenant ica \
  --jurisdiction ES \
  --sector procurement \
  --resource contract \
  --namespace procuredata \
  --pdf-root discovery/procuredata-test/pdfs \
  --outdir discovery-deterministic \
  --project procuredata-test
```

## 4) Expected structure

Historical:

- `discovery/<namespace>/ica/organization/VATES-<VAT>/vc-contract-organization-<timestamp>.json`
- `discovery/<namespace>/ica/organization-representative/VATES-<VAT>/vc-contract-representative-<timestamp>.json`

Deterministic:

- `discovery-deterministic/<namespace>/ica/organization/VATES-<VAT>/vc-contract-organization-<timestamp>.json`
- `discovery-deterministic/<namespace>/ica/organization-representative/VATES-<VAT>/vc-contract-representative-<timestamp>.json`

## 5) Quick validations

```bash
ls -lah discovery/logs/globaldatacare-ica-dev
ls -lah discovery/logs/procuredata-test

find discovery/globaldatacare/ica -name 'vc-contract-*.json' | wc -l
find discovery/procuredata/ica -name 'vc-contract-*.json' | wc -l

find discovery-deterministic/globaldatacare/ica -name 'vc-contract-*.json' | wc -l
find discovery-deterministic/procuredata/ica -name 'vc-contract-*.json' | wc -l
```

## 6) Key notes

- `export-discovery-vcs.mjs` exports from Firestore; it does not re-verify the
  PDF.
- `download-discovery-pdfs.mjs` supports `https://`, `urn:uuid`, and `ipfs://`.
- `urn:uuid` and `ipfs://` are resolved through GCS (same backend), not through
  an HTTP gateway.
- Always use `--namespace` to avoid mixing GlobalDataCare and ProcureData
  exports.
- If a bucket/prefix is missing, inspect `download-pdfs-unresolved-*.txt` and
  `download-pdfs-summary-*.txt`.
