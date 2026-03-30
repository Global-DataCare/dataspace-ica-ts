# Discovery Export Runbook (GlobalDataCare + ProcureData)

Guía operativa completa para:

1. exportar VCs históricas desde Firestore,
2. descargar PDFs referenciados en VCs,
3. regenerar VCs desde PDFs locales.

## 0) Prerrequisitos

- Estar en el repo `dataspace-ica-ts`.
- Tener permisos IAM para Firestore y GCS de cada proyecto.
- Tener autenticación ADC activa.
- Para export determinístico: ICA local levantada (ejemplo `http://localhost:8010`).
- Para regeneración determinística real: usar el mismo seed/key config de cada entorno.

### 0.1 Claves determinísticas ICA (obligatorio para v2)

Antes de regenerar VCs determinísticas, la ICA debe arrancar con estas variables:

- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE=<secreto>`
- `ICA_VC_PRIVATE_KEY_SEED_CONFIG=17:8:1:48`
- `ICA_VC_PRIVATE_KEY_SEED_SALT=ica-seed-salt-v1`
- `ICA_VC_SEED_ALG=ES384`
- `ICA_SELF_SIGN_TEST=true`

Referencia de archivos:

- GlobalDataCare v1: `.env.deploy.staging`
- ProcureData: `.env.deploy.procuredata`

Ejemplo (sin imprimir secretos):

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

Validación mínima antes de regenerar:

```bash
env | rg '^ICA_VC_PRIVATE_KEY_SEED_|^ICA_VC_SEED_ALG|^ICA_SELF_SIGN_TEST'
```

## 1) Login base

```bash
gcloud auth application-default login
gcloud config set project <TU_PROJECT_ID>
```

Plantilla mínima:

```bash
node scripts/export-discovery-vcs.mjs \
  --project <TU_PROJECT_ID> \
  --prefix <dev|st-v2|...> \
  --tenant ica \
  --outdir discovery
```

## 2) GlobalDataCare (`globaldatacare-ica-dev`)

### 2.1 Export histórico

```bash
gcloud config set project globaldatacare-ica-dev

node scripts/export-discovery-vcs.mjs \
  --project globaldatacare-ica-dev \
  --prefix dev \
  --tenant ica \
  --namespace globaldatacare \
  --outdir discovery
```

Salida:

- `discovery/globaldatacare/ica/organization/...`
- `discovery/globaldatacare/ica/organization-representative/...`
- `discovery/logs/globaldatacare-ica-dev/...`

### 2.2 Descarga de PDFs

```bash
node scripts/download-discovery-pdfs.mjs \
  --project globaldatacare-ica-dev \
  --namespace globaldatacare \
  --discovery-root discovery \
  --gcs-bucket globaldatacare-ica-dev \
  --gcs-audit-prefix ica-audit \
  --gcs-ipfs-prefix ipfs
```

Salida:

- PDFs: `discovery/globaldatacare-ica-dev/pdfs/...`
- logs: `discovery/logs/globaldatacare-ica-dev/...`

### 2.3 Export determinístico

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

### 3.1 Export histórico

```bash
gcloud config set project procuredata-test

node scripts/export-discovery-vcs.mjs \
  --project procuredata-test \
  --prefix st-v2 \
  --tenant ica \
  --namespace procuredata \
  --outdir discovery
```

Salida:

- `discovery/procuredata/ica/organization/...`
- `discovery/procuredata/ica/organization-representative/...`
- `discovery/logs/procuredata-test/...`

### 3.2 Descarga de PDFs

```bash
node scripts/download-discovery-pdfs.mjs \
  --project procuredata-test \
  --namespace procuredata \
  --discovery-root discovery \
  --gcs-bucket procuredata-test-ica \
  --gcs-audit-prefix st-v2-ica-audit \
  --gcs-ipfs-prefix st-v2-ipfs
```

### 3.3 Export determinístico

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

## 4) Estructura esperada

Histórico:

- `discovery/<namespace>/ica/organization/VATES-<VAT>/vc-contract-organization-<timestamp>.json`
- `discovery/<namespace>/ica/organization-representative/VATES-<VAT>/vc-contract-representative-<timestamp>.json`

Determinístico:

- `discovery-deterministic/<namespace>/ica/organization/VATES-<VAT>/vc-contract-organization-<timestamp>.json`
- `discovery-deterministic/<namespace>/ica/organization-representative/VATES-<VAT>/vc-contract-representative-<timestamp>.json`

## 5) Validaciones rápidas

```bash
ls -lah discovery/logs/globaldatacare-ica-dev
ls -lah discovery/logs/procuredata-test

find discovery/globaldatacare/ica -name 'vc-contract-*.json' | wc -l
find discovery/procuredata/ica -name 'vc-contract-*.json' | wc -l

find discovery-deterministic/globaldatacare/ica -name 'vc-contract-*.json' | wc -l
find discovery-deterministic/procuredata/ica -name 'vc-contract-*.json' | wc -l
```

## 6) Notas clave

- `export-discovery-vcs.mjs` exporta desde Firestore (no re-verifica PDF).
- `download-discovery-pdfs.mjs` soporta `https://`, `urn:uuid`, `ipfs://`.
- `urn:uuid` e `ipfs://` se resuelven en GCS (mismo backend), no por gateway HTTP.
- Usa `--namespace` siempre para evitar mezclar GlobalDataCare y ProcureData.
- Si falta bucket/prefijo correcto, revisa `download-pdfs-unresolved-*.txt` y `download-pdfs-summary-*.txt`.
