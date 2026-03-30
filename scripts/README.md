# Scripts de smoke test y limpieza

## `firestore-vat-manager.mjs`

Inspecciona o borra documentos Firestore asociados a un VAT en las 4 colecciones de ICA:

- `issued_credentials`
- `evidence_records`
- `did_bindings`
- `did_documents`

Uso:

```bash
node scripts/firestore-vat-manager.mjs --vat VATES-B00112233
node scripts/firestore-vat-manager.mjs --vat VATES-B00112233 --delete
node scripts/firestore-vat-manager.mjs --vat VATES-B00112233 --prefix st-v2 --project globaldatacare-ica-dev --delete
```

Opciones:

- `--vat`: VAT a buscar, obligatorio
- `--project`: proyecto GCP Firestore, por defecto `globaldatacare-ica-dev`
- `--prefix`: prefijo de colecciones, por defecto `dev`
- `--delete`: borra los documentos encontrados
- `--yes`: omite confirmación interactiva cuando se usa `--delete`
- `--json`: devuelve salida JSON

## `export-discovery-vcs.mjs`

Exporta credenciales de organización y representante desde Firestore a estructura `discovery/` para repositorio público:

- `discovery/<namespace>/ica/organization/VATES-<VAT>/vc-contract-organization-<timestamp>.json`
- `discovery/<namespace>/ica/organization-representative/VATES-<VAT>/vc-contract-representative-<timestamp>.json`
- logs en `discovery/logs/` (`summary`, `vats`, `vat-records`, `pdf-links`, `missing-pdf-links`)

Uso:

```bash
node scripts/export-discovery-vcs.mjs --project globaldatacare-ica-dev --prefix dev
node scripts/export-discovery-vcs.mjs --project <project> --prefix st-v2 --tenant ica --outdir discovery
node scripts/export-discovery-vcs.mjs --project procuredata-test --prefix st-v2 --tenant ica --namespace procuredata --outdir discovery
```

Opciones:

- `--project`: proyecto Firestore (default `globaldatacare-ica-dev`)
- `--prefix`: prefijo de colecciones (default `dev`)
- `--outdir`: directorio raíz de salida (default `discovery`)
- `--namespace`: namespace de salida en discovery (default inferido del project: `procuredata` o `globaldatacare`)
- `--tenant`: filtro opcional por tenant
- `--jurisdiction`: filtro opcional por jurisdicción
- `--sector`: filtro opcional por sector
- `--all`: exporta todas las versiones (si no, exporta la última por `VAT + tipo`)

Notas:

- El timestamp del nombre de archivo se toma de `credential.evidence[type=document].time` (fecha documental/verifier) y hace fallback a `updatedAt/createdAt`.
- La exportación se hace desde Firestore (`issued_credentials`) sin requerir descargar el PDF.
- Se registran enlaces documentales (`attachments.url`) en `discovery/logs/pdf-links-*.txt` para comprobar qué PDFs son recuperables.
- TODO: añadir modo opcional para descargar automáticamente PDFs accesibles desde `pdf-links`.

## `download-discovery-pdfs.mjs`

Descarga PDFs desde enlaces documentales ya exportados en VCs de `discovery/`.

Comportamiento:

- lee JSONs en `discovery/<namespace>/ica/{organization,organization-representative}/...`
- extrae `evidence[type=document].attachments.url`
- soporta enlaces `https://`, `urn:uuid:<id>` e `ipfs://<cid>`
- `urn:uuid` e `ipfs` se resuelven contra GCS (mismo backend), no contra gateway HTTP
- guarda en `discovery/<project>/pdfs/VATES-<VAT>/contract-<timestamp>-<hash>.pdf`
- si el archivo ya existe, no lo descarga de nuevo
- logs en `discovery/logs/<project>/` (`downloaded`, `skipped`, `failed`, `unresolved`, `summary`)

Uso:

```bash
node scripts/download-discovery-pdfs.mjs --project globaldatacare-ica-dev --discovery-root discovery

# con bucket GCS explícito (recomendado para urn/ipfs)
node scripts/download-discovery-pdfs.mjs \
  --project globaldatacare-ica-dev \
  --discovery-root discovery \
  --gcs-bucket globaldatacare-ica-dev \
  --gcs-audit-prefix ica-audit \
  --gcs-ipfs-prefix ipfs

# procuredata (namespace separado)
node scripts/download-discovery-pdfs.mjs \
  --project procuredata-test \
  --namespace procuredata \
  --discovery-root discovery \
  --gcs-bucket procuredata-test-ica \
  --gcs-audit-prefix st-v2-ica-audit
```

Opciones relevantes:

- `--gcs-bucket`: bucket GCS donde están audit PDFs/CIDs.
- `--gcs-audit-prefix`: prefijo de objetos de auditoría (por defecto `ICA_AUDIT_STORAGE_GCS_PREFIX` o `ica-audit`).
- `--gcs-ipfs-prefix`: prefijo para objetos por CID (por defecto `ICA_IPFS_GCS_PREFIX` o `ipfs`).

## `export-discovery-vcs-deterministic.mjs`

Regenera VCs llamando a ICA `_verify/_verify-response` usando PDFs locales ya descargados.

Comportamiento:

- recorre PDFs en `--pdf-root`
- envía cada PDF a `_verify` (async) y hace polling `_verify-response`
- exporta VCs nuevas a `discovery-deterministic/<namespace>/...` (`namespace` inferido o explícito)
- logs en `discovery-deterministic/logs/<project>/`

Uso:

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

## `verify-and-create.mjs`

Ejecuta un smoke test ICA contra `_verify` y `_create`.

Además puede limpiar Firestore antes y/o después para dejar el entorno repetible.

Uso básico:

```bash
node scripts/verify-and-create.mjs \
  --pdf "https://www.dropbox.com/scl/fi/mg9cd7hn2e3uliuik6a2m/TEST-A4-multisign-fnmt.pdf?rlkey=e2vionm99mb1zua6xx2qghwdi&st=yz4sjslb&dl=1" \
  --sector health-care
```

Uso recomendado en staging, con limpieza completa:

```bash
node scripts/verify-and-create.mjs \
  --pdf "https://www.dropbox.com/scl/fi/mg9cd7hn2e3uliuik6a2m/TEST-A4-multisign-fnmt.pdf?rlkey=e2vionm99mb1zua6xx2qghwdi&st=yz4sjslb&dl=1" \
  --sector health-care \
  --vat VATES-B00112233 \
  --cleanup-always
```

Opciones relevantes:

- `--base`: URL base del ICA, por defecto `http://34.175.75.120`
- `--tenant`: tenant ICA, por defecto `ica`
- `--jur`: jurisdicción, por defecto `ES`
- `--sector`: sector, por defecto `health-care`
- `--resource`: resource type, por defecto `contract`
- `--pdf`: ruta local o URL directa al PDF firmado
- `--vat`: VAT para limpieza previa; recomendado si se usa `--cleanup-before` o `--cleanup-always`
- `--project`: proyecto Firestore, por defecto `globaldatacare-ica-dev`
- `--prefix`: prefijo Firestore, por defecto `dev`
- `--cleanup-before`: limpia el VAT antes del test
- `--cleanup-after`: limpia el VAT después del test
- `--cleanup-always`: activa limpieza antes y después
- `--skip-create`: ejecuta sólo `_verify`
- `--out`: ruta del JSON de salida

## Comportamiento de limpieza

- Si se usa `--cleanup-before`, el script necesita saber el VAT antes de empezar. Para eso conviene pasar `--vat`.
- Si se usa `--cleanup-after`, el script borra usando el VAT detectado en la respuesta `_verify`.
- Si se usa `--cleanup-always`, el comportamiento recomendado es pasar también `--vat`, para que la limpieza previa y posterior sean consistentes.

## Artefactos

Cada ejecución guarda un JSON en `artifacts/smoke/verify-create-<timestamp>.json` con:

- parámetros usados
- resultado de `_verify`
- resultado de `_create`
- claves JWK generadas para el test
- estado de limpieza `before/after`
