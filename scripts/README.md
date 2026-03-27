# Scripts de smoke test y limpieza

## `firestore-vat-manager.mjs`

Inspecciona o borra documentos Firestore asociados a un VAT en las 4 colecciones de ICA:

- `issued_credentials`
- `evidence_records`
- `did_bindings`
- `did_documents`

Uso:

```bash
node scripts/firestore-vat-manager.mjs --vat VATES-B42215152
node scripts/firestore-vat-manager.mjs --vat VATES-B42215152 --delete
node scripts/firestore-vat-manager.mjs --vat VATES-B42215152 --prefix st-v2 --project globaldatacare-ica-dev --delete
```

Opciones:

- `--vat`: VAT a buscar, obligatorio
- `--project`: proyecto GCP Firestore, por defecto `globaldatacare-ica-dev`
- `--prefix`: prefijo de colecciones, por defecto `dev`
- `--delete`: borra los documentos encontrados
- `--yes`: omite confirmación interactiva cuando se usa `--delete`
- `--json`: devuelve salida JSON

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
  --vat VATES-B42215152 \
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
