# dataspace-ica (private)

Repositorio TypeScript con dos capacidades:

- CLI de operaciones ICA (onboarding, firma CSR, publicacion).
- API async de verificacion/activacion y operaciones de red (`_verify`, `_activate`, `_add`, `_issue`, `_status`, `_revoke` + polling).

Estado actual:

- API `_verify`, `_activate`, `_add` (evidence), `_issue` (credentials), `_status` y `_revoke` implementadas con patron async (`202 + Location` + polling).
- Respuestas de negocio y errores `4xx/5xx` en formato DIDComm plaintext (`jti/iss/aud/thid/type/body`).
- `body` contiene `Bundle batch-response` con `issues`, `data[]` y `result`.

## Quick Start (5 minutos)

Requisitos:

- Node.js 22+
- OpenSSL en `PATH`

Instalacion:

```bash
npm install
```

Arranque local:

```bash
cp .env.local.example .env.local
npm run dev
```

Comprobacion rapida:

```bash
curl -sS http://localhost:3310/ | jq .
curl -sS http://localhost:3310/openapi.json | jq '.openapi'
curl -sS http://localhost:3310/.well-known/did.json | jq '.id'
curl -i http://localhost:3310/api-docs
```

Nota: en navegador usa `http://localhost:3310/...` (no `0.0.0.0`).

## Flujo API con `curl`

Variables de prueba:

```bash
BASE="http://localhost:3310"
TENANT="ica"
JUR="ES"
SECTOR="animal-care"
VERSION="202630011200"
THID="verify-terms-001"
PDF_FILE="$HOME/Documents/TEST-A4-signed-fnmt.pdf"
```

Enviar job (`_verify`) solo DIDComm plaintext (`application/didcomm-plain+json`) con `attachments[].data.base64`:

```bash
PDF_B64=$(base64 < "$PDF_FILE" | tr -d '\n')

curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d "{
    \"jti\":\"msg-$THID\",
    \"thid\":\"$THID\",
    \"type\":\"https://globaldatacare.es/didcomm/ica/terms/verify-request/v1\",
    \"attachments\":[
      {
        \"id\":\"pdf-1\",
        \"media_type\":\"application/pdf\",
        \"data\":{\"base64\":\"$PDF_B64\"}
      }
    ]
  }"
```

Si usas otro `Content-Type` en `_verify`, la API responde `415 Unsupported Media Type`.

Polling (`_verify-response`):

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify-response?thid=$THID" | jq .
```

`Location` en respuestas `202` no incluye `thid`; envialo en query o body al hacer polling.

Activar/rotar clave de firma ICA (`_activate`) en caliente:

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"activate-msg-001",
    "thid":"activate-signing-001",
    "type":"https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1",
    "body":{
      "key":{
        "kid":"ica-es384-20260305",
        "alg":"ES384",
        "privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
        "certificateChainPem":[
          "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
        ]
      }
    }
  }'
```

Activar varias claves en una sola request (`body.data[]`), por ejemplo `ES384` + `ES256K`:

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"activate-msg-002",
    "thid":"activate-signing-002",
    "type":"https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1",
    "body":{
      "data":[
        {
          "key":{
            "kid":"ica-es384-20260305",
            "alg":"ES384",
            "privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
          }
        },
        {
          "key":{
            "kid":"ica-es256k-20260305",
            "alg":"ES256K",
            "privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
          }
        }
      ]
    }
  }'
```

Compatibilidad: `body.key` (clave unica) sigue soportado.

Payload real de pruebas (claves deterministas, no productivas) para Swagger y `curl`:

```bash
npm run api:example:activate > /tmp/ica_activate_example.json
jq '.didcommPayload' /tmp/ica_activate_example.json > /tmp/ica_activate_payload.json

curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate" \
  -H "Content-Type: application/didcomm-plain+json" \
  --data @/tmp/ica_activate_payload.json
```

Para Swagger, pega en el body el JSON de `didcommPayload`:

```bash
jq '.didcommPayload' /tmp/ica_activate_example.json
```

Comprobacion rapida de schema OpenAPI (`_activate` con `body.key` y `body.data[]`):

```bash
curl -sS "$BASE/openapi.json" | jq '.paths["/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate"].post.requestBody.content["application/didcomm-plain+json"].schema.properties.body.properties | keys'
```

Polling de activacion:

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate-response?thid=activate-signing-001" | jq .
```

Agregar evidencia adicional (`_add`) para una entidad/miembro:

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/evidence/official-registry/_add" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"evidence-add-msg-001",
    "thid":"evidence-add-001",
    "type":"https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1",
    "body":{
      "issuedCredentialRecordId":"urn:uuid:issued-credential-record-001",
      "operatorDid":"did:web:ica.example.com#employee-01",
      "evidence":{
        "type":"official-registry",
        "registryId":"COL-0001",
        "checkedAt":"2026-03-06T10:00:00.000Z",
        "proof":{
          "type":"OperatorApprovalProof",
          "signature":"<jws>"
        }
      }
    }
  }'
```

Polling de `_add`:

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/evidence/official-registry/_add-response?thid=evidence-add-001" | jq .
```

Emitir/persistir credencial (`_issue`) con evidencia acumulada:

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_issue" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"credential-issue-msg-001",
    "thid":"credential-issue-001",
    "type":"https://globaldatacare.es/didcomm/ica/network/credentials/issue-request/v1",
    "body":{
      "credential":{
        "id":"urn:uuid:vc-member-001",
        "type":["VerifiableCredential","MemberCredential"],
        "issuer":"did:web:ica.example.com",
        "credentialSubject":{
          "id":"mailto:member@example.org",
          "memberNumber":"COL-0001"
        }
      },
      "evidence":[
        {
          "type":"qualification",
          "checkedAt":"2026-03-06T10:01:00.000Z",
          "proof":{"type":"OperatorApprovalProof","signature":"<jws>"}
        }
      ]
    }
  }'
```

Polling de `_issue`:

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_issue-response?thid=credential-issue-001" | jq .
```

Consultar estado de una credencial (`_status`):

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_status" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"credential-status-msg-001",
    "thid":"credential-status-001",
    "type":"https://globaldatacare.es/didcomm/ica/network/credentials/status-request/v1",
    "body":{
      "credentialId":"urn:uuid:vc-member-001"
    }
  }'
```

Polling de `_status`:

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_status-response?thid=credential-status-001" | jq .
```

Revocar una credencial (`_revoke`):

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_revoke" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"credential-revoke-msg-001",
    "thid":"credential-revoke-001",
    "type":"https://globaldatacare.es/didcomm/ica/network/credentials/revoke-request/v1",
    "body":{
      "credentialId":"urn:uuid:vc-member-001",
      "reason":"membership-terminated",
      "revokedBy":"did:web:ica.example.com#employee-02"
    }
  }'
```

Polling de `_revoke`:

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_revoke-response?thid=credential-revoke-001" | jq .
```

Proceso de polling:

- repetir `POST` a `.../_verify-response` con el mismo `thid`.
- si responde `202`, esperar `Retry-After` (o 5s) y consultar de nuevo.
- terminar cuando la respuesta deje de ser `202`.

## Contrato de respuesta final (DIDComm)

Cuando el job termina (`200`) o hay error temprano (`4xx/5xx`), la API devuelve mensaje DIDComm con `type=application/bundle-api+json`:

```json
{
  "jti": "urn:uuid:...",
  "iss": "did:web:ica.example.com",
  "aud": "did:web:ica.example.com",
  "thid": "verify-terms-001",
  "type": "application/bundle-api+json",
  "body": {
    "resourceType": "Bundle",
    "type": "batch-response",
    "result": {},
    "issues": {
      "resourceType": "OperationOutcome",
      "issue": []
    },
    "total": 0,
    "data": []
  }
}
```

No hay `outcome` fuera de `body`.
En errores tempranos, `thid` y/o `aud` pueden venir como `""` si no estaban disponibles en la request.

Cuando la verificacion termina en `ok`, el PDF firmado puede persistirse en storage privado para auditoria y la evidencia `document.attachments.url` pasa a ser una referencia externa (por defecto `urn:uuid:{objectId}`).
Ademas, las VCs emitidas y sus evidencias se persisten en colecciones de backend (`issued_credentials`, `evidence_records`) usando adaptador `mem` o `firestore`.

Cuando falla por revocacion, el detalle tecnico va en `body.issues.issue[]` (y tambien en `body.data[0].response.outcome.issue[]`) para mantener formato `OperationOutcome`:

- `code=transient` + `diagnostics` con `status=http_error`: se pudo conectar pero HTTP no fue `2xx` (`httpStatus` presente).
- `code=timeout` + `diagnostics` con `status=timeout`: timeout de red al descargar CRL.
- `code=structure` + `diagnostics` con `status=parse_error`: CRL descargada pero OpenSSL no pudo parsearla.
- `code=processing|security|informational` para resultado de fase `verify`.

## Endpoints

Discovery:

- `GET /`
- `GET /openapi.json`
- `GET /api-docs`
- `GET /.well-known/did.json`
- `GET /did.json`

Verificacion:

- `POST /ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response`
- `POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate` (stub)
- `POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate-response` (stub)
- `POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate` (stub)
- `POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate-response` (stub)

Restricciones de ruta:

- `sector`: `animal-care` o `health-care`
- `resourceType` produccion: `yyyyddmmhhmm` (12 digitos)
- `resourceType` pruebas: `test-yyyyddmmhhmm` (requiere `ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX=true`)
- opcional: restringir versiones activas con `ICA_TERMS_ACTIVE_RESOURCE_TYPES` (CSV)
- `section`: `terms`
- `format`: `pdf`
- `evidenceType`: clasificador libre en ruta para `_add` (ej: `address`, `official-registry`, `qualification`)
- `credentialType`: clasificador libre en ruta para `_issue`, `_status` y `_revoke` (ej: `member-onboarding`)

Nota de diseno ICA:

- El contrato OpenAPI de esta ICA publica rutas fijadas a `/ica/...` para evitar confusion de multitenancy.
- Internamente el parser conserva `tenantId` por compatibilidad de codigo, y debe permanecer en `ica` en despliegue monotenant.
- Las rutas `network/evidence` y `network/credentials` representan operaciones de la ICA sobre organizaciones/miembros de la red (no autoemision para la propia ICA).
- `_status` y `_revoke` en `network/credentials` actuan como punto central de consulta/actualizacion de estado de revocacion para credenciales emitidas por la ICA.
- La organizacion firmante se extrae del certificado embebido del PDF (por ejemplo `legalName`/`taxID`), independiente de la URL.
- Los miembros/colegiados no son `tenantId`; son sujetos de credenciales/evidencias en colecciones (`issued_credentials`, `evidence_records`).

## Scripts npm

- `npm run dev`: arranque normal (sin watch).
- `npm run api:dev`: arranque con watch en `./src`.
- `npm run api:start`: arranque normal (alias historico).
- `npm run api:example:activate`: genera payload DIDComm con claves deterministas para pruebas de `_activate`.
- `npm run test`: tests de contrato API.
- `npm run typecheck`: validacion TypeScript estricta.

## Docker y GKE

Se incluyen artefactos de despliegue en:

- `Dockerfile`
- `.dockerignore`
- `deploy/k8s/configmap.yaml`
- `deploy/k8s/secret.example.yaml`
- `deploy/k8s/deployment.yaml`
- `deploy/k8s/service.yaml`

Guia paso a paso (build local, push a Artifact Registry y deploy en GKE):

- [`deploy/k8s/README.md`](./deploy/k8s/README.md)

## Configuracion de entorno (resumen)

Servidor:

- `ICA_API_HOST` (default `0.0.0.0`)
- `ICA_API_PORT` (default `3310`)
- `ICA_LOCAL_TENANT_ID` (recomendado en ICA monotenant: `ica`)
- `ICA_DIDCOMM_ISSUER_DID` (opcional; fuerza `iss` DIDComm)
- `ICA_DIDCOMM_AUDIENCE_DID` (opcional; fuerza `aud` DIDComm)
- `ICA_DID_DOCUMENT_JSON` (opcional; documento DID completo servido por la API)
- `ICA_DID_SERVICE_ENDPOINT` (opcional; `serviceEndpoint` en DID generado)
- `ICA_VC_SIGNING_PRIVATE_KEY_PEM` (opcional; clave privada para firmar VCs en produccion)
- `ICA_VC_SIGNING_ALG` (opcional; `ES384` | `ES256K` | `RS256` | `PS256` | `EdDSA`)
- `ICA_VC_SIGNING_KEY_ID` (opcional; default `key-1`, usado en `verificationMethod`)
- `ICA_VC_SIGNING_PREFERRED_ALG` (opcional; seleccion de clave activa cuando hay varias)
- `ICA_ACTIVE_SIGNING_KEYS_FILE` (opcional; persistencia de claves activadas por `_activate`)
- `ICA_VC_SIGNING_REQUIRED_FOR_PROD` (opcional; si `true`, falla VC de produccion si falta clave)
- Si no defines `ICA_DIDCOMM_ISSUER_DID`: `iss` se resuelve por `ICA_DID_DOCUMENT_JSON.id`, luego `ICA_EXTERNAL_DOMAIN`, luego `Host` HTTP y finalmente `did:web:localhost%3A<puerto>`.

Validaciones:

- `ICA_VERIFY_STRICT_REVOCATION` (default `true`)
- `ICA_VERIFY_STRICT_TEMPLATE_MATCH` (default `true`)
- `ICA_VERIFY_TEMPLATE_MATCH_MODE`:
  - `strict-bytes` (default): exige igualdad de hash del PDF (o de su `ByteRange` firmado) contra la plantilla.
  - `logical-content`: compara huella de contenido de paginas (`/Contents`) e ignora objetos de firma/annot visual.
- `ICA_VERIFY_DIGEST_ALGORITHM` (default `sha3-384`)

Persistencia de auditoria:

- `ICA_AUDIT_STORAGE_PROVIDER`: `none` | `filesystem` | `gcs`
- `ICA_AUDIT_STORAGE_REQUIRED` (default `true` cuando provider != `none`)
- `ICA_AUDIT_ATTACHMENT_URL_PATTERN` (default `urn:uuid:{objectId}`)
- `ICA_AUDIT_STORAGE_FS_DIR` (solo `filesystem`)
- `ICA_AUDIT_STORAGE_GCS_BUCKET` (requerido en `gcs`)
- `ICA_AUDIT_STORAGE_GCS_PREFIX` (prefijo de objeto, default `ica-audit`)

Persistencia de colecciones de verificacion:

- `ICA_COLLECTIONS_PROVIDER`: `mem` | `firestore` (default `mem`)
- `ICA_COLLECTIONS_REQUIRED`: si `true`, `_verify-response` falla si no se pueden persistir colecciones
- `ICA_COLLECTIONS_FIRESTORE_COLLECTION_PREFIX` (default `ica`)
- `ICA_COLLECTIONS_ISSUED_COLLECTION` (default `issued_credentials`)
- `ICA_COLLECTIONS_EVIDENCE_COLLECTION` (default `evidence_records`)
- `ICA_COLLECTIONS_FIRESTORE_PROJECT_ID` (opcional en `firestore`)
- `ICA_COLLECTIONS_FIRESTORE_DATABASE_ID` (opcional en `firestore`)

Politica de acceso (modo simple actual):

- Bucket/almacen siempre privado (sin acceso publico anonimo).
- La referencia en VC/evidence no expone contenido por si sola.
- La resolucion de acceso debe hacerse por backend ICA con control por membresia (miembros ICA y miembros de la organizacion titular), segun la politica de despliegue.

Trust material FNMT (prioridad):

1. `ICA_FNMT_*_CERT_PEM` (inline)
2. auto-download (`ICA_FNMT_AUTO_DOWNLOAD=true`)
3. fallback a `ICA_FNMT_*_CERT_PATH`

Template source:

- `ICA_TERMS_TEMPLATE_URL_PATTERN`
- placeholders: `{tenantId}`, `{jurisdiction}`, `{jurisdictionLower}`, `{jurisdictionUpper}`, `{sector}`, `{sectorLower}`, `{sectorUpper}`, `{section}`, `{format}`, `{resourceType}`, `{resourceVersion}`
- ejemplo recomendado para repositorio de terminos: `.../terms/dataspace/{sector}/{jurisdictionLower}/{resourceVersion}/terms.pdf`
- `ICA_TERMS_TEMPLATE_USE_TEST_PREFIX`: en dev/test, resuelve `resourceVersion` como `test-<resourceType>` sin cambiar la ruta API
- `ICA_TERMS_TEMPLATE_CACHE_TTL_SECONDS` y `ICA_TERMS_TEMPLATE_CACHE_MAX_ENTRIES`: cache en memoria de plantillas
- `ICA_TERMS_TEMPLATE_PRELOAD_ENABLED`
- `ICA_TERMS_TEMPLATE_PRELOAD_RESOURCE_TYPES` (CSV)
- `ICA_TERMS_TEMPLATE_PRELOAD_SECTORS` (CSV)
- `ICA_TERMS_TEMPLATE_PRELOAD_JURISDICTIONS` (CSV)
- `ICA_TERMS_TEMPLATE_PRELOAD_TENANT_ID`
- `ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX`: habilita rutas `test-...` para pruebas
- `ICA_TERMS_ACTIVE_RESOURCE_TYPES` (CSV): allowlist de versiones activas para retirar/deprecar anteriores
- Nota GitHub Raw: no usar `/tree/` en la URL; usa `/main/...` o `/refs/heads/main/...`
- En `test-*`, la VC incluye `proof.jws` detached intencionadamente invalida para pruebas.
- En version de produccion, la VC solo lleva `proof.jws` valida si `ICA_VC_SIGNING_PRIVATE_KEY_PEM` esta configurada.

Seleccion de adaptador de verificacion:

- `ICA_VERIFY_ADAPTER` (opcional): id preferido del adaptador (actualmente `fnmt-es`).
- `ICA_VERIFY_ADAPTER_STRICT` (default `false`): si `true`, falla si el adaptador preferido no aplica.
- `ICA_FNMT_ADAPTER_JURISDICTIONS` (default `ES`): lista CSV de jurisdicciones para `fnmt-es`.

## Troubleshooting

`FNMT trust anchors preload failed: ENOENT ... fnmt-root.pem`

- Causa: no hay certs por env ni ficheros fallback.
- Solucion: activar auto-download o definir PEM/certs locales.

`EMFILE: too many open files, watch`

- Causa: demasiados watchers del sistema.
- Solucion: usar `npm run dev` (sin watch) o aumentar limites del sistema.

`Endpoint not found` en `/`

- Verifica que ejecutas la version actual.
- Comprueba `GET /openapi.json` y `GET /api-docs`.

## Documentacion detallada

- Guia de integracion API (ES): [`../docs/ica/es/INTEGRATORS_GUIDE.md`](../docs/ica/es/INTEGRATORS_GUIDE.md)
- Runbook CLI/operaciones ICA (ES): [`../docs/ica/es/CLI_OPERATIONS_RUNBOOK.md`](../docs/ica/es/CLI_OPERATIONS_RUNBOOK.md)
# dataspace-ica-ts
