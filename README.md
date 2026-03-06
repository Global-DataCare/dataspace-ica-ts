# dataspace-ica (private)

TypeScript repository with two capabilities:

- ICA CLI operations (onboarding, CSR signing, publication).
- Async ICA API for verification and network lifecycle operations (`_verify`, `_activate`, `_add`, `_issue`, `_status`, `_revoke` + polling).

## Current Status

- `_verify`, `_activate`, `_add` (evidence), `_issue` (credentials), `_status`, and `_revoke` are implemented with async pattern (`202 + Location` + polling).
- Business responses and early `4xx/5xx` errors are returned as DIDComm plaintext (`jti/iss/aud/thid/type/body`).
- `body` is a `Bundle` (`batch-response`) with `issues`, `data[]`, and optional `result`.

## Quick Start (5 minutes)

Requirements:

- Node.js 22+
- OpenSSL available in `PATH`

Install:

```bash
npm install
```

Run locally:

```bash
cp .env.local.example .env.local
npm run dev
```

Quick checks:

```bash
curl -sS http://localhost:3310/ | jq .
curl -sS http://localhost:3310/openapi.json | jq '.openapi'
curl -sS http://localhost:3310/.well-known/did.json | jq '.id'
curl -i http://localhost:3310/api-docs
```

Use `http://localhost:3310/...` in browser (not `0.0.0.0`).

## API Flow With curl

Test variables:

```bash
BASE="http://localhost:3310"
TENANT="ica"
JUR="ES"
SECTOR="animal-care"
VERSION="202603051133"          # production-style version
# VERSION="test-202603051133"   # test version (requires ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX=true)
THID="verify-terms-001"
PDF_FILE="$HOME/Documents/TEST-A4-signed-fnmt.pdf"
```

### 1) Submit verification job (`_verify`)

`_verify` accepts only DIDComm plaintext (`application/didcomm-plain+json`) with PDF in `attachments[].data.base64`.

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

If `Content-Type` is not `application/didcomm-plain+json`, API returns `415 Unsupported Media Type`.

### 2) Poll verification result (`_verify-response`)

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/terms/pdf/$VERSION/_verify-response?thid=$THID" | jq .
```

`Location` returned by `202` does not include `thid`; send `thid` in query or JSON body on every poll.

Successful terminal response example (`POST /ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response`):

```json
{
  "jti": "urn:uuid:9cc3f9fb-9c3f-4e10-a2d4-2ce5c64f0a2d",
  "iss": "did:web:localhost%3A3310",
  "aud": "did:web:localhost%3A3310",
  "thid": "verify-terms-001",
  "type": "application/bundle-api+json",
  "body": {
    "resourceType": "Bundle",
    "type": "batch-response",
    "total": 2,
    "result": {
      "ok": true,
      "templateMatch": true,
      "signatureValid": true,
      "chainValid": true,
      "revocationStatus": "good"
    },
    "issues": {
      "resourceType": "OperationOutcome",
      "issue": [
        {
          "severity": "information",
          "code": "informational",
          "diagnostics": "Verification completed."
        }
      ]
    },
    "data": [
      {
        "type": "Organization-verification-v1.0",
        "response": {
          "status": "200",
          "outcome": {
            "resourceType": "OperationOutcome",
            "issue": [
              {
                "severity": "information",
                "code": "informational",
                "diagnostics": "Organization credential extracted from verified document."
              }
            ]
          }
        },
        "resource": {
          "type": ["VerifiableCredential", "OrganizationCredential"],
          "credentialSubject": {
            "@type": "Organization",
            "legalName": "Acme Health SL",
            "taxID": "VATES-A12345678"
          },
          "evidence": [
            {
              "type": "electronic_signature",
              "signature_type": "pades"
            },
            {
              "type": "document",
              "method": "eid",
              "attachments": {
                "digest": {
                  "alg": "sha3-384",
                  "value": "<base64>"
                }
              }
            }
          ]
        }
      },
      {
        "type": "LegalRepresentative-verification-v1.0",
        "response": {
          "status": "200",
          "outcome": {
            "resourceType": "OperationOutcome",
            "issue": [
              {
                "severity": "information",
                "code": "informational",
                "diagnostics": "Legal representative credential extracted from verified document."
              }
            ]
          }
        },
        "resource": {
          "type": ["VerifiableCredential", "PersonCredential", "LegalRepresentativeCredential"],
          "credentialSubject": {
            "@type": "Person",
            "roleName": "legal-representative",
            "memberOf": {
              "@type": "Organization",
              "legalName": "Acme Health SL",
              "taxID": "VATES-A12345678"
            }
          },
          "evidence": [
            {
              "type": "electronic_signature",
              "signature_type": "pades"
            },
            {
              "type": "document",
              "method": "eid",
              "attachments": {
                "digest": {
                  "alg": "sha3-384",
                  "value": "<base64>"
                }
              }
            }
          ]
        }
      }
    ]
  }
}
```

### 3) Activate credential signing keys (`_activate`)

Single key (`body.key`):

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

Multiple keys (`body.data[]`):

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

Backward compatibility: `body.key` remains supported.

Deterministic test payload for Swagger/curl:

```bash
npm run api:example:activate > /tmp/ica_activate_example.json
jq '.didcommPayload' /tmp/ica_activate_example.json > /tmp/ica_activate_payload.json

curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate" \
  -H "Content-Type: application/didcomm-plain+json" \
  --data @/tmp/ica_activate_payload.json
```

OpenAPI schema check (`_activate` exposes both `body.key` and `body.data[]`):

```bash
curl -sS "$BASE/openapi.json" | jq '.paths["/{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate"].post.requestBody.content["application/didcomm-plain+json"].schema.properties.body.properties | keys'
```

Activation polling:

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate-response?thid=activate-signing-001" | jq .
```

### 4) Add evidence (`_add`)

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
      "operatorDid":"did:web:localhost%3A3310#employee-01",
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

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/evidence/official-registry/_add-response?thid=evidence-add-001" | jq .
```

### 5) Issue credential (`_issue`)

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
        "issuer":"did:web:localhost%3A3310",
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

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_issue-response?thid=credential-issue-001" | jq .
```

### 6) Credential status (`_status`)

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

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_status-response?thid=credential-status-001" | jq .
```

### 7) Revoke credential (`_revoke`)

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
      "revokedBy":"did:web:localhost%3A3310#employee-02"
    }
  }'
```

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_revoke-response?thid=credential-revoke-001" | jq .
```

## Polling Behavior

- Repeat `POST` on the corresponding `.../_*-response` endpoint with the same `thid`.
- If the response is `202`, wait `Retry-After` (or 5 seconds) and poll again.
- Terminal state is any non-`202` response.

## DIDComm Response Contract

Final responses (`200`) and early errors (`4xx/5xx`) are always DIDComm plaintext with:

- `type: "application/bundle-api+json"`
- `body.resourceType: "Bundle"`
- `body.type: "batch-response"`
- `body.issues` in FHIR `OperationOutcome` format

Example envelope:

```json
{
  "jti": "urn:uuid:...",
  "iss": "did:web:localhost%3A3310",
  "aud": "did:web:localhost%3A3310",
  "thid": "verify-terms-001",
  "type": "application/bundle-api+json",
  "body": {
    "resourceType": "Bundle",
    "type": "batch-response",
    "total": 0,
    "data": [],
    "issues": {
      "resourceType": "OperationOutcome",
      "issue": []
    }
  }
}
```

Notes:

- No top-level `outcome` exists outside `body`.
- In early errors, `thid` and/or `aud` can be empty (`""`) if missing in request context.
- On successful verification, signed PDF can be persisted as private audit evidence and referenced as external attachment (`document.attachments.url`).
- Issued VCs and evidences are persisted through collections adapters (`mem` or `firestore`).

## Endpoint Summary

Discovery:

- `GET /`
- `GET /openapi.json`
- `GET /api-docs`
- `GET /.well-known/did.json`
- `GET /did.json`

Verification and keys:

- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate` (stub)
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate-response` (stub)
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate` (stub)
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate-response` (stub)

Network evidence and credentials:

- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response`

Route constraints:

- `sector`: `animal-care` or `health-care`
- `resourceType` (prod): `yyyyddmmhhmm` (12 digits)
- `resourceType` (test): `test-yyyyddmmhhmm` (requires `ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX=true`)
- `evidenceType`: free classifier for `_add` (e.g., `address`, `official-registry`, `qualification`)
- `credentialType`: free classifier for `_issue`, `_status`, `_revoke` (e.g., `member-onboarding`)

## npm Scripts

- `npm run dev`: normal start (no watch)
- `npm run api:dev`: watch mode (`./src`)
- `npm run api:start`: normal start alias
- `npm run api:example:activate`: generates deterministic DIDComm payload for `_activate`
- `npm run test`: API contract tests
- `npm run typecheck`: strict TypeScript checks

## Docker and GKE

Deployment artifacts are under:

- `Dockerfile`
- `.dockerignore`
- `deploy/k8s/configmap.yaml`
- `deploy/k8s/secret.example.yaml`
- `deploy/k8s/deployment.yaml`
- `deploy/k8s/service.yaml`

Step-by-step guide:

- [`deploy/k8s/README.md`](./deploy/k8s/README.md)

## Environment Configuration (summary)

Server and DID:

- `ICA_API_HOST` (default `0.0.0.0`)
- `ICA_API_PORT` (default `3310`)
- `ICA_LOCAL_TENANT_ID` (recommended in ICA single-tenant mode: `ica`)
- `ICA_DIDCOMM_ISSUER_DID` (optional)
- `ICA_DIDCOMM_AUDIENCE_DID` (optional)
- `ICA_DID_DOCUMENT_JSON` (optional)
- `ICA_DID_SERVICE_ENDPOINT` (optional)

VC signing:

- `ICA_VC_SIGNING_PRIVATE_KEY_PEM` (optional)
- `ICA_VC_SIGNING_ALG` (`ES384` | `ES256K` | `RS256` | `PS256` | `EdDSA`)
- `ICA_VC_SIGNING_KEY_ID`
- `ICA_VC_SIGNING_PREFERRED_ALG`
- `ICA_ACTIVE_SIGNING_KEYS_FILE`
- `ICA_VC_SIGNING_REQUIRED_FOR_PROD`

Verification behavior:

- `ICA_VERIFY_STRICT_REVOCATION` (default `true`)
- `ICA_VERIFY_STRICT_TEMPLATE_MATCH` (default `true`)
- `ICA_VERIFY_TEMPLATE_MATCH_MODE` (`strict-bytes` | `logical-content`)
- `ICA_VERIFY_DIGEST_ALGORITHM` (default `sha3-384`)

Audit document persistence:

- `ICA_AUDIT_STORAGE_PROVIDER` (`none` | `filesystem` | `gcs`)
- `ICA_AUDIT_STORAGE_REQUIRED`
- `ICA_AUDIT_ATTACHMENT_URL_PATTERN`
- `ICA_AUDIT_STORAGE_FS_DIR`
- `ICA_AUDIT_STORAGE_GCS_BUCKET`
- `ICA_AUDIT_STORAGE_GCS_PREFIX`

Verification collections persistence:

- `ICA_COLLECTIONS_PROVIDER` (`mem` | `firestore`, default `mem`)
- `ICA_COLLECTIONS_REQUIRED`
- `ICA_COLLECTIONS_FIRESTORE_COLLECTION_PREFIX`
- `ICA_COLLECTIONS_ISSUED_COLLECTION`
- `ICA_COLLECTIONS_EVIDENCE_COLLECTION`
- `ICA_COLLECTIONS_FIRESTORE_PROJECT_ID`
- `ICA_COLLECTIONS_FIRESTORE_DATABASE_ID`

Template source:

- `ICA_TERMS_TEMPLATE_URL_PATTERN`
- placeholders: `{tenantId}`, `{jurisdiction}`, `{jurisdictionLower}`, `{jurisdictionUpper}`, `{sector}`, `{sectorLower}`, `{sectorUpper}`, `{section}`, `{format}`, `{resourceType}`, `{resourceVersion}`
- recommended pattern: `.../terms/dataspace/{sector}/{jurisdictionLower}/{resourceVersion}/terms.pdf`
- `ICA_TERMS_TEMPLATE_USE_TEST_PREFIX`
- `ICA_TERMS_TEMPLATE_CACHE_TTL_SECONDS`
- `ICA_TERMS_TEMPLATE_CACHE_MAX_ENTRIES`
- `ICA_TERMS_TEMPLATE_PRELOAD_ENABLED`
- `ICA_TERMS_TEMPLATE_PRELOAD_RESOURCE_TYPES`
- `ICA_TERMS_TEMPLATE_PRELOAD_SECTORS`
- `ICA_TERMS_TEMPLATE_PRELOAD_JURISDICTIONS`
- `ICA_TERMS_TEMPLATE_PRELOAD_TENANT_ID`
- `ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX`
- `ICA_TERMS_ACTIVE_RESOURCE_TYPES`

FNMT trust material priority:

1. inline PEM: `ICA_FNMT_*_CERT_PEM`
2. auto-download: `ICA_FNMT_AUTO_DOWNLOAD=true`
3. file-path fallback: `ICA_FNMT_*_CERT_PATH`

## Troubleshooting

`FNMT trust anchors preload failed: ENOENT ... fnmt-root.pem`

- Cause: no certs provided via env and file fallback not present.
- Fix: enable auto-download or configure PEM/cert files.

`EMFILE: too many open files, watch`

- Cause: OS watcher limit.
- Fix: use `npm run dev` (no watch) or increase system limits.

`Endpoint not found` at `/`

- Verify you are running the latest process.
- Check `GET /openapi.json` and `GET /api-docs`.
