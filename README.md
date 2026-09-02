# dataspace-ica

TypeScript service for:

- ICA CLI operations: onboarding, CSR signing, publication
- async ICA API: `_verify`, `_activate`, `_add`, `_upsert`, `_issue`, `_status`, `_revoke` and polling

This `README` is the entry guide. Detailed documentation now lives under [`docs/`](./docs/README.md).

## Start Here

- Introduction and documentation map: [`docs/README.md`](./docs/README.md)
- Product overview: [`docs/01-introduction/01-overview.md`](./docs/01-introduction/01-overview.md)
- Local quickstart: [`docs/02-setup-and-run/01-local-quickstart.md`](./docs/02-setup-and-run/01-local-quickstart.md)
- Configuration guide: [`docs/02-setup-and-run/02-configuration.md`](./docs/02-setup-and-run/02-configuration.md)
- Key endpoints: [`docs/03-api-and-flows/01-key-endpoints.md`](./docs/03-api-and-flows/01-key-endpoints.md)
- Core flows: [`docs/03-api-and-flows/02-core-flows.md`](./docs/03-api-and-flows/02-core-flows.md)
- Host CSR enrollment for production: [`docs/03-api-and-flows/03-host-csr-enrollment.md`](./docs/03-api-and-flows/03-host-csr-enrollment.md)
- Examples, fixtures, and tests: [`docs/04-examples-and-tests/01-examples-fixtures-and-tests.md`](./docs/04-examples-and-tests/01-examples-fixtures-and-tests.md)
- Operations and deployment: [`docs/05-operations-and-deployment/01-gke-and-security.md`](./docs/05-operations-and-deployment/01-gke-and-security.md)

## What The Service Does

- Verifies signed Terms PDFs through `_verify`
- Activates credential-signing keys through `_activate`
- Publishes DID/JWKS/discovery artifacts
- Manages evidence, issuance, status, revocation, and delegated policy flows
- Supports CLI workflows for root/ICA bootstrap, CSR signing, and DCAT publication

## Interop Baseline

Across the main API surface:

- transport is DIDComm plaintext for the current baseline
- business payload is a `Bundle`
- `body.data[]` is the authoritative business result
- `body.issues` carries `OperationOutcome`-style errors and warnings
- business resources use `schema.org` semantics for `Organization` and `Person`

## Quickstart

Requirements:

- Node.js 22+
- OpenSSL in `PATH`

Recommended shared workspace:

- keep related repos under `~/GITS/gdc-workspace/`
- keep shared PDF fixtures under `~/GITS/gdc-workspace/examples/`
- current local tests and docs assume paths like:
  - `~/GITS/gdc-workspace/dataspace-ica-ts`
  - `~/GITS/gdc-workspace/ica-client-sdk-ts`
  - `~/GITS/gdc-workspace/gdc-common-utils-ts`
  - `~/GITS/gdc-workspace/examples/<example-pdf>.pdf`

Suggested layout:

```text
~/GITS/gdc-workspace/
  dataspace-ica-ts/
  ica-client-sdk-ts/
  gdc-common-utils-ts/
  examples/
    <example-pdf-1>.pdf
    <example-pdf-2>.pdf
```

Install and run:

```bash
npm install
cp env.example .env.deploy.dev
echo 'ICA_SUPPORTED_JURISDICTIONS=ES' >> .env.deploy.dev
echo 'ICA_SUPPORTED_SECTORS=animal-care' >> .env.deploy.dev
npm run dev
```

Useful commands:

```bash
npm run dev
npm run api:local
npm run api:export
npm run api:example:activate
npm run test
npm run typecheck
```

## Key Endpoints

- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify-response`

`networkKind` is part of the signed credential context:

- `test`: test signature, no Fabric;
- `local-network`: signature plus local Fabric anchoring;
- `test-network`: externally chained staging signature plus Kubernetes Fabric;
- `network`: externally chained production signature plus production Fabric.

The old `terms` path segment remains an alias of `test`.
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response`
- `GET /.well-known/did.json`
- `GET /.well-known/jwks.json`
- `GET /openapi.json`
- `GET /api-docs`

## Typical Developer Path

1. Run the local server and confirm `/.well-known/did.json` and `/openapi.json`.
2. Read the key endpoint and flow guides under `docs/03-api-and-flows/`.
3. Reuse `docs/examples/` fixtures and `npm run api:example:activate`.
4. Read the `api.*.test.ts` files in [`test/`](./test) as executable documentation.
5. Use the deeper documents in `docs/` only for the specific subsystem you are changing.

## Documentation Layout

The curated documentation tree is now organized as numbered folders:

- `docs/01-introduction`
- `docs/02-setup-and-run`
- `docs/03-api-and-flows`
- `docs/04-examples-and-tests`
- `docs/05-operations-and-deployment`
- `docs/06-architecture-and-reference`

Legacy deep-dive documents still exist in `docs/` root and are referenced from the numbered guides while the structure is being normalized.

## Detailed Reference

The rest of this `README` keeps the detailed API reference and curl material for backward compatibility. New explanatory material should go under `docs/`, not here.

Quick checks:

```bash
curl -sS http://localhost:3310/ | jq .
curl -sS http://localhost:3310/openapi.json | jq '.openapi'
curl -sS http://localhost:3310/.well-known/did.json | jq '.id'
curl -sS http://localhost:3310/ | jq '.controllerDid'
curl -sS http://localhost:3310/ | jq '.controllerDidPath'
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
# VERSION="test-202603051133"   # test version (requires ICA_ENABLE_TEST_TERMS_PREFIX=true)
THID="verify-terms-001"
PDF_FILE="$HOME/Documents/TEST-A4-signed-fnmt.pdf"
```

Swagger UI tip:

- For submit actions (`_verify`, `_activate`, `_add`, `_upsert`, `_issue`, `_status`, `_revoke`), set `thid: "thid-auto"` and/or `jti: "req-auto"` to auto-generate timestamped ids on send:
  - `thid-yyyymmddhhmmss`
  - `req-yyyymmddhhmmss`
- `_*-response` polling endpoints are not auto-modified.
- In Swagger UI for `_verify`, direct-link normalization is applied to known share URLs:
  - Dropbox: `dl=0` -> `dl=1` (recommended and tested)
- Outside Swagger (curl/scripts), use a direct PDF URL.
- Manual Dropbox conversion:
  - From: `https://www.dropbox.com/s/<id>/<file>.pdf?dl=0`
  - To: `https://www.dropbox.com/s/<id>/<file>.pdf?dl=1`

Deployment tip:

- deploy a named environment: `./cloud_deploy.sh <environment> --yes`
- full dataspace bootstrap + deploy (private script): `./scripts/bootstrap-<dataspace>.private.sh`
- generic public template: `./scripts/bootstrap-dataspace.template.sh`
- protected legacy staging: `./cloud_deploy.sh staging --yes --allow-staging`
- `staging` is blocked by default to reduce accidental deploys

### 1) Submit verification job (`_verify`)

`_verify` accepts DIDComm plaintext (`application/didcomm-plain+json`) with:
- the signed PDF in `attachments[].data.base64` or `attachments[].data.links`
- optional DIDComm communication metadata in `meta.jws` / `meta.jwe`
- preferred controller binding key in `body.data[].resource.controller.publicKeyJwk`
- legacy fallback controller binding key in `meta.jws.protected.jwk`
- optional organization public key attachment as `application/jwk+json`

Key separation:

- `meta.jws` / `meta.jwe` protect the communication channel and may belong to a
  device profile, confidential app, or BFF
- `body.data[].resource.controller.publicKeyJwk` is the controller
  operation-signing/binding key that ICA projects into
  `credentialSubject.hasCredential.material`

If the organization JWK attachment is omitted, ICA autogenerates an `ES384` organization credential-signing keypair and returns the public/private JWK outside `body.data[].resource` in `_verify-response`.

```bash
PDF_B64=$(base64 < "$PDF_FILE" | tr -d '\n')
VERIFY_PAYLOAD=$(cat <<JSON
{
  "jti": "msg-$THID",
  "thid": "$THID",
  "type": "application/bundle-api+json",
  "attachments": [
    {
      "id": "pdf-1",
      "media_type": "application/pdf",
      "data": {
        "base64": "$PDF_B64"
      }
    },
    {
      "id": "org-jwk-1",
      "media_type": "application/jwk+json",
      "filename": "organization-public-key.jwk.json",
      "data": {
        "json": {
          "kty": "EC",
          "crv": "P-384",
          "x": "<org-x>",
          "y": "<org-y>"
        }
      }
    }
  ],
  "meta": {
    "jws": {
      "protected": {
        "alg": "ES384",
        "kid": "controller-es384-001",
        "jwk": {
          "kty": "EC",
          "crv": "P-384",
          "x": "<controller-x>",
          "y": "<controller-y>"
        }
      }
    }
  }
}
JSON
)

curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/test/pdf/$VERSION/_verify" \
  -H "Content-Type: application/didcomm-plain+json" \
  --data "$VERIFY_PAYLOAD"
```

If `Content-Type` is not `application/didcomm-plain+json`, API returns `415 Unsupported Media Type`.

### 2) Poll verification result (`_verify-response`)

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/test/pdf/$VERSION/_verify-response?thid=$THID" | jq .
```

`Location` returned by `202` does not include `thid`; send `thid` in query or JSON body on every poll.

Successful terminal response example (`POST /ica/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify-response`):

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

For verification polling, consume `body.data[].resource` (including `resource.evidence`) as authoritative business output.

When the verified request supplies both a controller actor identity and its
public actor JWK, the bundle also contains one
`OrganizationController-verification-v1.0` entry. Its signed resource has
types `VerifiableCredential`, `ServiceCredential` and
`ServiceControllerCredential`; the tenant Service is the subject, while
`credentialSubject.owner.sameAs` identifies that controller and
`owner.hasCredential.material` carries the RFC 9278 JWK-thumbprint URN. This
entry is separate from `LegalRepresentativeCredential`, including when both
roles belong to the same person.

The JWK always belongs to the actor that submitted it. In the legacy legal
registration flow this is normally the legal representative. If the signed PDF
names a different technical controller but the request does not provide a
matching `controllerSameAs` for that actor, ICA emits only the organization and
legal-representative credentials. It retains the controller email only as a
hashed pending designation. The technical controller later obtains its own
`ServiceControllerCredential` by binding its own JWK through the sector portal
and completing DCR. Re-verifying with an older payload that omits the controller
field preserves the earlier signed pending designation.

The representative and controller occupations remain separate from controller
authority. Unless the signed PDF exposes explicit four-digit ISCO-08 fields,
ICA emits `ISCO-08|1120` for the legal representative and `ISCO-08|1330` for
the technical controller. The controller VC additionally carries the bare
HL7-derived authority code `RESPRSN` in `credentialSubject.owner.additionalType`.
The optional AcroForm field names are
`person.hasOccupation.occupationalCategory` and
`organization.contactPoint.hasOccupation.occupationalCategory`; each accepts one
four-digit ISCO-08 code. They can be omitted from the current test form to use
the defaults above.

### 3) Activate credential signing keys (`_activate`)

`_activate` requires controller authorization signature in `body.signature` by default (`DISABLE_CONTROLLER_DIDCOMM_PROOF=false`):

- `signature.data`: detached compact JWS (`<protected>..<signature>`) or base64 of that compact value
- JWS `kid` must match controller `kid` and at least one `body.data[].key.kid`
- `signature.who.reference`: controller DID verification method (`did:web:...#kid`)
- Signature is verified over canonical request `body` excluding `signature` and, if `body.resourceType="Bundle"`, also excluding root `id` and `meta`
- each `body.data[].key` must include CA chain (`x5c` or `certificateChainPem`) unless `DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION=true`

Keep transport as `application/didcomm-plain+json` over TLS and protect private keys via secret manager/KMS/HSM.

Single key (always as `body.data[]`):

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"activate-msg-001",
    "thid":"activate-signing-001",
    "type":"application/bundle-api+json",
    "body":{
      "signature":{
        "sigFormat":"application/jose",
        "who":{"reference":"did:web:ica.example.com#ica-es384-20260305"},
        "data":"<detached-compact-jws-or-base64>"
      },
      "data":[
        {
          "key":{
            "kid":"ica-es384-20260305",
            "alg":"ES384",
            "privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
            "certificateChainPem":[
              "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
            ]
          }
        }
      ]
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
    "type":"application/bundle-api+json",
    "body":{
      "signature":{
        "sigFormat":"application/jose",
        "who":{"reference":"did:web:ica.example.com#ica-es384-20260305"},
        "data":"<detached-compact-jws-or-base64>"
      },
      "data":[
        {
          "key":{
            "kid":"ica-es384-20260305",
            "alg":"ES384",
            "privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
            "certificateChainPem":[
              "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
            ]
          }
        },
        {
          "key":{
            "kid":"ica-es256k-20260305",
            "alg":"ES256K",
            "privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
            "certificateChainPem":[
              "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
            ]
          }
        }
      ]
    }
  }'
```

Deterministic test payload for Swagger/curl:

```bash
npm run api:example:activate > /tmp/ica_activate_example.json
jq '.didcommPayload' /tmp/ica_activate_example.json > /tmp/ica_activate_payload.json

curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate" \
  -H "Content-Type: application/didcomm-plain+json" \
  --data @/tmp/ica_activate_payload.json
```

OpenAPI schema check (`_activate` requires `body.data[]`):

```bash
curl -sS "$BASE/openapi.json" | jq '.paths["/{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate"].post.requestBody.content["application/didcomm-plain+json"].schema.properties.body.properties | keys'
```

Activation polling:

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/entity/keys/credentials/_activate-response?thid=activate-signing-001" | jq .
```

### 4) Add evidence (`_add`)

`_add` validates OIDC4IDA evidence objects. Canonical mode is `body.data[]` (one or many entries), and each `data[i].resource` can be either:
- direct OIDC4IDA evidence object, or
- wrapper with `verified_claims.verification.evidence[]` plus optional `verified_claims.claims` (additional claims like registry/professional IDs).

Also supported: DIDComm `attachments[]` with `application/vc+jwt` (Pontus-X style).  
Those vc+jwt attachments are verified using `ICA_EVIDENCE_VC_ISSUERS_LIST` (trusted issuer DID/URL list that resolves DID document/JWKS, plus optional x509 chain checks) and ingested as normalized `electronic_record` evidence.

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/evidence/official-registry/_add" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"evidence-add-msg-001",
    "thid":"evidence-add-001",
    "type":"application/bundle-api+json",
    "body":{
      "data":[
        {
          "issuedCredentialRecordId":"urn:uuid:issued-credential-record-001",
          "operatorDid":"did:web:localhost%3A3310#employee-01",
          "resource":{
            "verified_claims":{
              "verification":{
                "trust_framework":null,
                "time":"2026-03-06T10:00:00.000Z",
                "evidence":[
                  {
                    "type":"electronic_record",
                    "time":"2026-03-06T10:00:00.000Z",
                    "verifier":{"organization":"did:web:localhost%3A3310"},
                    "record":{
                      "type":"official-registry",
                      "source":{"id":"did:web:registry.example.org","type":"PublicRegistry"}
                    },
                    "attachments":[
                      {"digest":{"alg":"sha3-384","value":"<base64>"},"url":"urn:uuid:evidence-doc-001"}
                    ]
                  }
                ]
              },
              "claims":{
                "healthcareRegistrationNumber":"ES-SAN-REG-0001",
                "professionalLicenseDid":"did:web:college.example.org:member:12345"
              }
            }
          }
        },
        {
          "issuedCredentialRecordId":"urn:uuid:issued-credential-record-001",
          "operatorDid":"did:web:localhost%3A3310#employee-02",
          "resource":{
            "type":"document",
            "method":"eid",
            "time":"2026-03-06T10:05:00.000Z",
            "verifier":{"organization":"did:web:localhost%3A3310"},
            "document_details":{"type":"official-registry-certificate","document_number":"COL-0001"},
            "attachments":{"digest":{"alg":"sha3-384","value":"<base64>"},"url":"urn:uuid:evidence-doc-002"}
          }
        }
      ]
    }
  }'
```

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/evidence/official-registry/_add-response?thid=evidence-add-001" | jq .
```

VC+JWT attachment example (Pontus-X):

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/evidence/official-registry/_add" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"msg-evidence-vcjwt-001",
    "thid":"thid-evidence-vcjwt-001",
    "type":"application/bundle-api+json",
    "body":{
      "issuedCredentialRecordId":"urn:uuid:issued-existing-002",
      "operatorDid":"did:web:ica.example.com#delegate-1"
    },
    "attachments":[
      {
        "id":"pontusx-vc-001",
        "format":"vc+jwt",
        "media_type":"application/vc+jwt",
        "data":{
          "json":{
            "format":"vc+jwt",
            "jwt":"<compact-vc-jwt-es256k>"
          }
        }
      }
    ]
  }'
```

### 5) Upsert ICA delegation policy (`_upsert`)

Use this endpoint for ICA controller delegation rules (who can add/verify specific evidence types for ICA members).  
Canonical mode is `body.data[]` and each `data[i].resource` is an ODRL policy object.

Minimum constraints expected in policy resource:
- one constraint for `$.credentialSubject.id` (delegate DID)
- one constraint for `$.credentialSubject.hasOccupation.occupationalCategory`
  (occupation, e.g. `ISCO-08|1120`)

Practical pattern:
- delegate DID is in `credentialSubject.id`
- occupation is in `credentialSubject.hasOccupation.occupationalCategory`
- email hash can be in `credentialSubject.identifier` (instead of plain `schema:email`)
- if policy scope is `onehealth`, authorization applies to any API path sector starting with `animal` or `health`

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/policies/delegations/_upsert" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"delegation-policy-upsert-msg-001",
    "thid":"delegation-policy-upsert-001",
    "type":"application/bundle-api+json",
    "body":{
      "data":[
        {
          "resource":{
            "@context":[
              "http://www.w3.org/ns/odrl.jsonld",
              {
                "ovc":"https://w3id.org/gaia-x/ovc/1/",
                "sdo":"https://schema.org/",
                "onehealth":"https://onehealth.example/ns#"
              }
            ],
            "profile":"https://w3id.org/gaia-x/ovc/1/",
            "uid":"urn:policy:ica:es:delegate:1120:zEmailHash:official-registry:v1",
            "type":"Set",
            "assigner":{"@id":"did:web:ica.example.org:ica:cds-ES:v1:onehealth:controller:1120:zControllerHash"},
            "assignee":{"@id":"did:web:ica.example.org:ica:cds-ES:v1:onehealth:delegate:1120:zEmailHash"},
            "permission":[
              {
                "target":"urn:ica:organization:*:evidence:official-registry",
                "action":{"@id":"odrl:write"},
                "ovc:constraint":[
                  {
                    "ovc:leftOperand":"$.credentialSubject.id",
                    "odrl:operator":"odrl:eq",
                    "odrl:rightOperand":"did:web:ica.example.org:ica:cds-ES:v1:onehealth:delegate:1120:zEmailHash"
                  },
                  {
                    "ovc:leftOperand":"$.credentialSubject.hasOccupation.occupationalCategory",
                    "odrl:operator":"odrl:eq",
                    "odrl:rightOperand":"ISCO-08|1120"
                  },
                  {
                    "ovc:leftOperand":"$.credentialSubject.identifier",
                    "odrl:operator":"odrl:eq",
                    "odrl:rightOperand":"zEmailHash"
                  },
                  {
                    "ovc:leftOperand":"$.credentialSubject.walletKid",
                    "odrl:operator":"odrl:eq",
                    "odrl:rightOperand":"did:key:z6MkInvitee...#z6MkInvitee..."
                  }
                ]
              }
            ]
          }
        }
      ]
    }
  }'
```

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/policies/delegations/_upsert-response?thid=delegation-policy-upsert-001" | jq .
```

### 6) Issue credential (`_issue`)

`body.data[]` is canonical. Put the VC in `data[i].resource` and optional extra evidence in `data[i].evidence`.
`credentialSubject` must follow `schema.org` semantics and include `@type` (`Person` or `Organization`).

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_issue" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"credential-issue-msg-001",
    "thid":"credential-issue-001",
    "type":"application/bundle-api+json",
    "body":{
      "data":[
        {
          "resource":{
            "id":"urn:uuid:vc-member-001",
            "type":["VerifiableCredential","LegalRepresentativeCredential"],
            "issuer":"did:web:localhost%3A3310",
            "credentialSubject":{
              "id":"did:web:member.example.org:alice",
              "@type":"Person",
              "memberOf":{
                "@type":"Organization",
                "legalName":"Acme Health SL",
                "taxID":"VATES-A12345678"
              }
            },
            "evidence":[
              {
                "type":"qualification",
                "checkedAt":"2026-03-06T10:00:00.000Z"
              }
            ]
          }
        },
        {
          "resource":{
            "id":"urn:uuid:vc-member-002",
            "type":["VerifiableCredential","OrganizationCredential"],
            "issuer":"did:web:localhost%3A3310",
            "credentialSubject":{
              "id":"did:web:member.example.org",
              "@type":"Organization",
              "legalName":"Acme Health SL",
              "taxID":"VATES-A12345678"
            }
          },
          "evidence":[
            {
              "type":"address",
              "checkedAt":"2026-03-06T10:01:00.000Z",
              "proof":{"type":"OperatorApprovalProof","signature":"<jws>"}
            }
          ]
        }
      ]
    }
  }'
```

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_issue-response?thid=credential-issue-001" | jq .
```

### 7) Credential status (`_status`)

Use canonical `body.data[]` with one or many lookup entries (`credentialId`, `issuedCredentialRecordId`, `subjectId`, or `credentialStatusId`).

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_status" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"credential-status-msg-001",
    "thid":"credential-status-001",
    "type":"application/bundle-api+json",
    "body":{
      "data":[
        {
          "credentialId":"urn:uuid:vc-member-001",
          "resource":{
            "id":"urn:uuid:vc-member-001",
            "credentialStatus":{"id":"urn:uuid:issued-record-001#status"}
          }
        }
      ]
    }
  }'
```

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_status-response?thid=credential-status-001" | jq .
```

### 8) Revoke credential (`_revoke`)

Use canonical `body.data[]` for one or many revocations. Keep credential identifier in the payload (batch-friendly), not in path.

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_revoke" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"credential-revoke-msg-001",
    "thid":"credential-revoke-001",
    "type":"application/bundle-api+json",
    "body":{
      "data":[
        {
          "credentialId":"urn:uuid:vc-member-001",
          "reason":"membership-terminated",
          "revokedBy":"did:web:localhost%3A3310#employee-02",
          "resource":{
            "id":"urn:uuid:vc-member-001",
            "credentialStatus":{"id":"urn:uuid:issued-record-001#status"}
          }
        }
      ]
    }
  }'
```

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/member-onboarding/_revoke-response?thid=credential-revoke-001" | jq .
```

### 9) Search credentials (`_search`)

`_search` is unitary (single query), FHIR-style: `POST` with `application/x-www-form-urlencoded`.

Supported params:
- `id` (generic, mapped by `credentialType` hint)
- `text` (free text over legal name/address)
- `email`
- `taxId`, `taxIdHash`, `legalName`, `subjectId`, `issuerId`, `credentialId`
- `thid` (or `jti`) for async polling thread

```bash
curl -i -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/organization-taxid/_search" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "id=VATES-A12345678" \
  --data-urlencode "thid=credential-search-001"
```

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/credentials/organization-taxid/_search-response?thid=credential-search-001" | jq .
```

### 10) Dummy dataspace sync (logs even on failure)

You can force calls to a dummy endpoint to inspect metadata update traces
(`credential/evidence/catalog`) per dataspace target:

```bash
export ICA_SPACES_TARGETS_JSON='{"targets":[{"resourceType":"RuntimePlatform","name":"Pontus-X","identifier":"did:web:pontusx.example.org","url":"https://adapter.example.org/dummy-sync","license":"replace-me-api-key"}]}'
```

With `ICA_SPACES_STRICT=false` (default), the main flow does not fail when the
dummy endpoint returns an error. ICA logs the reason under `spaces-sync`.

Detailed Pontus-X integration guide (outbound payloads, target registration,
and catalog publication):
[`docs/pontusx-integration.md`](./docs/pontusx-integration.md)

Note: sync events currently use `@type: "DataspacePublicationMetadata"` as the
ICA adapter exchange format. They are not a standard DDO.

### 11) Manage sector-scoped dataspace target list (`spaces`)

List current configuration:

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/spaces/_list" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{"jti":"req-auto","thid":"thid-auto","type":"application/bundle-api+json","body":{}}' | jq .
```

Replace the full list (`body.data[]`):

```bash
curl -sS -X POST \
  "$BASE/$TENANT/cds-$JUR/v1/$SECTOR/network/spaces/_replace" \
  -H "Content-Type: application/didcomm-plain+json" \
  -d '{
    "jti":"req-auto",
    "thid":"thid-auto",
    "type":"application/bundle-api+json",
    "body":{
      "data":[
        {
          "resourceType":"RuntimePlatform",
          "name":"Pontus-X",
          "identifier":"did:web:pontusx.example.org",
          "url":"https://adapter.example.org/dummy-sync",
          "license":"replace-me-api-key"
        }
      ]
    }
  }' | jq .
```

Security notes:
- `apiKey` and `license` are input-only (write-only).
- `_list` and `_replace` never return secrets or secret references.
- `content[]` in responses uses `identifier` (DID) and `url` (endpoint) as the
  public shape, aligned with `schema.org`.
- In `targets`, use `@type` (JSON-LD) or `resourceType` (plain JSON). Do not
  use `type`.
- This restriction applies only to `body.data[]` entries in `spaces`; it does
  not change `body.type` in the DIDComm/FHIR Bundle envelope.
- For GKE runtime notes (ADC, Firestore/GCS IAM, static IP), see
  [`docs/05-operations-and-deployment/01-gke-and-security.md`](./docs/05-operations-and-deployment/01-gke-and-security.md).

## Polling Behavior

- Repeat `POST` on the corresponding `.../_*-response` endpoint with the same `thid`.
- If the response is `202`, wait `Retry-After` (or 5 seconds) and poll again.
- Terminal state is any non-`202` response.

## DIDComm Response Format

Final responses (`200`) and early errors (`4xx/5xx`) are always DIDComm plaintext with:

- `type: "application/bundle-api+json"`
- `body.resourceType: "Bundle"`
- `body.type: "batch-response"`
- `body.issues` in FHIR `OperationOutcome` format

`application/bundle-api+json` is a project-defined media type used intentionally by this API.

Basic DIDComm fields used by this API:

| Field | Where | Meaning in this API |
|---|---|---|
| `jti` | request/response | Message identifier. If `thid` is missing, request parsing can fallback to `jti` as thread id source. |
| `thid` | request/response | Thread identifier for async flow. Required in polling (`_*-response`) via query/body; if absent in early errors it can be `""`. |
| `type` | request/response | Semantic message type. This API uses the project-defined value `application/bundle-api+json` in DIDComm request/response examples. |
| `body` | request/response | Main business payload. In responses it is always a `Bundle` with `data[]`, `total`, and `issues`. |
| `iss` | response | Issuer DID of ICA service (`did:web:...`) used to build response envelope. |
| `aud` | response | Audience DID resolved by config/routing; in early errors it can be `""` if request context is incomplete. |
| `attachments` | request (`_verify`) | Transport for PDF: use `attachments[].data.base64` (or `attachments[].data.links`). |

Transport constraints:

- `Content-Type` is usually `application/didcomm-plain+json` (exception: credential `_search` supports `application/x-www-form-urlencoded`).
- `Content-Encoding` must be `identity`.
- `application/didcomm-encrypted+json` is not accepted directly by these endpoints (decrypt before calling API).

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
- `GET /.well-known/dcat3/catalog`
  - public ICA host/operator service autodiscovery catalog
- `GET /openapi.json`
- `GET /api-docs`
- `GET /.well-known/did.json`
- `GET /.well-known/jwks.json`
- `GET /did.json`
- `GET /ica/cds-{jurisdiction}/v1/{sector}/{membertype}/{role}/{idHash}/did.json` (controller/member DID when configured)

Verification and keys:

- The ICA VC issuer key remains a separate `ES384` verification method under
  `assertionMethod`.
- `ICA_COMMUNICATION_JWKS_JSON` accepts public-only `ML-DSA-44` and
  `ML-KEM-768` keys. The former is published under `authentication`, the latter
  under `keyAgreement`, and both are included in `/.well-known/jwks.json`.
- `ICA_COMMUNICATION_KEY_SEED_PASSPHRASE` derives both keypairs
  deterministically with separate domains and keeps their private bytes in the
  runtime identity. If absent, the existing VC seed is used only as the root
  input for those distinct derivations.
- Private JWK members and secret key bytes are rejected; they belong in the
  runtime wallet/KMS, never in the DID document or public JWKS.
- Only the legacy `ES384` JWK publishes `x5u`, defaulting to the canonical
  `/.well-known/x509.pem` URL even before its certificate chain is provisioned.
  ML-DSA and ML-KEM keys do not inherit legacy X.509 metadata.

- `/.well-known/x509.pem` publishes the `CA:FALSE` chain for the ICA VC
  signing key. `/.well-known/organization-ca.pem` publishes the separate
  `CA:TRUE` subordinate chain used to issue organization/tenant X.509 leaves.
  The two private keys and lifecycles must never be collapsed.
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate` (stub)
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate-response` (stub)
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate` (stub)
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate-response` (stub)
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/did/document/_create`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/did/document/_create-response`
  - explicit v1 mode still accepts `organization.publicKeyJwk` and `controller.publicKeyJwk` directly in `_create`.
  - v2 bootstrap can omit `organization.publicKeyJwk` and/or `controller.publicKeyJwk` in `_create` if ICA already stored them from `_verify`.
  - optional `organization.jwks` and `controller.jwks` can carry additional keys for communications or future capabilities using `purposes` such as `vc-sign`, `didcomm-sign`, and `didcomm-enc`.
  - if the ICA already has an active `ES384` key imported through `entity/keys/credentials/_activate` with `x5c`, `_create` signs the organization leaf certificate with that active ICA key and returns inline `x5c` on the primary organization signing key.
  - if `ICA_CREATE_DID_SELF_CA_STAGING=true` and `organization.publicKeyJwk` arrives without `x5c/x5u`, `_create` injects deterministic inline `x5c` for the primary organization signing key.
  - for SMART-on-FHIR / EUDI compatibility, prefer `ES384` as the primary VC-signing key and publish `ES256K` only as an additional key when needed for Pontus-X.

`_rotate` submit endpoints validate controller authorization signature (`body.signature.data`) before returning `202`.

Network evidence and credentials:

- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_search`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_search-response`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/spaces/_list`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/spaces/_replace`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/request`
- `GET /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/datasets/{id}`
  - scoped member dataset catalog discovery

## Catalog Profile Scope

The operational discovery baseline for ICA is `DCAT3`.

`HealthDCAT-AP` is not the default ICA interoperability baseline. Treat it as
optional profile guidance for richer dataset publication scenarios only.

Reference:
- [`docs/adr-0002-discovery-catalog-profile.md`](./docs/adr-0002-discovery-catalog-profile.md)

## Key Rotation And VC Re-Issuance Status

Credential and communication `_rotate` routes still exist in pre-`1.0.0`
status. They must not be treated as a complete production trust lifecycle yet.

The missing pieces still to be defined and implemented are:

- proof of possession of the old key
- proof of possession of the new key
- controller/operator authorization semantics
- VC re-issuance semantics
- trust-registry / ledger-adapter state transition recording

The documentation intentionally keeps this backlog jurisdiction-agnostic for
now.

Reference:
- [`docs/adr-0003-key-rotation-and-vc-reissuance-backlog.md`](./docs/adr-0003-key-rotation-and-vc-reissuance-backlog.md)
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/ddo/request` (DDO profile in parallel)
- `GET /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/ddo/datasets/{id}` (DDO profile in parallel)

Route constraints:

- `sector`: any value starting with `animal` or `health` (for `onehealth` umbrella)
- `idHash` (discovery DID path): `multibase58(multihash(SHA3-256(id)))`
- controller bootstrap `id`: normalized email (`trim().toLowerCase()`)
- `resourceType=contract`: skips template/content validation
- `resourceType` (versioned mode): `yyyyddmmhhmm` (12 digits)
- `resourceType` (test): `test-yyyyddmmhhmm` (requires `ICA_ENABLE_TEST_TERMS_PREFIX=true`)
- `evidenceType`: free classifier for `_add` (e.g., `address`, `official-registry`, `qualification`)
- `_add` supports vc+jwt DIDComm attachments (`application/vc+jwt`) verified against `ICA_EVIDENCE_VC_ISSUERS_LIST` (DID/URL issuer trust list)
- delegation policy path is fixed to `network/policies/delegations`; policy scope lives in `body.data[].resource.permission[]`
- `credentialType`: free classifier for `_issue`, `_status`, `_revoke`, `_search` (e.g., `member-onboarding`)
- recommended organization credentialType classifiers: `organization-taxid`, `organization-license`, `organization-legalname`, `organization-representative`, `organization-delegation`
- `dcat3` dataset `{id}`: `multibase58(multihash(SHA3-256(taxId)))`
- DCAT publisher must be a real organization `did:web` (ICA internal membership DID aliases are excluded from catalog publication).
- Every stored credential/evidence keeps `originDataspaceDid` + `dataspacePublications[]` metadata for multi-space sync tracking.

## npm Scripts

- `npm run dev`: normal start (no watch)
- `npm run api:local`: start using `.env.local` (manual/local-only overrides)
- `npm run api:dev`: watch mode (`./src`)
- `npm run api:start`: normal start alias (`.env.deploy.dev`)
- `npm run api:start:deploy:demo`: start with `.env.deploy.demo`
- `npm run api:start:deploy:dev`: start with `.env.deploy.dev`
- `npm run api:start:deploy:prod`: start with `.env.deploy.prod`
- `npm run api:example:activate`: generates deterministic DIDComm payload for `_activate`
- `npm run create:terms:pdf -- --text-file <terms.md|terms.txt> --out <annex.pdf> [--values-json <values.json>]`: generate Terms annex PDF with predefined fields (Markdown supported)
- `npm run test`: API behavior tests
- `npm run typecheck`: strict TypeScript checks

Test suite is split by concern (to avoid a single unmaintainable mega-file):
- `test/api.identity-signing.test.ts`: controller/issuer DID + proof + seed/self-signing behavior
- `test/api.verify.test.ts`: verify routing, parser, storage and request manager behavior
- `test/api.activation-keys.test.ts`: `_activate` / `_rotate` parsing and controller-signed key activation flow
- `test/api.vc-bundle.test.ts`: VC bundle assembly/evidence mapping output
- `test/api.delegation-policy.test.ts`: ODRL delegation policy `_upsert` parsing, validation and polling flow
- `test/api.lifecycle-collections.test.ts`: verify polling, issue/status/revoke/add lifecycle and collections persistence
- `test/api.credentials-search.test.ts`: credential `_search` request/response flow

## VC Debug Output (manual)

`test-output-vc-resources.json` is not generated automatically by API runtime or by `npm run api:test`.
It is created only when you run a manual export command.

Generate/update export of `body.data[].resource` from a stored verification response:

```bash
export ICA_RESPONSE_JSON="${HOME}/gdc-evidence/verification-response.json"
export ICA_VC_RESOURCES_OUTPUT="${PWD}/test-output-vc-resources.json"
node --input-type=module -e "import fs from 'node:fs/promises'; const source=process.env.ICA_RESPONSE_JSON; const raw=await fs.readFile(source,'utf8'); const didcomm=JSON.parse(raw); const dataEntries=Array.isArray(didcomm.body?.data)?didcomm.body.data:[]; const resources=dataEntries.map((entry)=>({type:entry?.type,resource:entry?.resource})).filter((entry)=>entry.resource); const target=process.env.ICA_VC_RESOURCES_OUTPUT; await fs.writeFile(target,JSON.stringify({generatedAt:new Date().toISOString(),source,resources},null,2)); console.log(target);"
```

## Docker, GKE and Cloud Run URL behavior

Deployment artifacts are under:

- `Dockerfile`
- `.dockerignore`
- `docker_build_local.sh`
- `docker_run.sh`
- `cloud_deploy.sh`
- `deploy/k8s/configmap.yaml`
- `deploy/k8s/secret.example.yaml`
- `deploy/k8s/deployment.yaml`
- `deploy/k8s/service.yaml`

Recommended quick flow (same local image for deploy):

```bash
./docker_build_local.sh
./docker_run.sh local
./cloud_deploy.sh staging
```

Important:
- `./cloud_deploy.sh` in this repo deploys to **GKE**.
- GKE gives internal service (`ClusterIP`) or public IP (`LoadBalancer`), not `*.run.app`.
- `*.run.app` URLs are from **Cloud Run** deployments.
- Before deploying, `./cloud_deploy.sh` validates the JSON pointed by `GOOGLE_APPLICATION_CREDENTIALS` (if set) and fails if its `project_id` does not match `FIRESTORE_PROJECT_ID`.
- Staging/production GKE should not use `GOOGLE_APPLICATION_CREDENTIALS=./gcp-service-account.json`; use Workload Identity instead.

Step-by-step guide:

- [`deploy/k8s/README.md`](./deploy/k8s/README.md)
- private operations documentation for environment-specific runtime identity,
  Firestore/GCS IAM and Workload Identity enablement

### Service Account JSON via CLI

For local Firestore/GCS testing, create a service-account key in the runtime data project, not the cluster project.

Typical split:

- GKE cluster project: `<cluster-project>`
- Runtime data/artifacts project: `<runtime-project>`

List existing service accounts in the runtime project:

```bash
gcloud iam service-accounts list --project <runtime-project>
```

Create a dedicated service account if needed:

```bash
gcloud iam service-accounts create dataspace-ica-local \
  --project <runtime-project> \
  --display-name="dataspace-ica local runtime"
```

Create the JSON key file:

```bash
gcloud iam service-accounts keys create gcp-service-account.json \
  --project <runtime-project> \
  --iam-account=dataspace-ica-local@<runtime-project>.iam.gserviceaccount.com
```

Check that the JSON belongs to the expected runtime project:

```bash
node --input-type=module -e "import { readFileSync } from 'node:fs'; const j=JSON.parse(readFileSync('gcp-service-account.json','utf8')); console.log(j.project_id)"
```

Expected output for this setup:

```text
<runtime-project>
```

Recommended local test flow with that file:

```bash
cp env.example .env.local.gcloud
# uncomment GOOGLE_APPLICATION_CREDENTIALS=./gcp-service-account.json if needed
npm run api:local:gcloud
```

If you later deploy to GKE, keep `GOOGLE_APPLICATION_CREDENTIALS` commented in `.env.deploy.*` unless you are explicitly mounting that JSON into the pod.

## Environment Configuration (summary)

Server and DID:

- `ICA_API_HOST` (default `0.0.0.0`)
- `ICA_API_PORT` (default `3310`)
- `ICA_LOCAL_TENANT_ID` (recommended in ICA single-tenant mode: `ica`)
- `ICA_DIDCOMM_ISSUER_DID` (optional)
- `ICA_DIDCOMM_AUDIENCE_DID` (optional)
- `ICA_DID_DOCUMENT_JSON` (optional)
- `ICA_DID_SERVICE_ENDPOINT` (optional)
- `ICA_DCAT_SERVICE_ENDPOINT` (optional explicit DCAT discovery endpoint in DID service; defaults to `/.well-known/dcat3/catalog`)
- `ICA_DSP_DATA_SERVICE_ENDPOINT` (optional explicit DID `DataService` endpoint; default `https://<did:web-authority>/.well-known/dspace-version`)
- `ICA_DCP_ISSUER_SERVICE_ENDPOINT` (optional explicit DID `IssuerService` endpoint; published only when configured)
- `ICA_DID_PROTOCOL_SERVICE_ENDPOINT` (backward-compatible alias of `ICA_DSP_DATA_SERVICE_ENDPOINT`)
- `ICA_SELF_CONTROLLER_KID` (bootstrap controller `kid` when CA credentials are not yet available)
- `ICA_SELF_CONTROLLER_EMAIL` (bootstrap controller email for T&C metadata fallback)
- `ICA_SELF_CONTROLLER_MEMBER_TYPE` (default `controller`; e.g. `organization`, `controller`, `delegate`)
- `ICA_SELF_CONTROLLER_ROLE` (default `RESPRSN`; bare HL7 v3 RoleCode used in the controller/member DID path)
- `ICA_SELF_CONTROLLER_JURISDICTION` (required for derived controller/member DID)
- `ICA_SELF_CONTROLLER_SECTOR` (optional; defaults to `management` for derived controller/member DID; legacy `controller`/`administration` values are normalized to `management`)
- `ICA_SELF_CONTROLLER_EMAIL_HASH` (optional precomputed member email hash; format `multibase58(multihash(SHA3-256(id)))`; if omitted derives from email)
- `ICA_SELF_CONTROLLER_DID` (optional explicit controller DID override)
- `ICA_SELF_CONTROLLER_PUBLIC_KEY_JWK` (optional controller public key for DID publication)
- `ICA_SELF_CONTROLLER_X5C` (optional CSV x5c chain for controller DID key)
- `ICA_SELF_CONTROLLER_ALG` (optional alg hint for `ICA_SELF_CONTROLLER_PUBLIC_KEY_JWK`)
- `DISABLE_CONTROLLER_DIDCOMM_PROOF` (default `false`; keep `false` in production)
- `DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION` (default `false`; keep `false` in production)
- `ICA_CONTROLLER_CA_TRUST_ANCHOR_PINS_SHA256` (optional CSV trust anchors pinning for controller x509 chains)
- `ICA_CONTROLLER_CA_ALLOWED_ISSUER_SUBSTRINGS` (optional CSV issuer allowlist for controller x509 chains)
- `ICA_EVIDENCE_VC_ISSUERS_LIST` (trusted issuer list for vc+jwt attachments; JSON/CSV with `did:web` or URL entries)
- `ICA_EVIDENCE_VC_ALLOWED_ALGS` (optional global CSV alg allowlist; default `ES256K`)
- `ICA_EVIDENCE_VC_ISSUERS_CACHE_TTL_SECONDS` (optional DID/JWKS cache TTL; default `300`)
- `ICA_EVIDENCE_VC_ISSUERS_REQUIRE_X509_CHAIN` (optional strict mode; default `false`)
- `ICA_EVIDENCE_VC_ISSUERS_TRUST_ANCHOR_PINS_SHA256` (optional CSV trust-anchor pins for issuer x509 chains)
- `ICA_EVIDENCE_VC_ISSUERS_ALLOWED_ISSUER_SUBSTRINGS` (optional CSV issuer substring filters for issuer x509 chains)
- `ICA_ROOT_CA_DID` (did:web of root CA used as trust/governance reference in spaces responses)
- `ICA_SPACES_TARGETS_JSON` (optional spaces adapter targets; accepts `did/endpointUrl/apiKey`, aliases `identifier/url/license`, and target typing via `@type` (JSON-LD) or `resourceType`)
- `ICA_SPACES_TARGET_DIDS` + `ICA_SPACES_DEFAULT_ENDPOINT` (CSV fallback for dummy adapter routing)
- `ICA_SPACES_DEFAULT_API_KEY` (optional auth for adapters; header fixed to `x-api-key`)
- `ICA_SPACES_STRICT` (default `false`; when `true` sync errors fail the job)
- `ICA_SPACES_TIMEOUT_MS` (default `8000`)

Controller x509 identity check for `_activate`:
- If `ICA_SELF_CONTROLLER_EMAIL` is set, certificate must include that email (subject/SAN).
- If `ICA_SELF_CONTROLLER_EMAIL_HASH` is set, certificate email values must hash to that id (multibase/multihash sha3-256).

VC signing:

- `ICA_VC_SIGNING_PRIVATE_KEY_PEM` (optional)
- `ICA_VC_SIGNING_ALG` (`ES384` | `ES256K` | `RS256` | `PS256` | `EdDSA`)
- `ICA_VC_SIGNING_PREFERRED_ALG`
- `ICA_VC_SIGNING_REQUIRED_FOR_PROD`
- `ICA_SELF_SIGN_TEST` (self-sign bootstrap for local key)
- `ICA_SELF_SIGN_IF_MISSING` (auto-generate self-sign key when no key is configured)
- `ICA_SELF_SIGN_TEST_ALG` (`ES384` default)
- `ICA_SELF_SIGN_TEST_KEY_ID` (optional forced `kid` for bootstrap key)
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE` (optional deterministic seed passphrase)
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_FILE` (optional secret file path; highest priority)
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_SECRET_ENV` (optional env-var indirection; middle priority)
- `ICA_HOST_SECRET_PROVIDER` (`gcp-secret-manager` to enable cloud provider mode)
- `ICA_GCP_PROJECT_ID` (project used when secret is configured by short name)
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET` (secret short/full resource name)
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET_VERSION` (optional full version resource; overrides short name)
- `ICA_HOST_SECRET_CACHE_TTL_SECONDS` (fresh cache TTL, default `300`)
- `ICA_HOST_SECRET_STALE_IF_ERROR_SECONDS` (stale cache budget when cloud fetch fails, default `21600`)
- `ICA_VC_PRIVATE_KEY_SEED_CONFIG` (optional scrypt config: `<log2N>:<r>:<p>:<dkLen>` or JSON)
- `ICA_VC_PRIVATE_KEY_SEED_SALT` (optional salt override, recommended separate from config)
- `ICA_VC_SEED_ALG` (`ES384` | `ES256K` for seed-derived key)
- `ICA_SELF_SIGN_TEST_VALID_PROOF` (if `true`, signs `test-*` proofs; default keeps invalid test proof)

Verification behavior:

- `ICA_VERIFY_STRICT_REVOCATION` (default `true`)
- `ICA_VERIFY_STRICT_TEMPLATE_MATCH` (default `true`)
- `ICA_VERIFY_TEMPLATE_MATCH_MODE` (`strict-bytes` | `logical-content`)
- `ICA_VERIFY_DIGEST_ALGORITHM` (default `sha3-384`)
- `VERIFIERS_VAT_LIST` (comma-separated `VATES-...`; matching signatures identify configured verifier organizations)
- `VERIFICATION_PARTNERS_VAT_LIST` (comma-separated `VATES-...`; matching signatures identify verification partners organizations)

For multi-signed contract PDFs, every detected signature is still CMS/chain/revocation validated. When `VERIFIERS_VAT_LIST` is configured, `_verify` only accepts the PDF if:

- at least one detected signer VAT belongs to `VERIFIERS_VAT_LIST`
- and there is a counterparty signature, resolved by these rules:
  - any non-verifier signer VAT is a counterparty candidate
  - if no non-verifier signer exists and all signer VATs are verifiers, the counterparty is the signer that matches the last configured VAT present in `VERIFIERS_VAT_LIST`

If `VERIFICATION_PARTNERS_VAT_LIST` is also configured, `_verify` will additionally require:
- at least one detected signer VAT belongs to `VERIFICATION_PARTNERS_VAT_LIST`

Counterparty selection rules used to populate organization/person credentials:

- if verifier+partner+third-party signatures exist, the third-party signer is preferred as counterparty
- if the PDF only has verifier+partner signatures, the partner signature is selected as the primary counterparty
- if the PDF only has verifier signatures, the counterparty is selected from verifiers using the last configured VAT present in `VERIFIERS_VAT_LIST`

Audit document persistence:

- `STORAGE_PROVIDER` (`mem` | `gcs` | `ipfs`)
- `ICA_AUDIT_STORAGE_REQUIRED`
- `ICA_AUDIT_ATTACHMENT_URL_PATTERN`
- `GCS_BUCKET_NAME`
- `ICA_AUDIT_STORAGE_GCS_PREFIX`
- `IPFS_API_URL`
- `IPFS_GATEWAY_URL`
- `IPFS_MFS_ROOT`
- `ICA_CONFIDENTIAL_STORAGE_ENABLED` (optional; when `true`, audit PDFs are encrypted at rest)
- `ICA_CONFIDENTIAL_STORAGE_KEY_SEED` (optional explicit seed; if absent ICA reuses resolved host seed passphrase)
- `ICA_CONFIDENTIAL_STORAGE_KEY_VERSION` (optional key version label, default `v1`)

Architecture decision note:
- Confidential storage scope and GW alignment criteria are documented in [`docs/adr-0001-confidential-storage-model.md`](./docs/adr-0001-confidential-storage-model.md).

Verification collections persistence:

- `DB_PROVIDER` (`mem` | `firestore` | `postgres`, default `mem`)
- `ICA_COLLECTIONS_REQUIRED`
- `ICA_COLLECTIONS_PREFIX`
- `FIRESTORE_PROJECT_ID`
- `POSTGRES_URL`

Reproducible migration from Firestore/GCS to PostgreSQL/IPFS:

```bash
npm run test:migration:postgres-ipfs
npm run evidence:migration:postgres-ipfs
```

The runner uses only synthetic open-source fixtures and real local Firestore
Emulator, PostgreSQL and Kubo boundaries. Real credentials, signed PDFs and
private key material remain outside source control. See
[`docs/06-architecture-and-reference/02-postgres-ipfs-gap.md`](./docs/06-architecture-and-reference/02-postgres-ipfs-gap.md).

Collection names are derived by code from `ICA_COLLECTIONS_PREFIX` using the fixed pattern:
- `${prefix}_issued_credentials`
- `${prefix}_evidence_records`

Template source:

- `ICA_TERMS_TEMPLATE_URL_PATTERN`
- placeholders: `{tenantId}`, `{jurisdiction}`, `{jurisdictionLower}`, `{jurisdictionUpper}`, `{sector}`, `{sectorLower}`, `{sectorUpper}`, `{section}`, `{format}`, `{resourceType}`, `{resourceVersion}`
- recommended pattern: `.../terms/dataspace/{sector}/{jurisdictionLower}/{resourceVersion}/terms.pdf`
- `ICA_ENABLE_TEST_TERMS_PREFIX`
- `ICA_TERMS_TEMPLATE_USE_TEST_PREFIX` (deprecated fallback)
- `ICA_TERMS_TEMPLATE_CACHE_TTL_SECONDS`
- `ICA_TERMS_TEMPLATE_CACHE_MAX_ENTRIES`
- `ICA_TERMS_TEMPLATE_PRELOAD_ENABLED`
- `ICA_TERMS_TEMPLATE_PRELOAD_RESOURCE_TYPES`
- `ICA_TERMS_TEMPLATE_PRELOAD_SECTORS`
- `ICA_TERMS_TEMPLATE_PRELOAD_JURISDICTIONS`
- `ICA_TERMS_TEMPLATE_PRELOAD_TENANT_ID`
- `ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX` (deprecated fallback)
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
## Terms Annex PDF (implemented)

Generate a Terms & Conditions annex PDF from plain text plus predefined form fields:

```bash
npm run create:terms:pdf -- \
  --text-file ./docs/examples/terms-annex.es.md \
  --out ./artifacts/terms-annex.pdf \
  --values-json ./docs/examples/terms-annex-values.example.json
```

Predefined annex field names:

- `organization.additionalType`
- `organization.sameAs`
- `organization.url`
- `organization.alternateName`
- `organization.registrationNumber`
- `person.email`
- `person.alternateName`
- `person.additionalType`

During `_verify`, signed PDF form values are extracted and incorporated into evidence/VC output:

- Included as `annexFormFields` inside evidence `document_details`.
- Mapped into organization/person credential subjects when present.
- Organization VC `credentialSubject.id` is the canonical dataspace DID:
  `did:web:<ORG_PUBLIC_DOMAIN_NODE_OPERATOR>:<sector>:organization:taxid:<VATES-NIF>`
  (defaults to `did:web:globaldatacare.es:...`).
- If `organization.sameAs` is a real `did:web` and differs from that canonical dataspace DID, it is mapped to `credentialSubject.sameAs`.
- `organization.alternateName` is the short org alias, e.g. `acme`.
- `organization.additionalType` carries the flattened profile string, e.g. `sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider`.
- `person.email` is the controller hash/email and is mapped to `credentialSubject.sameAs`.
  If it arrives in plain text, backend hashes it automatically to `urn:multibase:z...`.
- `person.alternateName` is used for the controller `kid`.
- `person.additionalType` is used for the controller algorithm, e.g. `ES384`.

Production/strict expectation:

- ICA can still reject `_verify` even if GW is correct, because the PDF is the
  primary signed evidence source.
- For smooth production issuance, the signed PDF should expose at least the
  organization identity ICA needs to bind the Organization VC:
  - organization VAT/tax identifier
  - organization legal name
  - valid digital signature material accepted by the configured verifier policy
- For GW activation/recovery flows, the signed evidence should also expose the
  organization authorization claims that ICA must emit in the VC:
  - `credentialSubject.makesOffer.category`
  - `credentialSubject.makesOffer.serviceType`
- In `demo`, ICA may temporarily fallback those authorization claims from route
  defaults or payload compatibility helpers. In production, they should come
  from the signed document/evidence itself, not from unverified frontend/BFF
  payloads.
- Representative/controller claims should likewise come from signed evidence or
  verified identity sources; payload-only merges are a local/demo convenience.

Extended guide: [docs/terms-annex-form.md](./docs/terms-annex-form.md)

## Entorno local y tests

Para que la API y los tests funcionen correctamente, es necesario configurar las variables de entorno:

1. **Copia el archivo de ejemplo:**

   ```bash
   cp env.example .env.local
   ```

2. **Edita `.env.local`** con los valores necesarios para tu entorno (por ejemplo, `DID_WEB_DOMAIN`, claves, etc).

3. **Carga automática en tests:**
   - Los tests relevantes cargan automáticamente `.env.local` usando `dotenv`.
   - Así, no necesitas exportar variables manualmente ni pasar el archivo al runner.

4. **Ejecución local:**
   - Usa `.env.local` también para `npm run api:local` y otros comandos de desarrollo.

> **Recomendación:** Mantén `.env.local` fuera de control de versiones y actualiza `env.example` cuando cambien las variables requeridas.

---
