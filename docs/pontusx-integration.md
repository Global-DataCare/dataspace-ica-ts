# Pontus-X Integration Guide (ICA)

This guide documents:
- where the current outbound metadata payloads are defined,
- concrete examples to share with Pontus-X API developers,
- and how ICA publishes/updates DCAT catalog metadata per sector.

Important: the payloads sent to Pontus-X are currently `DataspacePublicationMetadata` (internal adapter exchange format), not a Gaia-X self-description/DDO standard.
In parallel, ICA now exposes dedicated DDO endpoints for consumers that require a DDO-style view.

## 1) Where payloads are defined in code

- Outbound sync payload builders:
  - `src/api/tools/dataspace-sync.ts`:
    - credential payload: `syncIssuedCredentialRecord(...)`
    - evidence payload: `syncEvidenceRecord(...)`
    - catalog payload: `syncCatalogSnapshot(...)`
- Outbound HTTP POST execution:
  - `src/api/tools/dataspace-sync.ts` -> `syncToTarget(...)`
- Trigger points:
  - credential/evidence lifecycle managers via collections storage
  - catalog sync after `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/request`
    in `src/api/server.ts`

## 2) Outbound payload examples sent to Pontus-X adapter

All are sent as:
- Method: `POST`
- `Content-Type: application/json`
- API key header: fixed to `x-api-key`

### 2.1 Credential metadata event

```json
{
  "@type": "DataspacePublicationMetadata",
  "kind": "credential",
  "event": "issued",
  "status": "active",
  "targetNetwork": "did:web:pontusx.example.org",
  "sourceNetwork": "did:web:pontusx.example.org",
  "tenantId": "ica",
  "jurisdiction": "ES",
  "sector": "animal-care",
  "credentialType": "organization-taxid",
  "credentialId": "urn:uuid:vc-001",
  "subjectId": "did:web:member.example.org",
  "issuerId": "did:web:localhost%3A3310",
  "hashAlg": "sha3-384",
  "hashValue": "base64-sha3-384-of-canonical-credential",
  "updatedAt": "2026-03-09T12:00:00.000Z"
}
```

### 2.2 Evidence metadata event

```json
{
  "@type": "DataspacePublicationMetadata",
  "kind": "evidence",
  "event": "added",
  "status": "active",
  "targetNetwork": "did:web:pontusx.example.org",
  "sourceNetwork": "did:web:pontusx.example.org",
  "tenantId": "ica",
  "jurisdiction": "ES",
  "sector": "animal-care",
  "evidenceType": "official-registry",
  "evidenceRecordId": "urn:uuid:evidence-001",
  "issuedCredentialRecordId": "urn:uuid:issued-001",
  "hashAlg": "sha3-384",
  "hashValue": "base64-sha3-384-of-canonical-evidence",
  "updatedAt": "2026-03-09T12:00:00.000Z"
}
```

### 2.3 Catalog metadata event

```json
{
  "@type": "DataspacePublicationMetadata",
  "kind": "catalog",
  "event": "published",
  "status": "active",
  "targetNetwork": "did:web:pontusx.example.org",
  "tenantId": "ica",
  "jurisdiction": "ES",
  "sector": "animal-care",
  "catalogUrl": "https://ica.example.org/ica/cds-ES/v1/animal-care/dcat3/catalog",
  "datasetCount": 2,
  "datasetList": [
    "zQmTaxIdHashA",
    "zQmTaxIdHashB"
  ],
  "updatedAt": "2026-03-09T12:00:00.000Z"
}
```

## 3) How to register Pontus-X targets in ICA

Two options:

1. Environment variable (startup):
- `ICA_SPACES_TARGETS_JSON`

Example:

```json
{
  "targets": [
    {
      "resourceType": "RuntimePlatform",
      "name": "Pontus-X",
      "identifier": "did:web:pontusx.example.org",
      "url": "https://pontus-adapter.example.org/metadata",
      "license": "replace-with-api-key"
    }
  ]
}
```

Rule:
- if the entry is JSON-LD, use `@type`
- if it is plain JSON, use `resourceType`
- do not use `type` for spaces targets
- this applies only to `body.data[]` target entries; it does not affect `body.type` in DIDComm/FHIR Bundle envelopes

2. Runtime API replacement (volatile, in-memory):
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/network/spaces/_replace`
- input in `body.data[]`
- secrets accepted as write-only (`apiKey` or `license`) and never returned in `_list`
- `_list`/`_replace` responses expose `content[]` with `identifier` + `url` (public shape)

## 4) How ICA publishes catalog metadata to Pontus-X

1. Configure dataspace target (env or `_replace`).
2. Ensure issued organization credentials exist for that tenant/jurisdiction/sector.
3. Call:
   - `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/request`
4. ICA returns `dcat:Catalog` immediately.
5. ICA also triggers background sync (`kind: "catalog"`) to each configured target endpoint.

If sync fails and `ICA_SPACES_STRICT=false` (default), API response still succeeds and the error is logged.

## 5) Endpoints for developers who read directly from ICA

- Full catalog:
  - `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/request`
- Single dataset:
  - `GET /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/datasets/{id}`
- Full DDO profile (parallel endpoint):
  - `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/ddo/request`
- Single dataset DDO profile (parallel endpoint):
  - `GET /{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/ddo/datasets/{id}`

Dataset id convention:
- `{id} = multibase58(multihash(SHA3-256(taxId)))`

## 6) Quick test flow (local)

1. Register target:
   - call `_replace` with `did + endpointUrl + apiKey/license`
2. Verify target is present:
   - call `_list`
3. Trigger catalog publication:
   - call `dcat3/catalog/request`
4. Check Pontus-X adapter logs for received `kind: "catalog"` payload.
