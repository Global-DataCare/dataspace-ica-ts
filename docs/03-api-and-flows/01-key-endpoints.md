# 01 Key Endpoints

## Discovery and metadata

- `GET /`
- `GET /openapi.json`
- `GET /api-docs`
- `GET /.well-known/did.json`
- `GET /.well-known/jwks.json`
- `GET /.well-known/x509.pem`
- `GET /.well-known/x509.der`

The DID/JWKS and X.509 endpoints expose the same active public ICA signing
material. In the required trust profile, ICA validates that chain against the
pinned Root DID before it starts listening.

## Verification flow

- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify-response`

`networkKind` is `test`, `local-network`, `test-network` or `network`. The
legacy `terms` segment remains accepted as an alias of `test`.

Purpose:

- receive signed PDF evidence
- validate signature/evidence/business metadata
- return async job status and final bundle output

## Credential key activation

- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate`
- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response`

Purpose:

- import or activate signing key material
- bind active key state to ICA business flows

## Other lifecycle endpoints

- `_add`
- `_upsert`
- `_issue`
- `_status`
- `_revoke`

The transport/envelope stays broadly consistent while the business payload changes by endpoint.

## Contract style

Current baseline:

- DIDComm plaintext envelope
- business payload in `body`
- main results in `body.data[]`
- business issues and errors in `body.issues`

## Where to find concrete examples

- activation example generator:
  `npm run api:example:activate`
- tests:
  [`../../test`](../../test)
- fixtures:
  [`../examples`](../examples)
- detailed curl sections:
  [`../../README.md`](../../README.md)
