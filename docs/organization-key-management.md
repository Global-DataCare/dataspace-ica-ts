# Organization Key Management

## Current State

The implemented flow now looks like this:

1. `_verify` validates the signed adhesion contract
2. controller/message key travels in `meta.jws.protected.jwk`
3. organization credential key travels in an optional `application/jwk+json` attachment
4. if the organization key is absent, ICA autogenerates an `ES384` keypair
5. `_verify-response` returns bootstrap JWK data outside `body.data[].resource`
6. `_create` publishes the DID document using:
   - explicit keys sent in `_create`, or
   - the keys already stored from `_verify`

## Key Roles

- controller key:
  - message-signing / onboarding authorization
  - comes from `meta.jws.protected.jwk`
  - may be published later in controller-related DID relationships

- organization key:
  - credential-signing / DID document primary key
  - comes from attachment or ICA auto-generation
  - is the one expected to receive `x5c`

## Algorithm Policy

For organization credential signing:

- primary key should be `ES384`
- `ES256K` remains optional as an additional key in `organization.jwks.keys[]`

This keeps compatibility with SMART-on-FHIR / EUDI Wallet while still allowing Pontus-X style secondary keys.

## `_create` Rules

`_create` now supports:

- explicit organization/controller keys in the request
- stored fallback from verification records when keys are omitted

This means an organization can:

- accept the ICA-generated `ES384` bootstrap keypair from `_verify`
- or send its own organization key during `_verify` as the canonical credential key
- if ICA generated the key, `_create` must explicitly confirm that same `organization.publicKeyJwk`

## Future Add/Rotate Flow

Post-onboarding organization key updates still need a dedicated endpoint, for example:

- `POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/{taxid}/keys/credentials/_activate`

That future endpoint should update the organization DID document and return the updated DID document resource.

## Future Delete Flow

Organization deletion should be authorized by the controller message-signing key, not by raw taxID alone.

- didactic mode:
  - allow the controller public key to travel in `meta.jws.protected.jwk`
- hardened mode:
  - require `didcomm-signed`
  - optionally wrap it in `didcomm-encrypted`

That keeps delete semantics aligned with the same controller binding used during onboarding.

The planned contract is documented in [`organization-terms-remove-v2.md`](./organization-terms-remove-v2.md). The preferred business endpoint is `_remove` under `terms/pdf/{resourceType}`, not a generic `_delete`.
