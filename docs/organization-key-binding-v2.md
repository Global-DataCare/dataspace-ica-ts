# Organization Key Binding V2

## Goal

V2 separates two different keys during onboarding:

- the controller/message-signing key used by the wallet/frontend to talk to ICA
- the organization credential-signing key that will later receive `x5c` in the organization DID document

## Request Contract

`terms/pdf/contract/_verify` now uses these inputs:

1. PDF attachment:
   - `attachments[].media_type = application/pdf`
2. Controller binding key:
   - `meta.jws.protected.jwk`
3. Optional organization credential key:
   - extra DIDComm attachment with `media_type = application/jwk+json`

If the organization JWK attachment is missing, ICA autogenerates an `ES384` organization credential-signing keypair.

## Response Contract

`_verify-response` returns key bootstrap material outside `body.data[].resource`:

- organization entry:
  - `publicKeyJwk`
  - `privateKeyJwk` only when ICA generated the keypair
  - `keySource = generated | attachment`
- legal representative/controller entry:
  - `publicKeyJwk` with the controller binding key taken from `meta.jws.protected.jwk`

The organization keypair is therefore bootstrapped during `_verify`, while the credential resources stay clean inside `resource`.

## `_create` Behavior

`entity/did/document/_create` may now work in two modes:

1. explicit override mode:
   - frontend sends `organization.publicKeyJwk` and/or `controller.publicKeyJwk`
2. stored binding mode:
   - frontend omits one or both keys
   - ICA reuses the keys stored from `_verify`

That allows this flow:

1. `_verify` with controller binding key and optional organization JWK attachment
2. ICA returns generated organization keypair when no organization JWK was sent
3. frontend may keep that generated key, or discard it
4. `_create` can:
   - reuse the stored/generated organization key, or
   - confirm the ICA-generated key by resending the same `organization.publicKeyJwk`

## Security Rule

- `meta.jws.protected.jwk` is only the controller/message key.
- It is not automatically the same as the organization credential-signing key.
- Repeating `_verify` with the same contract and a different controller binding key must be rejected in the hardened production flow.
- Post-onboarding add/rotate/revoke of organization keys still belongs to a dedicated key-management endpoint, not to `_verify`.

## Deletion Direction

Organization deletion should follow the same controller-binding model:

- the request must be authorized by the controller message-signing key
- in the didactic `didcomm-plain` mode, that key can still be surfaced as `meta.jws.protected.jwk`
- in the hardened production flow, the request should be a real `didcomm-signed` message, optionally wrapped in `didcomm-encrypted`

That future remove flow should remove or deactivate the confirmed organization DID state and must not rely on plain unauthenticated metadata alone. See [`organization-terms-remove-v2.md`](./organization-terms-remove-v2.md).
