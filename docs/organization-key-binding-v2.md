# Organization Key Binding V2

## Goal

V2 separates two different keys during onboarding:

- the DIDComm communication key used by the wallet/frontend/device/BFF to talk to ICA
- the controller operation-signing / binding key used to represent the real controller in the VC
- the organization credential-signing key that will later receive `x5c` in the organization DID document

## Request Contract

`{networkKind}/pdf/contract/_verify` now uses these inputs. `networkKind` is
`test`, `local-network`, `test-network` or `network`; the legacy `terms`
segment remains an alias for `test`.

1. PDF attachment:
   - `attachments[].media_type = application/pdf`
2. DIDComm communication metadata:
   - optional `meta.jws.protected.jwk`
3. Controller binding key:
   - preferred `body.data[].resource.controller.publicKeyJwk`
   - legacy fallback `meta.jws.protected.jwk`
4. Optional organization credential key:
   - extra DIDComm attachment with `media_type = application/jwk+json`

Every organization must normally supply its public organization key. The old
ICA-generated `ES384` keypair is deprecated compatibility restricted to
development network kinds (`test` and `local-network`); it is rejected in
`test-network` and `network`.

## Response Contract

`_verify-response` returns key bootstrap material outside `body.data[].resource`:

- organization entry:
  - `publicKeyJwk`
  - `keySource = attachment` in the normal contract
  - deprecated development responses may say `keySource = generated`
  - `privateKeyJwk` is hidden by default and is never emitted in `test-network` or `network`
- legal representative/controller entry:
  - `publicKeyJwk` with the controller binding key taken from `body.data[].resource.controller.publicKeyJwk`

The organization owns its keypair. ICA stores and returns only its submitted
public key while credential resources stay clean inside `resource`.

## `_create` Behavior

`entity/did/document/_create` may now work in two modes:

1. explicit override mode:
   - frontend sends `organization.publicKeyJwk` and/or `controller.publicKeyJwk`
2. stored binding mode:
   - frontend omits one or both keys
   - ICA reuses the keys stored from `_verify`

That allows this flow:

1. `_verify` with controller binding key and organization public JWK
2. ICA stores those caller-owned public bindings
3. `_create` can reuse the stored public keys or resend those exact public keys

## Security Rule

- `meta.jws.protected.jwk` is a communication/profile/device/BFF key.
- `body.data[].resource.controller.publicKeyJwk` is the controller business binding key.
- Those two keys may be equal in simple didactic flows, but ICA must not assume they are the same.
- Neither of them is automatically the same as the organization credential-signing key.
- Repeating `_verify` with the same contract and a different controller binding key must be rejected in the hardened production flow.
- A staging or recovery deployment may explicitly set
  `ICA_ALLOW_CONTROLLER_REBIND_ON_REVERIFY=true`. In that deployment only, a
  successful `_verify` may supersede the active JWK when the controller
  identity is unchanged. ICA records the previous RFC 9278 thumbprint and the
  transition timestamp. The flag never authorizes changing
  `controller.sameAs` and remains disabled by default.
- After a successful `_remove`, re-enrollment may bind a new controller key
  without this opt-in because the previous lifecycle is already closed.
- Post-onboarding add/rotate/revoke of organization keys still belongs to a dedicated key-management endpoint, not to `_verify`.

## Deletion Direction

Organization deletion should follow the same controller-binding model:

- the request must be authorized by the controller message-signing key
- in the didactic `didcomm-plain` mode, that key can still be surfaced as `meta.jws.protected.jwk`
- in the hardened production flow, the request should be a real `didcomm-signed` message, optionally wrapped in `didcomm-encrypted`

That future remove flow should remove or deactivate the confirmed organization DID state and must not rely on plain unauthenticated metadata alone. See [`organization-terms-remove-v2.md`](./organization-terms-remove-v2.md).
