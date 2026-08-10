# Legal Organization Controller Binding and Rotation Handoff

## Purpose

This is a handoff note for the follow-up implementation thread. It defines the
general model for every legal organization hosted through GW CORE: the current
SDK routes, the standards-aligned DID model, the legacy ICA bootstrap to retire,
and the proposed controller rotation controls.

The scope is a **legal organization** registered through the host registry. It
is not the tenant-scoped `individual/org.schema/Organization` flow. Concrete
tenant identities, keys, evidence, domains and deployment observations belong
in tenant-owned operational documentation, not in this architecture note.

## Controller and Infrastructure Trust Boundaries

Registering a legal organization does not create a controller infrastructure
identity in the Root CA, the host, or Fabric.

- Root CA, ICA, and host MSP identities are infrastructure/operator identities
  used to administer and endorse the blockchain network.
- A legal organization's controller is business identity material: its DID,
  submitted public key, representative credential binding, and authorization
  evidence.
- GW's current Fabric registration at legal-organization activation anchors the
  organization VC, the public keys in the organization DID, and evidence
  artifacts. It does not register the controller's private key or make the
  controller an MSP/network administrator.
- For an existing tenant, GW now promotes the ICA-approved multikey controller
  during `_issue` and, in Fabric-backed modes, registers every public key plus
  its `legal-organization-controller-signing` binding. The initial
  `_transaction`/Order path still needs the same helper wired at finalization.
- Later `Device/_dcr` registers the JWKs supplied for an employee device in
  Fabric and binds them to the employee DID with `deviceId`. This includes the
  bootstrap controller only when that person completes DCR; those are
  employee-device keys and are not automatically the same key as the legal
  controller binding key.
- A controller key rotation, a new contract, a different legal representative,
  or a new controller email is therefore an organization lifecycle event. It
  must be authorized and audited, but it does not rotate Root CA, host, ICA, or
  Fabric MSP identities.

Controller binding must have an explicit, idempotent business audit/binding
record in Fabric. This is separate from Fabric identity enrollment.
`registerOrganizationOnLedger(...)` still processes only organization DID
verification methods. Existing-tenant `_issue` now uses the dedicated
controller-key helper; `registerSubjectKeysOnLedger(...)` continues to anchor
employee device keys after DCR with a distinct subject/device binding.

### Required Controller Binding Ledger Record

After ICA approves the legal organization `_transaction`, GW must register the
controller binding on the organization identity channel before reporting the
onboarding decision as complete. The registration must use the existing Fabric
assets, without placing a JWK or any private material on-chain:

1. Register or reuse `cryptographickey-sc` asset:
   - `keyId`: canonical RFC 9278 thumbprint URN;
   - `thumbprint`: the same canonical URN;
   - `kid`, `kty`, `crv`, `alg`, and `use: "sig"` from the public controller
     JWK;
   - `orgId`: canonical legal-organization ledger ID;
   - `purpose: "legal-organization-controller-signing"`;
   - `origin: "ica-verified-transaction"`;
   - `status: "active"`.
2. Upsert `subjectkeybinding-sc` asset:
   - `subjectType: "employee"` for the persisted bootstrap-controller
     relationship;
   - `subjectId`: the controller DID, not email;
   - `parentOrgId`: canonical legal-organization ledger ID;
   - `keyId`: the controller thumbprint URN;
   - `relationship: "legal-organization-controller-signing"`;
   - `status: "active"`;
   - audit metadata: ICA transaction `thid`, PDF digest, legal representative
     credential ID, controller DID, and the approved evidence decision ID.

The dedicated GW helper uses the existing Fabric wrappers and records
`legal-organization-controller-signing`, rather than relabeling controller
authority as `employee-device-signing`. The deployed chaincode schema must
accept that relationship string.

On controller rotation, register/reuse the new key asset, write the new active
legal-controller binding, and mark only the previous
`legal-organization-controller-signing` binding as `revoked` or `superseded`.
Do **not** revoke the underlying key asset merely because its legal-controller
binding is replaced: that public key may still be valid for a device or another
authorized relationship. A key status change requires a separate compromise or
retirement decision.

The current `_transaction` flow is the implementation target. Keep legacy
`_activate` behavior unchanged while it is being deprecated; add JSDoc, skills,
OpenAPI, test comments, and 101 documentation stating that it does not acquire
the new controller-binding ledger behavior unless explicitly migrated.

## Critical Security Finding

The captured ICA response includes `privateKeyJwk` for an ICA-generated
**organization** bootstrap key. Its private member must be treated as exposed.

Required immediate action:

1. Rotate that generated organization key if it was used beyond the test
   artifact.
2. Stop returning `privateKeyJwk` by default. Set
   `ICA_VERIFY_RESPONSE_INCLUDE_PRIVATE_KEY_JWK=false` as an immediate
   mitigation.
3. Remove private JWKs from API responses, async job results, logs, stored
   audit payloads, test fixtures intended for publication, and generated API
   examples.
4. Add regression tests asserting no response serialization contains JWK
   private members such as `d`, `k`, `p`, `q`, `dp`, `dq`, `qi`, or `oth`.

This is separate from a controller key submitted by any portal. The current
auto-generation path creates `organization` ES384 material when an organization
public JWK attachment is omitted.

## Standards-Aligned DID Model

Use DID Core `controller` at the top level. Its value is a DID or an array of
DIDs, not a JWK thumbprint URN.

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:host.example:LEGAL-ORG-ID:cds-ES:v1:sector",
  "controller": "did:web:people.host.example:controller:<stable-person-id>",
  "verificationMethod": [
    {
      "id": "did:web:host.example:LEGAL-ORG-ID:cds-ES:v1:sector#organization-signing-key",
      "type": "JsonWebKey2020",
      "controller": "did:web:host.example:LEGAL-ORG-ID:cds-ES:v1:sector",
      "publicKeyJwk": { "organization-public-key": "only" }
    }
  ]
}
```

Rules:

- Do not publish controller JWKs among the organization's own verification
  methods merely to represent control. DID Core `controller` references a
  separately resolvable controller DID document.
- The controller DID document may publish several simultaneously valid public
  verification methods. Use `controller.jwks.keys[]`, never a comma-separated
  string. A deployment may combine a primary classical signing key, an
  additional federation key, a PQC governance key, and a communication signer.
- Keep the RFC 9278 thumbprint URN as the `kid` and audit/key-binding value.
  It identifies a key; it is not itself a DID Core controller.
- Continue publishing the tenant/organization public verification methods in
  its DID according to their actual verification relationships.

ICA preserves `controller.did`, `controller.publicKeyJwk` and
`controller.jwks` from `_verify` through `_create`, requires the complete
binding to match, and assigns the stable DID to the organization document's
top-level `controller`. A single-key client without `controller.did` retains
the legacy derived `did:key` fallback; a multikey JWKS requires an explicit
controller DID.

GW Core projects that controller DID into the tenant DID while keeping the
controller keys in the separate controller DID document. It forwards the
complete public-only binding to ICA.

## Legal Organization Onboarding Routes

There are three distinct flows. Do not substitute one for another.

| Flow | SDK method | Endpoint | Purpose |
| --- | --- | --- | --- |
| Current legal onboarding | `orgControllerSdk.submitLegalOrganizationVerificationTransaction(...)` | `POST /host/cds-{jurisdiction}/v1/{hostNetwork}/registry/org.schema/Organization/_transaction` | Submit signed PDF evidence and controller binding; GW forwards to ICA `_verify`; then continue to `Order/_batch`. |
| Legacy legal activation | `activateOrganizationInGatewayFromIcaProof(...)` | `POST /host/cds-{jurisdiction}/v1/{hostNetwork}/registry/org.schema/Organization/_activate` | Compatibility path when caller already has ICA `vp_token`. |
| Existing legal tenant credential reissuance | `orgControllerSdk.submitLegalOrganizationCredentialReissuance(...)` | `POST /host/cds-{jurisdiction}/v1/{hostNetwork}/registry/org.schema/Organization/_issue` | Refresh legal evidence/reissue controller activation without a new Offer. The old `submitLegalOrganizationIssue(...)` name remains a deprecated SDK alias. |

For any host, derive `{jurisdiction}` and `{hostNetwork}` from host discovery
and use the SDK route builder.

The tenant-scoped route below is unrelated to this legal onboarding work and
must not be suggested to the developer for it:

```text
/{tenantId}/cds-{jurisdiction}/v1/{sector}/individual/org.schema/Organization/_transaction
```

A client should use the host discovery descriptor and the SDK route builder
rather than constructing a tenant activation path manually.

## Why the Developer Saw 404

The reported request pattern used a tenant URL for legal activation and omitted
the legal host registry contract. This is a routing-flow mismatch, not evidence
that a legal organization is absent:

- `OPTIONS` succeeds for the tenant path, so edge routing recognizes it.
- The legal onboarding handler lives under `/host/.../registry/...`.
- `_transaction` is the current `OrganizationControllerSdk` path.
- `_activate` is retained only for an ICA-proof-first compatibility caller.

When diagnosing a remaining `404`, capture the full request method, URL,
content type, response body, deployment revision, and host discovery response.
Do not infer tenant provisioning from the host `dspace-version` endpoint alone.

## Retire ICA Organization-Key Bootstrap

The legacy path is in `src/api/managers/verify-request-manager.ts`:

- if `organizationPublicKeyJwk` is omitted, ICA calls
  `generateOrganizationCredentialKeyPair()`;
- the generated ES384 private JWK is currently stored in the job result and,
  by default, returned by `verify-response-manager.ts`.

This path exists for older web applications that could not create or import a
keypair. Portal implementations must now supply both public bindings before
submitting verification:

- `body.data[].resource.controller.publicKeyJwk`: controller business key;
- organization key attachment or
  `body.data[].resource.organization.publicKeyJwk`: organization
  credential-signing key.

Deprecation plan:

1. Add explicit ICA policy fields:
   `requireSubmittedControllerKey` and `requireSubmittedOrganizationKey`.
2. In test environments, emit a deprecation outcome whenever the organization
   bootstrap fallback is used.
3. In production, reject missing keys with a clear `400` once every supported
   portal has migrated.
4. Remove private-key return support rather than preserving it behind a public
   response flag. If a temporary controlled recovery workflow is unavoidable,
   make it an authenticated one-time secret delivery outside `_verify-response`.
5. Update OpenAPI, JSDoc, SDK docs, and examples so generated organization keys
   are marked legacy until deleted.

## Algorithm and Custody Migration

### Current state

- ICA accepts ES384, ES256K, RSA variants, and EdDSA for current signing flows.
- A legacy federation custodian may submit an existing ES256K controller public
  JWK. It must prove possession via a signature made in its key service; ICA
  must never receive the private key.
- The Node managed wallet keeps `actor-signing` ES384 and ML-DSA-44
  communication signing as its defaults. A tenant may derive ML-DSA-65 as an
  additional controller signing key under an independently versioned domain;
  adding that key does not rotate an established classical key.
- A multikey controller uses a resolvable `did:web`; ICA therefore does not
  need to derive an AKP `did:key` merely to retain the ML-DSA-65 public JWK.
- AWS KMS supports managed ECC/RSA key use, but does not provide ML-DSA-65 key
  operations. A portal using AWS KMS cannot claim ML-DSA-65 controller signing
  without an additional PQC key provider or HSM/service.

### Required migration policy

Do not require ML-DSA-65 proof-of-possession for every custodian until all of
the following are implemented and tested:

1. A shared SDK algorithm identifier and JWK validation for ML-DSA-65.
2. An interoperable DID representation for the ML-DSA controller public key;
   update the `did:key` derivation or use a resolvable controller DID that
   publishes the key according to the agreed multicodec/profile.
3. Wallet support that creates/imports an ML-DSA-65 controller key and provides
   detached proof-of-possession signing.
4. A custody adapter for portals not using the SDK wallet. A cloud-KMS-backed
   portal can hold the ML-DSA private key in a dedicated PQC/HSM service or
   encrypted envelope, with its DEK protected by KMS; expose only signing
   operations.
5. Gateway/ICA verification support for ML-DSA-65 proof-of-possession.

Until then:

- require a submitted controller key;
- allow ES256K for existing controller registrations under explicit legacy
  policy with an expiry date;
- prefer a hybrid transition with existing ES256K proof plus new ML-DSA-65
  proof once available;
- reject a key algorithm only through an explicit policy allowlist, never by
  silently replacing caller key material with an ICA-generated key.

## Rotation and Re-registration Policy

The future controller rotation operation must be driven by ICA-approved legal
evidence and must update GW only after the ICA decision is final.

Inputs:

- New controller public key and its RFC 7638/RFC 9278 thumbprint binding.
- Proof of possession of the new key, over a canonical challenge containing
  tenant DID, old/new thumbprints, audience, nonce, issued/expiry timestamps,
  and transaction ID.
- New qualified electronic signature evidence from the legal representative.
- Existing controller proof where the old key is still available.

Freshness policy:

- Add `controllerRotation.maxQualifiedSignatureAge` in ICA policy.
- Parse durations such as `72h` and `3d`.
- If unset, accept any otherwise-valid qualified signature for the initial
  rollout.
- If set, compare the verifier-extracted CMS/PAdES signing time, not a visible
  date field, against the policy clock.
- Require chain and revocation checks to be valid at the defined validation
  time; document how trusted timestamps are handled when added.

Authorization:

- Normal rotation: current controller proof plus legal representative evidence
  plus new-key proof.
- Recovery rotation: legal representative with fresh qualified evidence plus a
  configurable delay/notification policy; do not accept only an IdP `id_token`
  and a replayable PDF.
- IdP tokens may bind the acting email/session, but are not legal authority by
  themselves.
- The legal representative is a governance authorization role; it should not
  consume an operational employee license merely because its email differs from
  the controller's email.

Idempotency:

- Calculate a decision key from tenant identity, PDF digest, qualified signer
  certificate/signature fingerprints, current controller thumbprint, and target
  controller thumbprint.
- If it exactly matches an already-approved rotation, return HTTP `200` and an
  informational `OperationOutcome` with `code: "duplicate"`.
- Do not use HTTP `209`: it is not a standard HTTP status and can break SDKs or
  proxies. If historical DIDComm payloads require a `209` internal status, keep
  it inside the Bundle only while retaining HTTP `200`.
- On exact duplicate, write neither GW tenant state nor blockchain/Fabric.
- On changed evidence or target key, evaluate the full policy before any write.

## Patch Sequence

1. **Immediate containment in ICA**
   - Disable private JWK response output.
   - Rotate any exposed bootstrap key.
   - Add tests preventing private JWK serialization.
2. **ICA policy and evidence**
   - Add submitted-key requirements, qualified-signature freshness policy, and
     decision-key idempotency.
   - Return structured `OperationOutcome` decisions.
3. **GW Core DID projection**
   - Persist ICA-approved controller DID and thumbprint with the tenant
     registration.
   - Populate the standard top-level DID Core `controller` in the tenant DID.
   - Do not add the controller JWK as an organization verification method.
4. **SDK and portal migration**
   - Make `OrganizationControllerSdk` submit both bindings by default.
   - Migrate managed-wallet portals to their controller binding path.
   - Add a KMS signing adapter for existing ES256K controller keys.
5. **PQC capability**
   - Implement, document, and test ML-DSA-65 DID/key/custody support.
   - Enable hybrid rotation, then enforce ML-DSA-65 only after portal support
     is deployed.
6. **Host staging validation**
   - Build the target host GW image, deploy it to its staging network, then
     submit through
     `orgControllerSdk.submitLegalOrganizationVerificationTransaction(...)`.
   - Verify the hosted DID exposes top-level `controller` and no response
     contains a private JWK.
   - Validate first with a non-production legal organization and then repeat
     with a second independent host.

## Required Tests and Audit Documentation

Add narrow unit/integration tests for:

- Submitted controller and organization JWKs are retained; ICA generates none.
- Missing binding keys fail after policy enforcement.
- `privateKeyJwk` never appears in serialised responses.
- Top-level tenant DID `controller` equals ICA-approved controller DID.
- Existing ES256K controller is accepted only when policy permits it.
- ML-DSA-65 is rejected as unsupported until its DID/custody capability exists,
  then accepted with proof verification.
- Freshness: valid at `72h`, invalid at `72h + 1ms`, policy-disabled behavior,
  and parsing for `3d`.
- Duplicate PDF/signatures/target key produces no writes or ledger calls and
  returns the informational duplicate outcome.
- Changed PDF, signer, controller, target key, expired evidence, replayed
  nonce, and wrong audience are rejected.
- Route regression: legal onboarding uses `/host/.../registry/.../_transaction`;
  tenant `individual/...` is never used by the organization controller facade.

Add JSDoc to policy parsing, proof verification, idempotency decision, DID
projection, and legacy bootstrap code. Each test should state the audit rule it
protects. Update OpenAPI descriptions, SDK 101 docs, and this document when the
policy fields and final ML-DSA DID profile are implemented.

## Primary Code References

- ICA bootstrap generation:
  `src/api/managers/verify-request-manager.ts`
- ICA response exposure:
  `src/api/managers/verify-response-manager.ts`
- ICA DID Core controller construction:
  `src/api/tools/organization-did.ts`
- ICA evidence timestamp generation:
  `src/api/tools/vc-bundle.ts`
- GW tenant DID generation:
  `../gwtemplate-node-ts/src/managers/hosting/finalize-tenant-config.ts`
- GW controller entity persistence:
  `../gwtemplate-node-ts/src/managers/hosting/controller-entity-config.ts`
- GW legal host routes:
  `../gwtemplate-node-ts/src/routes/api.ts`
- SDK legal flow facade:
  `../gdc-sdk-node-ts/src/orchestration/organization-controller-sdk.ts`
- SDK legal transaction runtime:
  `../gdc-sdk-node-ts/src/node-runtime-client.ts`
- SDK wallet defaults:
  `../gdc-sdk-node-ts/src/node-managed-wallet.ts`
