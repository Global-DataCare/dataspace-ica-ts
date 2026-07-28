---
name: ica-fabric-credential-registry
description: Use for ICA credential identity, Fabric anchoring, evidence hashes, revocation, and migration between test, local-network, and test-network.
---

# ICA Fabric credential registry

## Immutable identity contract

- A JSON VC and its VC-JWT are two representations of one logical credential.
- The Fabric key is the logical credential identifier: JSON `vc.id` = JWT `jti`
  = embedded JWT `vc.id`.
- The subject is separate: JSON `credentialSubject.id` = JWT `sub`.
- In plain terms, the mappings are VC id to JWT jti and subject id to JWT sub.
- Never key issuance, status, or revocation by `credentialSubject.id`; one
  subject may own several credentials.
- An organization VC and a legal-representative VC are two logical credentials
  and therefore two `credential-sc` assets and two independently addressable
  statuses.
- One revocation of a credential asset covers its JSON-LD and JWT
  representations. It does not automatically revoke the other logical
  credential unless an explicit business policy performs both operations.

## Hash and evidence contract

- Store one SHA3-384 logical-content hash per credential, excluding only the
  JSON-LD proof wrapper.
- Store exact SHA3-384 representation hashes for `vc+ld+json` and `vc+jwt`.
- Preserve the issued compact JWT off-ledger so later retrieval can serve the
  representation whose hash was anchored.
- `evidence[].check_details[].txn` is the immutable PDF CID/reference generated
  by ICA; it is not a Hyperledger Fabric transaction ID.
- Project audit fields into `metadata.evidenceRefs`: verifier DID, verification
  timestamp, certificate issuer, certificate serial number, signature
  timestamp, and document CID.
- The same PDF CID may be referenced by both logical credentials. Do not create
  four independent evidence/status records merely because there are two
  representations.
- If `vc.id` already exists with the same logical hash, skip creation. If the
  same id has a different logical hash, fail closed.

## Runtime modes

- `NETWORK_MODE=test`: compatibility mode, always no Fabric even if ledger
  flags are present.
- `NETWORK_MODE=local-network`: Fabric enabled on `identity-local`.
- `NETWORK_MODE=test-network`: Fabric remains opt-in. Organization,
  representative/employee, location, identity-evidence and identity-event
  credentials for EU organizations use `identity-eu`. Natural-person
  individual credentials, identity evidence and identity events use
  `identity-global`. Channel selection is authoritative server configuration,
  never a request field. Provide the four canonical `HLF_*` connection secrets.
- The current ICA runtime accepts one configured credential channel per
  deployment. Until typed multi-channel routing exists, use separate
  organization and individual deployment profiles; never mix both planes in
  one `ICA_CREDENTIAL_LEDGER_CHANNEL`.
- Creating `identity-<region>` does not update every peer automatically. A
  controller/governance approval feeds a privileged declarative reconciler,
  which updates channel configuration, joins only authorized host peers,
  approves/commits required chaincodes and records health/audit state. Do not
  give a portal user peer-admin certificates. Membership permits ledger
  visibility; ACL, endorsement and chaincode rules independently gate writes.
- `ICA_CREDENTIAL_LEDGER_REQUIRED=true` makes issuance/revocation fail if the
  ledger cannot commit. Use this for the staging cutover gate.
- Chaincode is `credential-sc` unless explicitly overridden.

## Root CA and ICA signing trust

- The Root CA is an offline authority whose public static surface is
  `did:web:ca.unid.online`, its JWKS/X.509 chain and trust metadata. It is not
  an online issuance service and its private key never enters ICA or
  Kubernetes.
- ICA receives its own private key plus an offline-signed leaf-to-Root chain.
  `ICA_VC_SIGNING_TRUST_REQUIRED=true` must fail startup unless the private key
  matches the leaf, every certificate signature is valid, the terminal Root
  matches `ICA_ROOT_CA_CERT_SHA256`, and the resolved `ICA_ROOT_CA_DID`
  verification method matches that same Root certificate.
- X.509 proves the cryptographic chain; `ICA_ROOT_CA_DID` binds the Root public
  key to the governed web authority and discovery metadata. The DID is not a
  second key and is not redundant with the certificate.
- Keep `ICA_VC_SIGNING_PRIVATE_KEY_PEM` and
  `ICA_VC_SIGNING_CERTIFICATE_CHAIN_PEM` in a Kubernetes Secret. The Root DID,
  Root certificate pin and ICA `x5u` are public ConfigMap values.
- ICA publishes its exact active chain at `/.well-known/x509.pem` and includes
  the same `x5c`/`x5u` in DID/JWKS signing methods. Do not generate a fallback
  self-signed production key.

## Verification workflow

1. Run `npm run test:fabric:credential`.
2. Prepare/deploy the local identity channel from the sibling GW/Fabric stack.
3. Run `npm run fabric:credential:smoke:local`, then start ICA with
   `npm run api:local:fabric`.
4. Issue through the normal PDF `_verify` / `_verify-response` flow.
5. Extract `body.data[].resource.id`; verify each using
   `npm run fabric:credential:read:local -- --credential-id '<vc.id>'`.
6. Confirm two assets for a two-credential response and that every attachment
   JWT has `jti === vc.id` and `sub === credentialSubject.id`.
7. Re-submit the same deterministic PDF and confirm the assets are skipped,
   not duplicated.
8. Revoke by `credentialId` and confirm both representations of that one
   credential report revoked.

Read `docs/06-architecture-and-reference/03-fabric-credential-registry.md`
before changing this contract or staging configuration.
