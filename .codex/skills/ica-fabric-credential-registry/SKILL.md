---
name: ica-fabric-credential-registry
description: Use for ICA credential identity, Fabric anchoring, evidence hashes, revocation, governed host preauthorization without PDF, and migration between test, local-network, and test-network.
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

## Route network contexts

- The canonical verification route is
  `/{tenantId}/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify`.
  `networkKind`, not the PDF signature policy, selects the credential signing
  and registration context for that request.
- `test` always means no Fabric. The historical path segment `terms` is only
  an input alias for `test`; polling locations return the canonical `test`
  segment.
- `local-network` enables Fabric on `identity-local`.
- `test-network` is the externally trusted staging context. Organization,
  representative/employee, location, identity-evidence and identity-event
  credentials for EU organizations use `identity-eu`. Natural-person
  individual credentials, identity evidence and identity events use
  `identity-global`. Channel selection is authoritative server configuration,
  never a request field. Provide the four canonical `HLF_*` connection secrets.
- Credentials restricted to this context carry `TestNetworkCredential` in
  their signed `type[]`. Do not add `targetNetwork` to schema.org credential
  subjects: the environment discriminator is the credential type selected
  from the authoritative route. `network`, `local-network` and `test` omit
  that marker.
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
- `network` is the production Fabric context and uses the same fail-closed
  server-controlled channel routing rules.
- A governed host may omit the PDF only when its domain is in
  `ICA_PREAUTHORIZED_HOST_DOMAINS` and the route kind is in
  `ICA_PREAUTHORIZED_HOST_NETWORK_KINDS`. Require matching host DID, Service
  URL and issuer plus an ES384 compact JWS over the route scope and exact
  forwarded resource;
  resolve the key from the host's `did:web` document. Never treat the discovery
  allowlist or a client route value as issuance authorization.
- For reproducible `local-network`, configure
  `globaldatacare.es,member.example`. Preserve the normal PDF path for every
  unlisted organization/host and record the governed request digest without
  manufacturing PDF evidence.
- The accepted no-PDF branch must still emit the host's logical
  `HostingServiceCredential` as JSON VC and compact VC-JWT. Its evidence names
  the governed-host JWS authorization and must not synthesize PDF, PAdES,
  terms-and-conditions or IPFS evidence. Prove this with
  `npm run test:host-preauthorization`.
- For an actual staging or production host, preauthorize its exact canonical
  domain before deploying the workload: use `test-network` for staging and
  `network` for production. Keep the sector allowlist exact. Routing regions
  such as `na`, `latam`, `asia` and `pacific` are Fabric/governance scope and
  never replace the verified legal jurisdiction in the ICA request.
- If the host must receive its credential before DNS/workload deployment,
  mount a JSON file and configure `ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_FILE`
  with exactly one governance-approved public `did:web` document for that host.
  Treat it as an
  authoritative public-key pin, reject private JWK members, and do not fall
  back to network resolution when the configured array omits the issuer.
- Keep the authority chain ordered: ICA host approval and
  `HostingServiceCredential`, Fabric enrollment, private host materialization,
  Helm runtime installation, then tenant onboarding. The first tenant
  controller manages the host through the tenant contract; it is independent
  from the ICA governance controller and Fabric enrollment identity.
- `NETWORK_MODE=test` remains the legacy deployment default and compatibility
  input, but it must not override an explicit canonical route `networkKind`.
  The request can select whether anchoring applies; it can never name a Fabric
  channel, MSP, peer, ACL or endorsement policy.
- `ICA_CREDENTIAL_LEDGER_REQUIRED=true` makes issuance/revocation fail if the
  ledger cannot commit. Use this for the staging cutover gate.
- Chaincode is `credential-sc` unless explicitly overridden.

## Root CA and ICA signing trust

- The Root CA is an offline authority whose public static surface is a
  deployment-configured `did:web`, its JWKS/X.509 chain and trust metadata. It is not
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
- Staging may regenerate the ICA-owned ES384 leaf private key from
  `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE`. This seed is not a Root/issuer/Fabric
  key. Generate its public CSR in `dataspace-ca-ts` with the explicit
  `ica-vc-runtime-v1` derivation profile so the CSR `kid` matches the deployed
  ICA key; never transfer the generated private PEM to the offline Root operator.
  An explicit `ICA_VC_SIGNING_PRIVATE_KEY_PEM` takes precedence over the seed.
- ICA publishes its exact active chain at `/.well-known/x509.pem` and includes
  the same `x5c`/`x5u` in DID/JWKS signing methods. Do not generate a fallback
  self-signed production key.
- The VC-signing certificate is a `CA:FALSE` ES384 leaf. A different ES384
  subordinate certificate with `CA:TRUE` and `pathLen=0` issues public
  organization/tenant X.509 leaves and is published at
  `/.well-known/organization-ca.pem`. Never use the VC-signing leaf as an
  organization certificate issuer.
- An organization/tenant certificate is not a Fabric identity. A host that
  operates a peer proves a Root-authorized `HostingServiceCredential`, then
  generates its Fabric MSP/TLS private keys and CSRs locally for enrollment.
  ICA must support several governed dataspace ICA DIDs; the issuer that
  verified a tenant remains visible in that tenant's certificate chain.

## Verification workflow

1. Run `npm run test:fabric:credential`.
2. Prepare/deploy the local identity channel from the sibling GW/Fabric stack.
3. Run `npm run fabric:credential:smoke:local`, then start ICA with
   `npm run api:local:fabric`.
4. Issue through the normal PDF `_verify` / `_verify-response` flow, or through
   the signed governed-host branch when reproducing a preauthorized host.
   For the host branch, preserve jurisdictional registration identifiers as
   typed `identifier.additionalType` and `identifier.value` (for example type
   `BN`). Keep a registry scheme such as Washington UBI in separate evidence;
   never manufacture VAT/TAX or use the registry scheme as identifier type.
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
