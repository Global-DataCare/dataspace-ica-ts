# Changelog

## Unreleased

- Align clean ICA installations with `gdc-common-utils-ts@2.7.2`, matching the
  current shared contract consumed by downstream professional portal, and enforce the
  manifest/lockfile pin with an executable release test.

- Add the open-source Firestore/GCS to PostgreSQL/IPFS migration engine. It
  migrates all four ICA verification collections, pins audit bytes in Kubo,
  rewrites governed references to immutable CIDs and fails on unresolved
  objects or reconciliation-digest mismatch.
- Add a reproducible local evidence gate across Firebase Firestore Emulator,
  PostgreSQL and Kubo with synthetic fixtures, content-only manifests and
  checksums; real credentials, signed PDFs and private key material remain
  outside source control.
- Remove the PostgreSQL adapter's 200-record read limit and expose explicit
  pool shutdown for one-shot migration processes.
- Pin patched `brace-expansion` transitively so the production dependency
  audit remains free of known high-severity findings.

- Define a product-neutral signing-custody rule: every deployment wrapper must
  use environment-scoped `-st-` or `-prod-` secret resources, pin immutable
  Secret Manager versions, preserve identity during naming migrations and
  generate independent production signing material.

- Mark every `HostingServiceCredential` issued through the authoritative
  `test-network` route with `TestNetworkCredential` in its signed `type[]`.
  Keep schema.org `Service` subjects free of the non-standard
  `targetNetwork` property; production and local credentials omit the marker.

- Add a governed PDF-free host verification path for reproducible
  `local-network` onboarding. ICA accepts only server-preauthorized host
  domains, requires matching `iss`, organization `did:web` and Service URL,
  verifies an ES384 request JWS against the host DID document, and records the
  governance/request digest without persisting it as a PDF.
- Emit the resulting `HostingServiceCredential` both as JSON VC and compact
  VC-JWT. Its evidence identifies the verified governed-host JWS and never
  invents PDF, PAdES, terms-and-conditions or IPFS document evidence.
- Add `npm run test:host-preauthorization` as the focused, reproducible
  contract gate consumed by the open-source local-network evidence runner.
- Allow governance to pin an approved host's public DID document so ICA can
  verify its signed request and issue the `HostingServiceCredential` before
  host DNS, TLS or workload deployment. Configured pins fail closed and reject
  private JWK material; normal `did:web` resolution remains the fallback only
  when no pin set is configured.
- Accept the governance-pinned host DID array from a mounted public file via
  `ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_FILE`; the file takes precedence over
  the backwards-compatible inline JSON variable and preserves fail-closed
  verification before host DNS exists.
- Preserve a governed host's jurisdictional organization identifier as typed
  `identifier.additionalType` plus `identifier.value` (for example type `BN`).
  Keep a registry scheme such as Washington UBI in separate evidence rather
  than treating it as another identifier type. Do not synthesize VAT/TAX
  identity when no tax identifier was submitted; both OrganizationCredential
  and HostingServiceCredential retain the registered identifier and host DID.

## 1.2.5 - 2026-08-20

- Keep the JWK submitted by legacy legal-organization registration bound to
  the legal representative. A different controller email in signed PDF
  evidence remains a hashed pending designation until that actor supplies a
  matching identity and its own JWK through the sector controller flow.
- Preserve that pending controller designation when an older re-verification
  omits the controller field, and do not synthesize a controller credential
  that attributes the representative's key to the designated actor.

## 1.2.4 - 2026-08-13

- Make `ServiceControllerCredential` the canonical controller VC. Its owner
  carries bare `RESPRSN` in schema.org `additionalType` and its ISCO token in
  `hasOccupation.occupationalCategory`; no invented role property or display
  label is signed.
- Present the three independent ICA verification credentials in Swagger and
  distinguish representative ISCO `1120` from controller `RESPRSN`, ISCO
  `1330` and actor-JWK binding.
- Keep legal-representative occupation (`ISCO-08|1120` by default) separate
  from controller authority. Controller VCs now carry both bare `RESPRSN` and
  the technical occupation (`ISCO-08|1330` by default), with validated signed
  PDF occupation fields overriding either default when present.

- Emit one signed `ServiceControllerCredential` service VC when verified
  controller identity evidence and a public actor JWK are both present. Keep
  legal-representative and technical-controller bindings separate when their
  emails differ, while preserving distinct VCs when they are the same actor.
- Persist and return controller bootstrap metadata on the new controller entry
  while retaining the legal-representative projection for older clients.

- Emit the organization controller/legal-representative role as the bare HL7
  v3 code `RESPRSN` and keep `credentialSubject.sameAs` as the independent
  simple contact-hash URN; ISCO-08 `1120` is no longer used as controller
  authorization.

- Preserve existing legal-organization controller DIDs when DID `_create`
  adds another independently verified representative; organization DID
  documents now publish an additive controller array.
- Recompute every published JWK `kid` from public material as an RFC 9278
  SHA-256 thumbprint URN instead of trusting caller-controlled aliases.

## 1.2.3 - 2026-08-09

- Move environment-specific maintenance, GKE, IAM, discovery and incident
  runbooks into the private ICA operations repository; retain only generic
  parameterized deployment guidance and manifests in this source repository.
- Reuse `gdc-common-utils-ts` for compatibility-preserving deterministic EC
  bootstrap, RFC 7638 key identifiers, controller alias multihashes and
  extensible membership-scope validation.
- Remove the historical product scope allowlist. Deployments may pass
  `--allowed-sectors`; otherwise any valid
  `<service-category>:<membership-profile>` value is accepted.
- Remove product-specific local Fabric env paths and live staging addresses
  from package scripts.

- Preserve a stable controller DID plus additional public JWKS from `_verify`
  through DID `_create`, reject binding changes/private members/duplicates, and
  use the stable controller DID in the organization DID. Multikey controllers
  require an explicit DID; the single-key `did:key` fallback remains compatible.

## 1.2.2 - 2026-07-30

- Allow the existing deterministic ICA VC seed to remain the private-key
  custody mechanism when an offline-issued `x5c` chain is configured, exposing
  that exact chain and `x5u` through the active DID/JWKS signing method.
- Document the explicit `dataspace-ca-ts` runtime-compatible CSR profile and
  clarify that the ICA seed never derives a Root, issuer or Fabric key.

## 1.2.1 - 2026-07-30

- Publish the canonical `/.well-known/jwks.json` projection from the ICA DID
  verification methods and advertise it from the DID document.
- Add public-only ICA communication JWKS configuration with strict separation:
  `ML-DSA-44` under `authentication`, `ML-KEM-768` under `keyAgreement`, while
  legacy `ES384` VC issuance remains under `assertionMethod`.
- Bootstrap deterministic, domain-separated ICA communication keypairs from a
  dedicated runtime seed, with a staging-compatible fallback to the existing VC
  seed; private ML-DSA/ML-KEM material remains in runtime memory.
- Publish the canonical `x5u` placeholder exclusively on the legacy `ES384`
  verification key in both DID and JWKS; PQC keys remain free of X.509 metadata
  until a separate PQC certificate contract exists.
- Separate the ICA `CA:FALSE` VC-signing identity from a dedicated `CA:TRUE`
  organization certification authority, publish the latter in the ICA DID and
  at `/.well-known/organization-ca.pem`, and refuse to issue tenant X.509
  leaves from a non-CA certificate.
- Replace the canonical PDF route section `terms` with typed `networkKind`
  values (`test`, `local-network`, `test-network`, `network`), retain `terms`
  as an alias of `test`, and select Fabric anchoring per request rather than
  from one process-global mode.
- Require an active signing key outside `test` and an externally chained
  `x5c` signing identity for `test-network` and `network`.
- Emit a signed schema.org `HostingServiceCredential` when the verified PDF
  contains the complete versioned host-service form.

## 1.2.0 - 2026-07-29

- Added fail-closed ICA signing bootstrap validation that binds the configured
  private key and leaf certificate through the full X.509 chain to a pinned
  Root CA certificate and its resolved `did:web` document.
- Made `ICA_ROOT_CA_DID` an enforced trust identity when
  `ICA_VC_SIGNING_TRUST_REQUIRED=true`, rather than sync-only metadata.
- Loaded offline-issued `x5c`/chain material into the active signing method,
  published it through dynamic DID/JWKS output, and exposed the public chain at
  `/.well-known/x509.pem` and `/.well-known/x509.der`.
- Documented the deployment-configured offline Root DID boundary and Kubernetes
  Secret/ConfigMap split without deploying or changing staging infrastructure.

## 1.1.8 - 2026-07-28

- Added opt-in Hyperledger Fabric registration of issued organization and legal
  representative credentials in `credential-sc`, keyed by JSON `vc.id` / JWT
  `jti`, with logical and exact representation hashes plus compact audit
  evidence references.
- Added Fabric-backed status/revocation, idempotent duplicate handling,
  issuance-time `credentialStatus`, and persistence of the exact emitted
  VC-JWT for later retrieval.
- Preserved `NETWORK_MODE=test` as no-Fabric compatibility mode; documented and
  tested the `local-network` to parallel `test-network` migration.
- Matched every VC-JWT attachment to its logical credential by the shared
  `credentialId` instead of relying on attachment order.
- Updated to `gdc-common-utils-ts@^2.3.8`.
- Recorded a tenant-specific countersigned contract and Fabric inspection in
  tenant-owned operational evidence rather than the generic ICA repository.

## 1.1.7 - 2026-07-28

- Enforced the member-discovery credential-layer boundary: `vc[]` retains
  schema.org VC JSON, while member-level DIDComm `attachments[]` accepts only
  Gaia-X VC-JWT payloads with the expected `gx:LegalPerson` or
  `gx:ServiceOffering` semantic properties. Schema.org credentials serialized
  as JWT are rejected as Gaia-X participant attachments.
- Documented that `_retrieve` VC-JWT serialization and
  `credential.evidence[].attachments` are not member-level Gaia-X discovery
  attachments.
- Updated to `gdc-common-utils-ts@^2.3.7`, removed ICA's adapter-local Gaia-X
  semantic validator and delegated fail-closed validation to the shared
  attachment builders and fixtures.
- Pinned patched transitive `protobufjs` and `uuid` versions so the production
  dependency audit remains clean.

## 1.1.6 - 2026-07-28

- Paginate Firestore collection reads by document id so credential retrieval,
  DID resolution and member discovery still see records beyond the former
  arbitrary 200-document window.

## 1.1.5 - 2026-07-28

- Pinned patched `fast-xml-parser`, `minimatch` and `brace-expansion`
  transitive versions so the production dependency audit contains no high or
  critical findings.
- Fixed production image packaging by tracking every runtime module under
  `src/api/tools/**`; the generic local `tools/` ignore rule had excluded four
  modules imported by the API server and produced a non-starting image.
- Documented the supported split-project staging topology while keeping
  environment-specific project, address and identity values in the private
  operations repository.

## 1.1.4 - 2026-07-28

- Added an explicit Cloud Build upload manifest so the tracked npm package
  manifests required by the Docker image are not excluded with root JSON
  credential exports.
- Standardized the canonical supported-sector catalog as the eight combinations
  of `animal|health` with `care|tech|research|insurance`, while retaining
  `onehealth-research` as an independently addressable compatibility sector.
  Existing signed credentials are never relabeled; an organization can be
  reverified additionally under canonical `health-research`.
- Simplified `HostServiceFormPdfFields` to legal host/provider/controller
  evidence. Fabric channels, permissions, block-zero fingerprints, chaincodes
  and mutable service policy are configured separately by governance and
  provisioning.

## 1.1.3 - 2026-07-21

- Added the versioned `HostServiceFormPdfFields` contract and runtime validation
  for signed host-service authorization PDFs. The form binds the service category,
  provider identity, host origin, controller email, and RFC 9278 controller-key
  identifier before Service VC issuance; jurisdiction derives from the provider
  country and later operations prove possession of the corresponding private key.

## 1.1.2 - 2026-07-21

- Autodiscovery now fails closed at the network boundary: ICA traverses only
  HTTP(S) dataset hosts listed in `ICA_MEMBER_DISCOVERY_ALLOWED_HOSTS`.
- Documented the migration from the temporary IP/DNS allowlist to a persistent
  host registry authorized by a governance VC issued to the host DID.
- Replaced real organization identifiers in examples and tests with synthetic
  placeholders.

## 1.1.1 - 2026-07-21

- Added the authorized-member autodiscovery aggregate at
  `/{tenantId}/cds-{jurisdiction}/v1/{sector}/network/members/_discover`.
  It returns `data[]` entries containing the locally issued schema.org `vc[]`,
  resolved `did.document`, optional `dcat.document`, and exact signed Gaia-X
  VC-JWT `attachments[]`, with participant first and configurable cache age.
- Organization credentials now publish the canonical schema.org
  `PropertyValue` registration identifier. Explicit `identifierType/value`
  wins; otherwise ICA derives VAT/TAX from the signed tax field.
- Added a reproducible GKE HTTPS profile:
  - a reserved deployment address remains the public endpoint
  - `ingress-nginx` terminates TLS and proxies to the internal ICA service
  - `cert-manager` obtains and renews the Let's Encrypt certificate
  - the canonical DID authority and OpenAPI origin are configured separately
    as `ICA_EXTERNAL_DOMAIN` and `ICA_OPENAPI_SERVER_URL`

# 1.1.0 - 2026-06-30

- Merged the `REI94` implementation line into the current branch:
  - added `DB_PROVIDER=postgres` support for verification collections
  - added `STORAGE_PROVIDER=ipfs` support for audit document persistence
  - added the `pg` dependency and PostgreSQL adapter/config plumbing
- Removed `filesystem` from the supported audit-storage profile:
  - runtime config now accepts `mem`, `gcs`, or `ipfs`
  - public types/OpenAPI/README/examples no longer advertise `filesystem`
  - runtime config tests now explicitly reject `STORAGE_PROVIDER=filesystem`
- Updated runtime/docs/config examples for the supported operator profile:
  - documented `IPFS_API_URL`, `IPFS_GATEWAY_URL`, `IPFS_MFS_ROOT`
  - documented `POSTGRES_URL`
  - aligned `deploy/k8s/configmap.yaml` and `env.example`
- Updated architecture notes so the former `postgres + ipfs` gap document now
  reflects the new code reality: implementation is present, and the remaining
  work is operator hardening plus deeper integration/E2E validation.

# 1.0.4 - 2026-06-22

- In `SECURITY_MODE=demo`, `_verify` now also falls back
  `OrganizationCredential.credentialSubject.makesOffer.serviceType` to the
  canonical provider capabilities
  `organization/Composition.cruds,organization/ResearchSubject.cruds` when
  the signed PDF does not carry them.
- Kept the demo-only `makesOffer.category` fallback from route `{sector}` and
  aligned the emitted `serviceType` tokens with `gdc-common-utils-ts` so GW
  `_transaction` and legacy `_activate` validate the same canonical values.

# 1.0.3 - 2026-06-20

- Updated the shared dependency target to `gdc-common-utils-ts@^2.0.6`.
- Added temporary startup compatibility for legacy
  `application/didcomm-plaintext+json` while downstream packages and clients
  finish migrating to the canonical `application/didcomm-plain+json` media
  type.
- Removed the Docker image default `NODE_ENV=production` so each deployment
  environment controls runtime mode explicitly from its own `.env`.
- Expanded `env.example` to document:
  - the recommended `NODE_ENV` / `SECURITY_MODE` local-demo baseline
  - the demo-only `_verify` fallbacks for route `{sector}` and representative
    `sameAs`
  - the unsafe payload-merge flags
    `DISABLE_STRICT_IDENTITY_SOURCE=true` +
    `ICA_ALLOW_UNVERIFIED_CREDENTIAL_PAYLOADS=true`

# 1.0.2 - 2026-06-18

- Bumped the shared dependency target to `gdc-common-utils-ts@^2.0.5`.
- `_verify` now fills `OrganizationCredential.credentialSubject.makesOffer.category`
  from the route `{sector}` only in `SECURITY_MODE=demo` when the signed PDF
  does not expose that authorization claim yet.
- Clarified the `_verify` contract in OpenAPI and runtime JSDoc:
  - sector authority lives in the route path
  - `organizationPayload` does not need a duplicate sector field
  - production/strict flows should still source the authorization from the
    signed document
- Added VC-bundle coverage proving the sector/category fallback is demo-only
  and is not applied in compat mode.
- Hardened the operator scripts and test coverage around discovery downloads,
  VAT search, DID document creation, multisign controller material, and
  VC-bundle projections:
  - `scripts/download-discovery-pdfs.mjs`
  - `scripts/firestore-vat-search.mjs`
  - `test/api.did-document-create.test.ts`
  - `test/api.multisign-controller-material.test.ts`
  - `test/api.vc-bundle.test.ts`

# 1.0.1 - 2026-06-17

- Fixed the `_verify` controller-binding contract for representative VCs:
  - preferred source is now `body.data[].resource.controller.publicKeyJwk`
  - `meta.jws.protected.jwk` remains only as a legacy fallback
  - the representative `credentialSubject.hasCredential.material` projection
    now follows the controller business key instead of conflating it with the
    DIDComm communication key
- Added explicit request parsing and async verification tests that prove the
  separation between:
  - transport/profile/BFF communication keys in `meta.jws` / `meta.jwe`
  - controller operation-signing/binding keys in
    `body.data[].resource.controller.publicKeyJwk`
- Expanded real-PDF coverage so `_verify` + `_retrieve?version=v2` keeps the
  representative binding stable in the multisign flow.
- Updated OpenAPI, README, and operational docs to document:
  - the preferred v2 `_verify` payload shape
  - the confidential-app / BFF separation of communication keys vs controller
    keys
  - the current legacy fallback behavior and migration path

# 0.9.2 - 2026-06-15

- `_verify` representative `sameAs` fallback is now explicitly demo-only:
  - signed sources remain authoritative in strict/compat modes
  - demo mode may use `legalRepresentativePayload.sameAs` or `.email` only as
    a bootstrap convenience when the signed PDF/certificate does not expose the
    representative contact value
- Added VC-bundle tests that prove the representative payload fallback is
  accepted only in demo mode and ignored in compat mode.
- Documented the representative payload security contract in the async verify
  types so downstream callers do not treat the payload as production identity
  evidence.
- Normalized local fixture path helpers in real-PDF tests to resolve from the
  current user home directory instead of embedding literal `$HOME` strings.
- Reorganized the top-level documentation entry points:
  - numbered `docs/` sections for introduction, setup, API flows, examples,
    operations, and architecture
  - `README.md` now acts as the entry guide into that curated docs tree

# 0.9.1 - 2026-05-29

- Merged `HealthDCAT-APv7` into `main` so the confidential-storage and backend
  auth line is preserved on the main branch before further follow-up work.
- Clarified the ICA discovery/catalog baseline:
  - operational baseline is `DCAT3`
  - `HealthDCAT-AP` is optional profile guidance, not the default ICA baseline
- Added backlog ADRs for:
  - discovery catalog profile scope
  - key rotation, VC re-issuance, and jurisdiction-agnostic ledger adapter
- Updated documentation language so the newly added/edited operational guidance
  is in English only.

# 0.8.7 - 2026-03-30

- Fixed `_verify` submit-time 502 behind ingress by deferring heavy visible text/OCR extraction to async job execution (post-`202`) when `ICA_VERIFY_DEFER_VISIBLE_EXTRACTION=true`.
- Added `ICA_VERIFY_DEFER_VISIBLE_EXTRACTION=true` to deployment-specific env files so fallback extraction still runs, but no longer blocks `_verify` request response.

# 0.8.6 - 2026-03-30

- Fixed OCR runtime temp directory for cloud deployments:
  - OCR workspace now uses OS temp path (`/tmp`) instead of `process.cwd()/artifacts`.
  - Prevents `EACCES: permission denied, mkdir '/app/artifacts'` in containerized environments.

# 0.8.5 - 2026-03-30

- `_verify` failed-job diagnostics now always include annex extraction summary, even when no fields/warnings were extracted (`fieldCount=0`, `warningCount=0`), to make cloud troubleshooting deterministic.

# 0.8.4 - 2026-03-30

- Adjusted OIDC4IDA `document.check_details` semantics for promoter-only / non-cryptographic representative extraction flows:
  - `vcrypt` is now emitted only when electronic signature evidence is present for that credential.
  - In fallback representative flows (identity inferred from document/form/OCR without person-signature cryptographic validation), evidence now includes `vdig` only.

# 0.8.3 - 2026-03-30

- Added extended failure diagnostics to `_verify-response`:
  - Includes annex extraction debug summary (`fieldCount`, detected `organization.taxID/legalName`, key list).
  - Includes annex extraction warnings (pdf-parse/OCR/tesseract/pdftoppm warnings) as OperationOutcome entries.
  - Includes annex debug object inside failed `TermsVerification` content for easier troubleshooting.
- Verification request manager now persists annex debug context into failed jobs so cloud failures expose why verifier-only fallback did not activate.
- Added tests for annex diagnostics propagation in failed verification responses.

# 0.8.2 - 2026-03-30

- Improved PDF signature extraction robustness:
  - `_verify` now ignores malformed CMS payloads from non-primary signatures when at least one valid signature can still be processed.
  - This fixes mixed-signature PDFs where one signer is valid (promoter/verifier) and other signatures are broken.
- Improved `_verify-response` terminal behavior:
  - Internal post-verification persistence errors now return a terminal failed DIDComm bundle instead of a bare transport error.
  - Jobs are explicitly marked as failed so polling always has a recoverable terminal state.
- Added tests covering terminal failed payload behavior on persistence failures.
- Added code TODO for multi-natural-person signer handling (multiple legal representatives in one contract).

# 0.8.0 - 2026-03-30

- Fixed verifier/partner counterparty rules:
  - Partner signature is no longer mandatory in two-signature flows.
  - Partner enforcement now applies to three-actor scenarios (verifier + partner + counterpart).
  - Kept verifier-list fallback behavior for verifier-only signature sets.
- Updated verification tests for the new partner enforcement semantics.

# 0.7.8 - 2026-03-30

- Improved `_verify` resilience:
  - Added endpoint-level `try/catch` guard in verify routes so unexpected failures return controlled `500` responses instead of crashing request handling.
- Improved PDF identity extraction for non-canonical forms:
  - Added fallback mapping for generic AcroForm fields (`Text1..TextN`) to infer `organization.taxID` and `organization.legalName`.
  - Expanded visible organization field aliases (EN/ES variants) used in verification and VC bundle generation.
  - Added text-based visible identity extraction helper and integrated it into verify submission parsing.
- Local runtime defaults:
  - `./docker_run.sh local` now publishes on host port `8010` by default (container app port remains `3310`).

# 0.7.7 - 2026-03-30

- Fixed OpenAPI `info.version` resolution order to avoid stale runtime `npm_package_version` values.
- New priority: `ICA_OPENAPI_INFO_VERSION` -> `package.json` version -> `npm_package_version` -> fallback.

# 0.7.6 - 2026-03-30

- `_create` no longer rejects placeholder-looking JWK values explicitly; placeholder validation was disabled for transition/testing.
- Improved OpenAPI examples for `_verify` and `_create`:
  - Added explicit legacy v1 `_create` example with full keys.
  - Added `_verify` example with controller JWK binding.
  - Unified controller key sample values across recommended examples.
- Updated `GET _retrieve` query semantics and docs:
  - `identifier` and `taxId` both accepted.
  - If both are sent, server tries `identifier` first and falls back to `taxId`.

# 0.7.5 - 2026-03-30

- Added separated credential retrieval flow with async `POST _retrieve` + `POST _retrieve-response` and direct `GET _retrieve` output negotiation (`application/vc+json` or `application/vc+jwt`).
- Added `identifier` alias support for `taxId` in credential retrieval/search inputs.
- Added versioned retrieval semantics: `version=v1` returns first stored snapshot, `version=v2` returns deterministic regenerated output based on latest stored verification lineage.
- Updated OpenAPI/Swagger for retrieval endpoints and improved examples for `GET _retrieve` responses (`200/400/404`).

# 0.7.4 - 2026-03-29

- Fixed organization tax ID normalization in VC generation to emit VAT format (`VATES-<id>` for ES) instead of `ES-<id>` fallbacks when identity comes from annex/PDF fields.
- Fixed discovery export VAT folder normalization to avoid `VATES-ES-...` directory names and keep canonical `VATES-...`.
- Updated procurement/natural-person certificate flow tests to assert canonical VAT output.

# 0.7.1 – 2026-03-26

- VC issuer (`did:jwt`) is always derived from the ICA key.
- For production, the issuer is a `did:web`; the DID Document is always `did:web` with `alsoKnownAs` containing the `did:jwt`.
- Tests now use a real EC P-384 key fixture, ensuring robust and reliable test results.
- Refactored test setup to activate the correct key only where required.
- All relevant tests pass with the new key management logic.


## 2026-03-26 17:15 CET

- Added `scripts/firestore-vat-manager.mjs` to inspect and delete documents by VAT across ICA collections.
- Added `scripts/verify-and-create.mjs` smoke test for ICA `_verify` + `_create`.
- Updated smoke test to support `--cleanup-before`, `--cleanup-after`, and `--cleanup-always`.
- Added `scripts/README.md` with usage examples and cleanup guidance.
