# Changelog

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
- Added `ICA_VERIFY_DEFER_VISIBLE_EXTRACTION=true` to ProcureData deploy/local env files so fallback extraction still runs, but no longer blocks `_verify` request response.

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
- Updated tests for ProcureData/natural-person certificate flows to assert canonical VAT output.

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
