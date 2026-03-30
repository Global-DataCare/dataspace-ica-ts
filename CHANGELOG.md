# Changelog

# 0.8.1 - 2026-03-30

- Added OCR runtime support for contract identity fallback:
  - Local/runtime extraction can use `pdftoppm + tesseract` when visible/form text is insufficient.
  - Added OCR language coverage for ES/PT/EN in container build.
- Improved organization identity extraction rules for ProcureData contracts:
  - `Razón Social` is mapped as organization legal name.
  - `CIF/NIF/NIPC` is mapped as organization VAT/tax identifier.
  - `Representante legal` is extracted and propagated to annex/person fallback mapping.
  - If fiscal domicile indicates Portugal, generated VAT prefix switches to `VATPT-...` (even in ES jurisdiction routes).
- Improved tax normalization and routing consistency:
  - `_verify` parsing uses route jurisdiction consistently.
  - `vc-bundle` preserves explicit VAT country prefixes (`VATPT-*`, `VATES-*`) without duplicating/reprefixing.
- Added/updated tests for OCR text parsing and PT fiscal domicile VAT behavior.

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
