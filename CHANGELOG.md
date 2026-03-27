# 0.7.1 – 2026-03-26

- Deterministic VC issuer (`did:jwt`) is now always derived from the ICA bootstrap key, never from environment variables.
- In production, the issuer is a `did:web`; the DID Document is always `did:web` with `alsoKnownAs` containing the `did:jwt`.
- There is always an active signing key (deterministic or random); process never fails for lack of a key.
- Tests now use a real EC P-384 key fixture for deterministic and evidence scenarios, ensuring robust and reliable test results.
- Refactored test setup to activate the correct key only where required.
- All relevant tests pass with the new key management logic.
# Changelog

## 2026-03-26 17:15 CET

- Added `scripts/firestore-vat-manager.mjs` to inspect and delete Firestore documents by VAT across ICA collections.
- Added `scripts/verify-and-create.mjs` smoke test for ICA `_verify` + `_create`.
- Updated smoke test to support `--cleanup-before`, `--cleanup-after`, and `--cleanup-always`.
- Added `scripts/README.md` with usage examples and cleanup guidance.
