# PostgreSQL And IPFS Gap To Match GW

## Purpose

This note records what `dataspace-ica-ts` still needs in order to offer the
same operational profile that GW now supports:

- `DB_PROVIDER=postgres`
- `STORAGE_PROVIDER=ipfs`

The goal here is precision, not aspiration. The list below reflects the code
that exists today in this repository.

## Current State

Today ICA has code-level support for that target profile, but it is not yet a
fully closed operational track.

What already exists:

- deterministic evidence/document identifiers already use IPFS-style `ipfs://`
  attachment URLs in several verification and retrieve flows
- confidential-at-rest protection already exists for persisted signed adhesion
  contracts for the dataspace
- runtime config tests already cover:
  - `DB_PROVIDER=postgres`
  - `DB_PROVIDER=firestore`
  - `STORAGE_PROVIDER=ipfs`
  - `STORAGE_PROVIDER=gcs`
  - `STORAGE_PROVIDER=mem`
- runtime code now accepts:
  - `DB_PROVIDER=postgres`
  - `STORAGE_PROVIDER=ipfs`

Important:

- This note is not proposing legacy storage/runtime modes as architecture,
  roadmap, or GW/GW Template alignment.
- The target profile for this gap remains strictly:
  - `DB_PROVIDER=postgres`
  - `STORAGE_PROVIDER=ipfs`

Primary enforcement points:

- `src/api/tools/audit-document-storage.ts`
- `src/api/tools/verification-collections-storage.ts`
- `src/api/types.ts`
- `src/api/openapi.ts`
- `test/api.runtime-config.test.ts`

## What Already Helps

Some existing behavior reduces the future migration cost:

- `DETERMINISTIC_VC_BY_CONTRACT=true` already emits `ipfs://<cid>`-style
  evidence attachment URLs in the business contract
- retrieval/search flows already understand that the logical evidence locator
  may be `ipfs://...` instead of legacy `urn:audit:gcs:...`
- the confidential-storage ADR already separates ICA from GW's full
  per-document CEK model, so adding IPFS does not require copying all GW
  cryptographic persistence semantics first

That means the main storage/provider implementation is now present. The
remaining gap is mostly around operator support and deeper validation.

## Required Changes

To reach real support parity with GW, ICA still needs all of the following.

### 1. Harden PostgreSQL support

Code support exists now, but it still needs stronger validation and operator
guidance.

Remaining work:

- validate schema management for:
  - issued credentials
  - evidence records
  - DID bindings
  - DID documents
- verify current query semantics used by:
  - credential retrieve
  - credential search
  - credential status/revoke
  - terms remove
  - dataspace sync follow-up persistence
- add integration tests for the PostgreSQL provider
- document expected connection/bootstrap requirements for operators

### 2. Harden IPFS adhesion-contract storage support

Code support exists now, but the IPFS path still needs runtime hardening.

Remaining work:

- validate the Kubo-backed storage adapter for persisted signed adhesion
  contracts under real operator conditions
- confirm and document required env vars:
  - `IPFS_API_URL`
  - `IPFS_GATEWAY_URL`
  - `IPFS_MFS_ROOT`
- decide the canonical persisted locator policy:
  - external/public `ipfs://<cid>`
  - internal mutable path if needed for local management
- add one live E2E smoke for `upload -> retrieve/delete`

### 3. Keep the first scope limited to adhesion contracts only

This was the point that needed clarification.

ICA currently uses storage only for verified signed adhesion contracts, via
`AuditDocumentStorageService`.

For the first parity pass, do not generalize this into a generic blob-storage
initiative.

Expected first-pass scope:

- keep ICA storage scoped to verified signed adhesion contracts
- add IPFS only for that existing adhesion-contract persistence path
- do not introduce a broader multi-artifact storage abstraction unless a later
  concrete requirement appears

Why:

- it matches the current ICA architecture
- it is the shortest path to real `postgres + ipfs` support
- it avoids reopening scope around unrelated confidential artifacts

### 4. Add local operator support

GW support is not only code; it also includes a runnable local profile.

ICA still needs equivalent operator assets:

- `docker-compose.ipfs.yml`
- optional `docker-compose.postgres.yml` if not already present elsewhere
- a local env example dedicated to `postgres + ipfs`
- startup scripts/README flow for that profile

Without this, the feature would exist only as code, not as a supported path.

### 5. Extend the test matrix

Current tests now prove config parsing for `postgres` and `ipfs`, but not full
end-to-end operator behavior.

To claim support parity, ICA should add:

- integration tests for the PostgreSQL collections adapter
- unit/integration tests for the IPFS audit storage adapter
- one live E2E smoke with local Kubo

## Recommended Implementation Order

The least risky order is:

1. verify the merged PostgreSQL adapter under integration tests
2. verify the merged IPFS adapter with local Kubo smoke coverage
3. add local env/compose assets
4. document the supported operator profile

This keeps the contract honest and avoids documenting unsupported env
combinations too early.

## Non-Goals For The First Pass

The first parity pass does not need to include:

- migration of ICA to GW's full CEK-per-document storage model
- replacement of all Firestore/GCS paths in staging/production
- retroactive migration of historical GCS audit blobs into IPFS
- expansion beyond the current ICA signed-adhesion-contract storage scope

## Bottom Line

`dataspace-ica-ts` now has code support for `PostgreSQL + IPFS`, but it still
needs operator assets and deeper integration/E2E validation before that profile
is fully closed as a supported path.

The missing pieces are concrete and bounded:

- env/operator assets
- deeper integration/E2E coverage
- final operator-facing documentation
