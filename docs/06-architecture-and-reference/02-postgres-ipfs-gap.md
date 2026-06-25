# PostgreSQL And IPFS Gap To Match GW

## Purpose

This note records what `dataspace-ica-ts` still needs in order to offer the
same operational profile that GW now supports:

- `DB_PROVIDER=postgres`
- `STORAGE_PROVIDER=ipfs`

The goal here is precision, not aspiration. The list below reflects the code
that exists today in this repository.

## Current State

Today ICA is only partially aligned with that target profile.

What already exists:

- deterministic evidence/document identifiers already use IPFS-style `ipfs://`
  attachment URLs in several verification and retrieve flows
- confidential-at-rest protection already exists for persisted signed adhesion
  contracts for the dataspace
- runtime config tests already cover:
  - `DB_PROVIDER=firestore`
  - `STORAGE_PROVIDER=gcs`
  - `STORAGE_PROVIDER=mem`

What is still hard-limited in code:

- audit document storage supports only:
  - `none`
  - `filesystem`
  - `gcs`
- verification collections persistence supports only:
  - `mem`
  - `firestore`

Important:

- `filesystem` appears here only as part of the current code reality.
- It is not part of the target support profile for this gap.
- The target profile remains strictly:
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

That means the main missing work is storage/provider implementation, not
business-contract invention.

## Required Changes

To reach real support parity with GW, ICA still needs all of the following.

### 1. Add PostgreSQL as a real collections provider

Current limitation:

- `parseProvider(...)` in
  `src/api/tools/verification-collections-storage.ts` rejects anything except
  `mem` and `firestore`

Required work:

- add `postgres` to the provider union in the collections config/types
- implement a PostgreSQL adapter under
  `src/api/tools/verification-collections/adapters.ts` and related adapter
  types/files
- define schema management for:
  - issued credentials
  - evidence records
  - DID bindings
  - DID documents
- preserve current query semantics used by:
  - credential retrieve
  - credential search
  - credential status/revoke
  - terms remove
  - dataspace sync follow-up persistence
- add runtime config tests and integration tests for the PostgreSQL provider

### 2. Add IPFS as a real adhesion-contract storage provider

Current limitation:

- `parseAuditStorageMode(...)` in
  `src/api/tools/audit-document-storage.ts` only accepts `mem`, `none`,
  `filesystem`, or `gcs`
- `AuditStorageProvider` in `src/api/types.ts` only exposes `filesystem | gcs`
- OpenAPI also exposes only `filesystem` and `gcs`

Required work:

- add `ipfs` to the audit storage mode/parser/types/OpenAPI
- implement a Kubo-backed storage adapter for persisted signed adhesion
  contracts
- define required env vars, likely equivalent to GW:
  - `IPFS_API_URL`
  - `IPFS_GATEWAY_URL`
  - `IPFS_MFS_ROOT`
- decide the canonical persisted locator policy:
  - external/public `ipfs://<cid>`
  - internal mutable path if needed for local management
- add runtime tests plus one live E2E smoke for `upload -> retrieve/delete`

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

Current tests prove config parsing and business behavior mostly around
`mem`/`firestore` and legacy audit storage modes.

To claim support parity, ICA should add:

- config tests for `DB_PROVIDER=postgres`
- config tests for `STORAGE_PROVIDER=ipfs`
- integration tests for the PostgreSQL collections adapter
- unit tests for the IPFS audit storage adapter
- one live E2E smoke with local Kubo

## Recommended Implementation Order

The least risky order is:

1. add PostgreSQL collections provider
2. add IPFS audit storage provider
3. add local env/compose assets
4. add integration + E2E coverage
5. update OpenAPI and docs only after tests prove the path

This keeps the contract honest and avoids documenting unsupported env
combinations too early.

## Non-Goals For The First Pass

The first parity pass does not need to include:

- migration of ICA to GW's full CEK-per-document storage model
- replacement of all Firestore/GCS paths in staging/production
- retroactive migration of historical GCS audit blobs into IPFS
- expansion beyond the current ICA signed-adhesion-contract storage scope

## Bottom Line

`dataspace-ica-ts` is logically IPFS-aware at the business-contract layer, but
it is not yet operationally `PostgreSQL + IPFS` capable.

The missing pieces are concrete and bounded:

- a PostgreSQL collections adapter
- an IPFS audit storage adapter
- env/operator assets
- matching tests and OpenAPI/runtime documentation
