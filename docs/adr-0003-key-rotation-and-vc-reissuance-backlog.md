# ADR 0003: Key Rotation And VC Re-Issuance Backlog

## Status

Accepted as backlog guidance

## Date

2026-05-29

## Context

ICA already exposes `_rotate` routes for credential and communication key
lifecycle, but they are still stubs and do not yet define the full end-to-end
trust flow required for production maturity.

The missing design is not jurisdiction-specific. It exists regardless of the
final trust registry or ledger implementation.

## Decision

ICA will keep the current rotation routes in pre-`1.0.0` status until the
following flow is specified and implemented:

1. Tenant or hosting operator requests key rotation.
2. Request proves possession of:
   - the old authorized signing key
   - the new candidate signing key
3. ICA validates controller/business authorization for the change.
4. ICA re-issues the affected VC(s) or trust artifact(s).
5. ICA records the trust-state transition through a ledger/trust-registry
   adapter.

## Non-Goals For This ADR

- Choosing a jurisdiction-specific ledger implementation
- Fixing the integration to Hyperledger Fabric only
- Fixing the integration to Pontus-X only

## Required Future Design Items

### 1. Rotation proof model

Define the payload and proof semantics for:

- old key possession proof
- new key possession proof
- controller/operator authorization proof

### 2. VC re-issuance semantics

Define:

- whether rotation produces a new VC identifier
- how previous VC status is superseded or revoked
- how relying parties resolve the current valid key set

### 3. DID document update semantics

Define:

- when the DID document changes
- how key continuity is represented
- whether old verification methods remain published during grace periods

### 4. Ledger/trust-registry adapter

Keep this layer jurisdiction-agnostic in the documentation for now.

Use neutral wording such as:

- trust registry
- ledger adapter
- external verifiable registry

This preserves room for different backends without changing the ICA contract.

## Release Policy Consequence

ICA should continue through `0.9.x`, `0.10.x`, and later pre-`1.0.0` releases
until the lifecycle above is no longer a stub and is backed by real
re-issuance/state-transition behavior.
