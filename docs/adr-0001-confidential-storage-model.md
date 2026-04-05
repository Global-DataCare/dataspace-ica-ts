# ADR-0001: Confidential Storage Model Scope (GW vs ICA/DataConv)

## Status
Accepted - 2026-04-05

## Context
There are two valid confidentiality patterns in the platform:

1. GW confidential-document model (high granularity):
- random CEK per document (AES-GCM)
- CEK wrapped/protected with tenant key material
- tenant key material protected by host key/KMS/HSM

2. ICA/DataConv lightweight model (current scope):
- encryption at rest using tenant+purpose derived key material
- host seed/secret resolved via secure provider (GCP Secret Manager) with encrypted runtime cache
- no per-document CEK lifecycle yet

The question is whether ICA/DataConv must immediately adopt the full GW model.

## Decision
For ICA/DataConv, keep the lightweight tenant+purpose model by default, and do not require immediate CEK-per-document rollout.

Rationale:
- lower operational complexity for current ICA/DataConv risk profile
- faster delivery and simpler incident handling
- avoids introducing early key-lifecycle overhead where not required yet

## Scope
This ADR applies to:
- ICA service
- Data Conversion API

This ADR does not change GW, which keeps its confidential-document model.

## Security Baseline (required)
Even in lightweight mode:
- at-rest encryption must be enabled for sensitive artifacts
- keys/seeds must not be shared in plaintext `.env` across teams
- cloud secret provider + IAM + audit logging must be used in staging/production
- runtime cache must be encrypted in memory and bounded with TTL/stale policy
- key versioning/rotation path must exist

## Escalation Criteria to GW-like Model
Move ICA/DataConv to CEK-per-document + wrapping when any of these is true:
- regulatory/audit requirement explicitly mandates per-record/document key separation
- high-volume multi-tenant data with strong blast-radius constraints
- requirement for fine-grained crypto revocation per document
- formal threat model identifies tenant+purpose key scope as insufficient
- external compliance assessment flags current model as non-sufficient

## Consequences
Positive:
- pragmatic and consistent baseline across services
- reduced delivery risk now

Tradeoff:
- weaker crypto granularity vs GW until escalation criteria are met

## Implementation Notes
Current ICA implementation aligns with this ADR by:
- using secure secret resolution (file/env indirection + GCP Secret Manager option)
- enabling encrypted runtime cache for host secrets
- supporting confidential audit PDF persistence with tenant-scoped encryption

Next optional step (if criteria trigger):
- introduce CEK-per-document envelope encryption in ICA/DataConv, mirroring GW.

