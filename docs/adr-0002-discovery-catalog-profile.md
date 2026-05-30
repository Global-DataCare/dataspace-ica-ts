# ADR 0002: ICA Discovery Catalog Profile

## Status

Accepted

## Date

2026-05-29

## Context

ICA currently exposes operational discovery/catalog endpoints under:

- `/.well-known/dcat3/catalog`
- `/{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/request`
- `/{tenantId}/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/datasets/{id}`

At the same time, some previous work explored `HealthDCAT-AP Release 7` as a
profile reference.

That created ambiguity between:

1. the operational catalog baseline required for ICA/node operator discovery,
2. and a richer dataset metadata profile that may be appropriate only for some
   domains and publication scenarios.

## Decision

ICA adopts the following discovery/catalog baseline:

1. The operational baseline is `DCAT3`.
2. `/.well-known/dcat3/catalog` is an ICA platform convention for public
   operational discovery.
3. `HealthDCAT-AP Release 7` is not the default ICA interoperability baseline.
4. `HealthDCAT-AP Release 7` may be documented or added later as an optional
   dataset profile for domains that explicitly need it.

## Consequences

### Positive

- The ICA discovery contract stays small and operational.
- Dataspace member/operator discovery does not depend on health-specific
  metadata richness.
- Future non-health sectors are not forced into a health-specific profile.

### Negative

- Some richer metadata examples must remain outside the default operational
  discovery baseline.
- Additional profile documentation may be needed later for dataset-heavy use
  cases.

## Follow-up

1. Keep `DCAT3` as the default README/OpenAPI wording for operational
   discovery/catalog endpoints.
2. Treat any `HealthDCAT-AP` guidance as optional profile guidance, not as the
   baseline contract for ICA itself.
3. When common discovery DTOs mature in `gdc-common-utils-ts`, converge local
   catalog-specific helper types toward those shared contracts where practical.
