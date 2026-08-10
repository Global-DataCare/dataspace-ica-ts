# dataspace-ica docs

This directory is the curated documentation entrypoint for developers and operators.

## Reading order

1. [`01-introduction/01-overview.md`](./01-introduction/01-overview.md)
2. [`02-setup-and-run/01-local-quickstart.md`](./02-setup-and-run/01-local-quickstart.md)
3. [`02-setup-and-run/02-configuration.md`](./02-setup-and-run/02-configuration.md)
4. [`03-api-and-flows/01-key-endpoints.md`](./03-api-and-flows/01-key-endpoints.md)
5. [`03-api-and-flows/02-core-flows.md`](./03-api-and-flows/02-core-flows.md)
6. [`04-examples-and-tests/01-examples-fixtures-and-tests.md`](./04-examples-and-tests/01-examples-fixtures-and-tests.md)
7. [`05-operations-and-deployment/01-gke-and-security.md`](./05-operations-and-deployment/01-gke-and-security.md)
8. [`06-architecture-and-reference/02-postgres-ipfs-gap.md`](./06-architecture-and-reference/02-postgres-ipfs-gap.md)
9. [`06-architecture-and-reference/03-fabric-credential-registry.md`](./06-architecture-and-reference/03-fabric-credential-registry.md)
10. [`06-architecture-and-reference/04-root-ca-and-ica-signing-trust.md`](./06-architecture-and-reference/04-root-ca-and-ica-signing-trust.md)
11. [`06-architecture-and-reference/05-legal-organization-controller-binding-handoff.md`](./06-architecture-and-reference/05-legal-organization-controller-binding-handoff.md)

## Numbered sections

- `01-introduction`
  product context, scope, terminology, and navigation
- `02-setup-and-run`
  local startup, environment configuration, and first verification steps
- `03-api-and-flows`
  key endpoints and the main business/security flows
- `04-examples-and-tests`
  fixtures, example payloads, and tests to read as executable documentation
- `05-operations-and-deployment`
  deployment and production operation concerns
- `06-architecture-and-reference`
  architecture notes and pointers to existing deep dives
  including the current gap to reach GW-style `PostgreSQL + IPFS` support

## Existing detailed docs

Some older deep-dive documents still remain at `docs/` root, for example:

- `organization-key-binding-v2.md`
- `organization-key-management.md`
- `pontusx-integration.md`
- environment-specific security and troubleshooting runbooks are intentionally
  maintained outside this source repository
- `backend-auth-migration.md`

Those are still valid references, but new top-level guidance should be added to the numbered sections first.

## Current ICA documentation scope

- For animal-domain examples in ICA docs, keep the current documented scope limited to `animal-pet-global`.
- Do not expand ICA docs here into finer veterinary segmentation such as wild/farm/terrestrial/marine/aerial.
- That finer taxonomy belongs to domain-extension SDKs and higher-level architecture notes.
- Do not lock regional naming strategy in ICA docs yet unless it is required by an implemented contract.
