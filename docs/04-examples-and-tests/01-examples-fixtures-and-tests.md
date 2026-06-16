# 01 Examples, Fixtures, and Tests

## Why developers should read tests here

In this repo, the `api.*.test.ts` files are one of the best sources of truth for:

- supported payload shapes
- expected endpoint behavior
- compatibility rules
- edge cases and regression coverage

## High-value tests

- [`../../test/api.verify.test.ts`](../../test/api.verify.test.ts)
  `_verify` flow and response behavior
- [`../../test/api.activation-keys.test.ts`](../../test/api.activation-keys.test.ts)
  `_activate` parsing and key activation flow
- [`../../test/api.did-document-create.test.ts`](../../test/api.did-document-create.test.ts)
  DID document creation and trust material behavior
- [`../../test/api.dcat-catalog.test.ts`](../../test/api.dcat-catalog.test.ts)
  discovery/catalog output
- [`../../test/api.backend-auth.test.ts`](../../test/api.backend-auth.test.ts)
  backend auth migration-related behavior

## Example assets

- [`../examples/terms-annex.es.md`](../examples/terms-annex.es.md)
- [`../examples/terms-annex.es.txt`](../examples/terms-annex.es.txt)
- [`../examples/terms-annex-values.example.json`](../examples/terms-annex-values.example.json)
- [`../examples/verify-response-test-202603051133-0.3.6.json`](../examples/verify-response-test-202603051133-0.3.6.json)

## Useful commands

Generate an activation payload example:

```bash
npm run api:example:activate
```

Run the API tests:

```bash
npm run test
```

Run type checking:

```bash
npm run typecheck
```

## Suggested reading path for a new developer

1. Read the endpoint guide.
2. Open the matching `api.*.test.ts`.
3. Reuse example payloads from `docs/examples`.
4. Only then dig into `src/api`.
