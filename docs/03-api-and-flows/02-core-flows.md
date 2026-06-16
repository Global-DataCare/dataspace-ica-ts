# 02 Core Flows

## Flow 1: Terms verification

Goal:

- ingest a signed Terms PDF
- verify trust/evidence details
- derive business output used by later onboarding steps

Typical sequence:

1. Client submits `_verify`
2. ICA accepts asynchronously with `202`
3. Client polls `_verify-response`
4. Final result returns a bundle with `body.data[]` and `body.issues`

Read next:

- detailed reference: [`../../README.md`](../../README.md)
- annex mapping: [`../terms-annex-form.md`](../terms-annex-form.md)
- tests: [`../../test/api.verify.test.ts`](../../test/api.verify.test.ts)

## Flow 2: Credential key activation

Goal:

- activate the ICA signing key material used for credential issuance and trust publication

Typical sequence:

1. Client submits `_activate`
2. Controller authorization proof is validated
3. Active key material is stored/activated
4. Client polls `_activate-response`

Read next:

- tests: [`../../test/api.activation-keys.test.ts`](../../test/api.activation-keys.test.ts)
- example generator: `npm run api:example:activate`

## Flow 3: Evidence ingestion and issuance lifecycle

Goal:

- add evidence
- issue credentials
- update status or revoke when needed

Relevant tests:

- [`../../test/api.vc-bundle.test.ts`](../../test/api.vc-bundle.test.ts)
- [`../../test/api.lifecycle-collections.test.ts`](../../test/api.lifecycle-collections.test.ts)
- [`../../test/api.terms-remove.test.ts`](../../test/api.terms-remove.test.ts)

## Flow 4: Discovery publication

Goal:

- expose `did.json`, `jwks.json`, and DCAT/discovery artifacts that other actors can resolve publicly

Relevant references:

- [`../adr-0002-discovery-catalog-profile.md`](../adr-0002-discovery-catalog-profile.md)
- [`../../test/api.dcat-catalog.test.ts`](../../test/api.dcat-catalog.test.ts)
- [`../../test/api.did-document-create.test.ts`](../../test/api.did-document-create.test.ts)
