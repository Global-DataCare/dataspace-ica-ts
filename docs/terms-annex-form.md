# Terms & Conditions Annex PDF

This service now includes a local generator for a Terms & Conditions annex PDF with predefined AcroForm fields.

## Generate annex PDF from text

```bash
npm run create:terms:pdf -- \
  --text-file ./docs/examples/terms-annex.es.md \
  --out ./artifacts/terms-annex.pdf \
  --values-json ./docs/examples/terms-annex-values.example.json \
  --title "Términos y Condiciones - Anexo de Identidad"
```

`--text-file` accepts Markdown (`.md`/`.markdown`) or plain text.

## Predefined field names

Field lookup is case-insensitive on read, so `Organization.sameAs` and `organization.sameAs` are both accepted. The canonical names remain the lowercase ones below.

For a machine-readable catalog that also includes visible identity fields and accepted aliases, see `docs/examples/terms-annex-field-catalog.json`.
For a typed TypeScript contract similar to `IndividualFormTemplateFields`, see `LegalOrgFormTemplateFields` in `src/api/models/verify-terms-fields.ts`.
For downstream GW `_activate/_transaction` TODOs and consumption priority rules, see `docs/gwtemplate-node-ts-vc-consumption-todo.md`.

- `organization.additionalType`
- `organization.sameAs`
- `organization.url`
- `organization.alternateName`
- `organization.registrationNumber`
- `person.email`
- `person.alternateName`
- `person.additionalType`

### Identifier note

- `organization.registrationNumber` is treated as legacy compatibility in the programming contract.
- Preferred optional model: `organization.identifierType` + `organization.identifierValue` (mapped to `Organization.identifier.propertyID` and `Organization.identifier.value`).
- `organization.taxID` remains the mandatory organization identity anchor for onboarding.

## Route sector and serviceType

- `sector` is not a PDF field. The authoritative value comes from the route path `/cds-{jurisdiction}/v1/{sector}/...`.
- `serviceType` is not currently extracted from the annex AcroForm fields.
- Today, if you need `OrganizationCredential.credentialSubject.makesOffer.serviceType`, send it through `organizationPayload.serviceType` or `organizationPayload.makesOffer.serviceType` in compat/demo flows.
- Supported downstream capability values are documented in `src/api/models/verify-terms-fields.ts` as `VerifyTermsServiceCapability`.
- Proposed next PDF/interface extensions are also documented in that file:
  - `organization.contactPoint.email`
  - `organization.participant.additionalType`
  - `organization.hostingOrganization.url`
  - `organization.hostingOrganization.identifier`

## What matters for later `_create`

- If you want `_verify` output to be reusable by `entity/did/document/_create`, send `body.data[].resource.controller.publicKeyJwk` during `_verify`.
- The organization credential-signing key can be sent as an `application/jwk+json` attachment, but if omitted ICA can generate an ES384 keypair and return it in `_verify-response`.
- When the signer certificate does not expose organization identity, the PDF must expose `organization.taxID` and `organization.legalName`.

## Runtime extraction during `_verify`

When a signed PDF contains these form fields, the API extracts them and carries them through verification:

- `VerifyResult.annexFormFields` includes the extracted name/value map.
- `document_details.annexFormFields` is intentionally not emitted in VCs/public exports.
- VC mapping uses these fields:
  - `credentialSubject.id` (organization VC) is the canonical dataspace-member DID derived as
    `did:web:<ORG_PUBLIC_DOMAIN_NODE_OPERATOR>:<sector>:organization:taxid:<VATES-NIF>`.
    Default public domain is `globaldatacare.es`.
  - `organization.sameAs` -> `credentialSubject.sameAs` when present and different from the canonical dataspace-member DID.
    Use it for an alternative real organization DID, for example `did:web:provider.example.org`.
  - `organization.url` -> `credentialSubject.url` (stored as bare domain, without `http(s)://`).
  - `organization.additionalType` -> `credentialSubject.additionalType`.
    Used as a flattened profile string such as `sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider`.
  - `organization.alternateName` -> `credentialSubject.alternateName`.
    Used for the short organization alias such as `acme`, not for the DID.
  - `organization.registrationNumber` -> `credentialSubject.registrationNumber`.
  - `person.email` -> person VC `credentialSubject.sameAs` (preferred over certificate email).
    If it arrives as plain email, backend hashes it automatically to `urn:multibase:z...` so the plain value is not persisted.
  - actor binding JWK captured during `_verify` -> the VC of the actor that
    submitted it (the legal representative in the legacy portal flow)
    `credentialSubject.hasCredential.material`.
    ICA prefers an RFC 9278 JWK-thumbprint URN
    `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url>` when the public
    JWK exposes enough material; otherwise it falls back to the existing JWK
    `kid`.
  - representative proof is intentionally two-dimensional:
    `credentialSubject.sameAs` proves public identity continuity, while
    `credentialSubject.hasCredential.material` proves continuity of the
    controller signing/binding key. Production-grade VCs should ideally carry
    both dimensions.
  - `person.alternateName` -> person VC `credentialSubject.alternateName`.
    Used for the controller `kid`. We use `alternateName` instead of `nickname` to stay within the agreed schema.org Organization/Person subset already used here.
  - `person.additionalType` -> person VC `credentialSubject.additionalType`.
    Used for the controller key algorithm, for example `ES384`.

DCAT publication remains strict: only real organization `did:web` is used as publisher; internal ICA membership aliases are excluded as publisher DID.

Recommended step by step:

1. Put representative email in `person.email` inside the signed annex whenever possible.
2. `_verify` derives representative `credentialSubject.sameAs` from that signed email evidence or, secondarily, from the signer certificate email.
3. `_verify` derives representative `credentialSubject.hasCredential.material` from the captured controller binding JWK.
   A distinct `organization.contactPoint.email` is only a hashed pending
   controller designation unless the request explicitly supplies a matching
   `controllerSameAs` with that controller's own JWK.
4. Only in `demo/local`, if signed sources do not expose the email, `legalRepresentativePayload.email` or `.sameAs` may bootstrap the representative alias.
5. Downstream GW activation should ideally receive a representative VC that already carries both dimensions.
6. A separately designated technical controller completes its own `_issue`,
   key binding and DCR later from the sector portal; ICA must never copy the
   representative's JWK to that actor.
