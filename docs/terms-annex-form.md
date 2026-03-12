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

- `organization.additionalType`
- `organization.sameAs`
- `organization.url`
- `organization.alternateName`
- `organization.registrationNumber`
- `organization.email`
- `person.email`
- `person.alternateName`
- `person.additionalType`

## Runtime extraction during `_verify`

When a signed PDF contains these form fields, the API extracts them and carries them through verification:

- `VerifyResult.annexFormFields` includes the extracted name/value map.
- `document_details.annexFormFields` inside evidence `type=document` includes the same map.
- VC mapping uses these fields:
  - `organization.sameAs` -> `credentialSubject.id` and `sameAs` (organization VC, when it is a `did:web`).
  - `organization.url` -> `credentialSubject.url` (stored as bare domain, without `http(s)://`).
  - `organization.additionalType` -> `credentialSubject.additionalType`.
    Used as a flattened profile string such as `sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider`.
  - `organization.alternateName` -> `credentialSubject.alternateName`.
    Used for the short organization alias such as `acme`, not for the DID.
  - `organization.registrationNumber` -> `credentialSubject.registrationNumber`.
  - `organization.email` -> organization VC `credentialSubject.email`.
    Used for the organization contact hash/email.
  - `person.email` -> person VC `credentialSubject.email` (preferred over certificate email).
    Used for the controller hash/email.
  - `person.alternateName` -> person VC `credentialSubject.alternateName`.
    Used for the controller `kid`. We use `alternateName` instead of `nickname` to stay within the agreed schema.org Organization/Person subset already used here.
  - `person.additionalType` -> person VC `credentialSubject.additionalType`.
    Used for the controller key algorithm, for example `ES384`.

DCAT publication remains strict: only real organization `did:web` is used as publisher; internal ICA membership aliases are excluded as publisher DID.
