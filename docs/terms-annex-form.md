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
- `person.email`
- `person.alternateName`
- `person.additionalType`

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
  - controller binding JWK captured during `_verify` -> person VC
    `credentialSubject.hasCredential.material`.
    ICA prefers an RFC 9278 JWK-thumbprint URN
    `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url>` when the public
    JWK exposes enough material; otherwise it falls back to the existing JWK
    `kid`.
  - `person.alternateName` -> person VC `credentialSubject.alternateName`.
    Used for the controller `kid`. We use `alternateName` instead of `nickname` to stay within the agreed schema.org Organization/Person subset already used here.
  - `person.additionalType` -> person VC `credentialSubject.additionalType`.
    Used for the controller key algorithm, for example `ES384`.

DCAT publication remains strict: only real organization `did:web` is used as publisher; internal ICA membership aliases are excluded as publisher DID.
