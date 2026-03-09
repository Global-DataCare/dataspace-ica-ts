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

- `organization.additionalType`
- `organization.did`
- `organization.sameAs`
- `organization.alternateName`
- `organization.registrationNumber`
- `legalRepresentative.email`
- `controller.email`
- `controller.kid`
- `controller.alg`
- `controller.publicKeyJwk`

## Runtime extraction during `_verify`

When a signed PDF contains these form fields, the API extracts them and carries them through verification:

- `VerifyResult.annexFormFields` includes the extracted name/value map.
- `document_details.annexFormFields` inside evidence `type=document` includes the same map.
- VC mapping uses these fields:
  - `organization.did` / `organization.sameAs` -> `credentialSubject.id` and `sameAs` (organization VC).
  - `organization.additionalType` -> `credentialSubject.additionalType`.
  - `organization.alternateName` -> `credentialSubject.alternateName`.
  - `organization.registrationNumber` -> `credentialSubject.registrationNumber`.
  - `legalRepresentative.email` -> person VC `credentialSubject.email` (preferred over certificate email).
  - `controller.*` -> `credentialSubject.controller` and evidence `document_details.controller`.

DCAT publication remains strict: only real organization `did:web` is used as publisher; internal ICA membership aliases are excluded as publisher DID.
