# TODO for gwtemplate-node-ts: VC Consumption Priority in _activate/_transaction

## Scope

Document and implement VC-consumption rules for `_activate` and `_transaction` so controller identity and service capability are consistently taken from OrganizationCredential first when available.

## Priority Rules

1. Controller email source priority
- Primary: `OrganizationCredential.credentialSubject.contactPoint.email`
- Fallback: representative identity from `LegalRepresentativeCredential` (`credentialSubject.sameAs` or legacy email source)
- Rationale: signer legal representative may differ from the organization controller who performs key binding/reissue.

2. Participant/service capability source
- Source: `OrganizationCredential.credentialSubject.participant.additionalType`
- Semantics: comma-separated token list using domain tokens:
  - `IndexReader` or `IndexProvider` or none
  - `DigitalTwinReader` or `DigitalTwinProvider` or none
- Constraints:
  - max 2 tokens total
  - max 1 token from Index family
  - max 1 token from DigitalTwin family
  - at least 1 token is required
- Mapping to persisted service values (`Service.serviceType`):
  - `IndexReader` -> `organization/Composition.rs`
  - `IndexProvider` -> `organization/Composition.cruds`
  - `DigitalTwinReader` -> `organization/ResearchSubject.rs`
  - `DigitalTwinProvider` -> `organization/ResearchSubject.cruds`

3. Hosting target source
- `OrganizationCredential.credentialSubject.hostingOrganization.url`: domain/IP where `_activate` / `_transaction` targets the hosting side
- `OrganizationCredential.credentialSubject.hostingOrganization.identifier`: hosting provider VAT/tax identifier

4. Sector source
- Source: `OrganizationCredential.credentialSubject.makesOffer.category`
- Note: in ICA generation, route sector is authoritative and may fallback into this field in demo mode.

## Backward Compatibility

- Keep existing representative-based fallback until all OrganizationCredential producers include `contactPoint.email`.
- If both sources exist and differ, log diagnostic metadata and prefer OrganizationCredential.

## Suggested Test Cases in gwtemplate-node-ts

1. Uses OrganizationCredential contactPoint email when it differs from representative email.
2. Falls back to LegalRepresentativeCredential when OrganizationCredential contactPoint email is absent.
3. Rejects invalid participant token combinations (more than 2, both Index variants, both DigitalTwin variants, zero tokens).
4. Correctly maps participant tokens to canonical serviceType values.
5. Uses hostingOrganization url/identifier in activation/transaction request routing.
6. Uses makesOffer.category as sector context.

## Contract Reference

The typed source contract maintained in dataspace-ica-ts is:
- `src/api/models/verify-terms-fields.ts`
- especially `VerifyTermsOrganizationCredentialFieldHints`, `VerifyTermsParticipantAdditionalTypeRules`, and `VerifyTermsGwtemplateTodoChecklist`.
