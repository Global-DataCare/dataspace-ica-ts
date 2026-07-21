import assert from 'node:assert/strict';
import test from 'node:test';
import {
  VerifyTermsCreateReadiness,
  VerifyTermsGeneratedAnnexFieldNames,
  VerifyTermsGwtemplateTodoChecklist,
  VerifyTermsParticipantAdditionalTypeRules,
  VerifyTermsParticipantCapabilityToken,
  VerifyTermsParticipantCapabilityToServiceType,
  VerifyLegalOrgTermsPdfFieldName,
  VerifyTermsIdentityPdfFieldNames,
  VerifyTermsPdfFieldName,
  VerifyTermsServiceCapability,
} from '../src/api/models/verify-terms-fields.ts';
import type { LegalOrgFormTemplateFields } from '../src/api/models/verify-terms-fields.ts';

test('VerifyTermsGeneratedAnnexFieldNames exports the canonical generated annex field list', () => {
  assert.deepEqual(VerifyTermsGeneratedAnnexFieldNames, [
    VerifyTermsPdfFieldName.organizationAdditionalType,
    VerifyTermsPdfFieldName.organizationSameAs,
    VerifyTermsPdfFieldName.organizationUrl,
    VerifyTermsPdfFieldName.organizationAlternateName,
    VerifyTermsPdfFieldName.organizationRegistrationNumber,
    VerifyTermsPdfFieldName.personEmail,
    VerifyTermsPdfFieldName.personAlternateName,
    VerifyTermsPdfFieldName.personAdditionalType,
  ]);
});

test('VerifyTermsPdfFieldName includes identifierType and identifierValue replacement fields', () => {
  assert.equal(VerifyTermsPdfFieldName.organizationIdentifierType, 'organization.identifierType');
  assert.equal(VerifyTermsPdfFieldName.organizationIdentifierValue, 'organization.identifierValue');
});

test('VerifyTermsIdentityPdfFieldNames exports the canonical identity field list used by verification', () => {
  assert.deepEqual(VerifyTermsIdentityPdfFieldNames, [
    VerifyLegalOrgTermsPdfFieldName.organizationTaxID,
    VerifyLegalOrgTermsPdfFieldName.organizationLegalName,
    VerifyLegalOrgTermsPdfFieldName.organizationName,
    VerifyLegalOrgTermsPdfFieldName.representativeLegalFullName,
    VerifyLegalOrgTermsPdfFieldName.representativeLegalIdentifier,
    VerifyLegalOrgTermsPdfFieldName.personGivenName,
    VerifyLegalOrgTermsPdfFieldName.personFamilyName,
  ]);
});

test('VerifyTermsServiceCapability keeps the exact capability values expected downstream', () => {
  assert.deepEqual(VerifyTermsServiceCapability, {
    IndexReader: 'organization/Composition.rs',
    IndexProvider: 'organization/Composition.cruds',
    DigitalTwinReader: 'organization/ResearchSubject.rs',
    DigitalTwinProvider: 'organization/ResearchSubject.cruds',
  });
});

test('VerifyTermsParticipantCapabilityToServiceType maps UI tokens to canonical serviceType values', () => {
  assert.equal(
    VerifyTermsParticipantCapabilityToServiceType[VerifyTermsParticipantCapabilityToken.IndexReader],
    VerifyTermsServiceCapability.IndexReader,
  );
  assert.equal(
    VerifyTermsParticipantCapabilityToServiceType[VerifyTermsParticipantCapabilityToken.IndexProvider],
    VerifyTermsServiceCapability.IndexProvider,
  );
  assert.equal(
    VerifyTermsParticipantCapabilityToServiceType[VerifyTermsParticipantCapabilityToken.DigitalTwinReader],
    VerifyTermsServiceCapability.DigitalTwinReader,
  );
  assert.equal(
    VerifyTermsParticipantCapabilityToServiceType[VerifyTermsParticipantCapabilityToken.DigitalTwinProvider],
    VerifyTermsServiceCapability.DigitalTwinProvider,
  );
});

test('VerifyTermsParticipantAdditionalTypeRules captures agreed token constraints', () => {
  assert.equal(VerifyTermsParticipantAdditionalTypeRules.maxItems, 2);
  assert.equal(VerifyTermsParticipantAdditionalTypeRules.requireAtLeastOneToken, true);
  assert.deepEqual(VerifyTermsParticipantAdditionalTypeRules.indexFamily, [
    VerifyTermsParticipantCapabilityToken.IndexReader,
    VerifyTermsParticipantCapabilityToken.IndexProvider,
  ]);
  assert.deepEqual(VerifyTermsParticipantAdditionalTypeRules.digitalTwinFamily, [
    VerifyTermsParticipantCapabilityToken.DigitalTwinReader,
    VerifyTermsParticipantCapabilityToken.DigitalTwinProvider,
  ]);
});

test('VerifyTermsCreateReadiness documents the create-binding prerequisites', () => {
  assert.equal(VerifyTermsCreateReadiness.authoritativeSectorSource, 'route');
  assert.deepEqual(
    VerifyTermsCreateReadiness.requiredPdfIdentityFieldsWhenCertificateOmitsOrganizationIdentity,
    [
      VerifyTermsPdfFieldName.organizationTaxID,
      VerifyTermsPdfFieldName.organizationLegalName,
    ],
  );
  assert.equal(
    VerifyTermsCreateReadiness.preferredControllerBindingPath,
    'body.data[].resource.controller.publicKeyJwk',
  );
});

test('VerifyTermsGwtemplateTodoChecklist includes OrganizationCredential-first controller email rule', () => {
  assert.equal(
    VerifyTermsGwtemplateTodoChecklist.some((item) => item.includes('contactPoint.email')),
    true,
  );
  assert.equal(
    VerifyTermsGwtemplateTodoChecklist.some((item) => item.includes('participant.additionalType')),
    true,
  );
  assert.equal(
    VerifyTermsGwtemplateTodoChecklist.some((item) => item.includes('hostingOrganization.url')),
    true,
  );
});

test('LegalOrgFormTemplateFields exposes the raw string-based form contract', () => {
  const sample: LegalOrgFormTemplateFields = {
    organizationTaxID: 'B12345678',
    organizationLegalName: 'Example Legal Org SL',
    representativeLegalFullName: 'Jane Example',
  };

  assert.equal(typeof sample.organizationTaxID, 'string');
  assert.equal(typeof sample.organizationLegalName, 'string');
  assert.equal(typeof sample.representativeLegalFullName, 'string');
});