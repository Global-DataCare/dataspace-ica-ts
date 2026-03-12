import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVerifyRoute } from '../src/api/path.ts';
import { buildVerificationVcBundle } from '../src/api/server.ts';
import { resetActiveSigningKeysStateForTests } from '../src/api/tools/active-signing-keys.ts';
import type { VerifyResult } from '../src/api/types.ts';

function buildTestVerifyResult(label: string): VerifyResult {
  return {
    ok: true,
    verifiedAt: '2026-03-05T00:00:00.000Z',
    templateUrl: `https://example.test/${label}.pdf`,
    templateMatch: true,
    signatureValid: true,
    chainValid: true,
    revocationStatus: 'good',
    digest: {
      alg: 'sha3-384',
      signedPdfHex: 'a',
      unsignedPdfHex: 'b',
      templateHex: 'c',
    },
    signerCertificateSerialNumber: '00AA11',
    signerSubject: 'CN=Signer',
    signerIssuer: 'CN=FNMT',
    hashes: {
      signedPdfSha256Hex: 'a',
      unsignedPdfSha256Hex: 'b',
      templateSha256Hex: 'c',
    },
    notes: [label],
  };
}

test('buildVerificationVcBundle returns two VCs each with evidence', () => {
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousExternalDomain = process.env.ICA_EXTERNAL_DOMAIN;
  delete process.env.ICA_DIDCOMM_ISSUER_DID;
  delete process.env.ICA_EXTERNAL_DOMAIN;
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;

    const bundle = buildVerificationVcBundle(parsed.context, {
      ok: true,
      verifiedAt: '2026-03-05T00:00:00.000Z',
      templateUrl: 'https://example.test/template.pdf',
      templateMatch: true,
      signatureValid: true,
      chainValid: true,
      revocationStatus: 'good',
      digest: {
        alg: 'sha3-384',
        signedPdfHex: 'deadbeef',
        unsignedPdfHex: 'beadfeed',
        templateHex: 'cafebabe',
      },
      signerCertificateSerialNumber: '00AA11',
      signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
      signerIssuer: 'CN=FNMT Intermediate',
      hashes: {
        signedPdfSha256Hex: 'deadbeef',
        unsignedPdfSha256Hex: 'beadfeed',
        templateSha256Hex: 'cafebabe',
      },
      notes: ['ok'],
    });

    assert.equal(bundle.resourceType, 'Bundle');
    assert.equal(bundle.type, 'batch-response');
    assert.equal(bundle.issues?.resourceType, 'OperationOutcome');
    assert.equal(bundle.total, 2);
    assert.equal(Array.isArray(bundle.data), true);
    assert.equal(bundle.data.length, 2);
    assert.equal(bundle.data[0].response.outcome.resourceType, 'OperationOutcome');
    assert.equal(bundle.data[1].response.outcome.resourceType, 'OperationOutcome');
    const organizationResource = bundle.data[0].resource as Record<string, any>;
    const personResource = bundle.data[1].resource as Record<string, any>;
    assert.equal(Array.isArray(organizationResource.evidence), true);
    assert.equal(Array.isArray(personResource.evidence), true);
    assert.equal(organizationResource.resourceType, undefined);
    assert.equal(personResource.resourceType, undefined);

    const organizationSubject = organizationResource.credentialSubject as Record<string, any>;
    assert.equal(organizationSubject['@type'], 'Organization');
    assert.equal(organizationSubject.legalName, 'Acme Health SL');
    assert.equal(organizationSubject.taxID, 'VATES-A12345678');
    assert.equal(organizationSubject.identifier, undefined);
    assert.equal(organizationSubject.sector, undefined);
    assert.equal(organizationSubject.name, undefined);

    const personSubject = personResource.credentialSubject as Record<string, any>;
    assert.equal(personSubject['@type'], 'Person');
    assert.equal(personSubject.id, 'urn:person:identifier:12345678Z');
    assert.equal(personSubject.name, 'Jane Doe');
    assert.equal(personSubject.identifier, '12345678Z');
    assert.deepEqual(personSubject.hasOccupation, {
      '@type': 'Occupation',
      name: 'LegalRepresentative',
      identifier: 'urn:ilo:ilostat:isco-08:1120',
    });
    assert.equal(personSubject.memberOf?.['@type'], 'Organization');
    assert.equal(personSubject.memberOf?.legalName, 'Acme Health SL');
    assert.equal(personSubject.memberOf?.taxID, 'VATES-A12345678');
    assert.equal(personSubject.memberOf?.identifier, undefined);
    assert.equal(personSubject.worksFor, undefined);

    const organizationEvidence = organizationResource.evidence as Array<Record<string, any>>;
    assert.ok(organizationEvidence);
    assert.equal(organizationEvidence.length, 2);

    const signatureEvidence = organizationEvidence[0];
    assert.equal(signatureEvidence.type, 'electronic_signature');
    assert.equal(signatureEvidence.signature_type, 'pades');
    assert.equal(signatureEvidence.issuer, 'CN=FNMT Intermediate');
    assert.equal(signatureEvidence.serial_number, '00AA11');
    assert.equal(signatureEvidence.created_at, '2026-03-05T00:00:00.000Z');
    assert.equal(Array.isArray(signatureEvidence.attachments), true);
    assert.equal(signatureEvidence.attachments?.[0]?.content_type, 'application/json');
    assert.equal(typeof signatureEvidence.attachments?.[0]?.content, 'string');
    assert.equal((signatureEvidence.attachments?.[0]?.content || '').length > 0, true);

    const expectedIssuerDid = `did:web:localhost%3A${process.env.ICA_API_PORT || process.env.PORT || '3310'}`;
    const documentEvidence = organizationEvidence[1];
    assert.equal(documentEvidence.type, 'document');
    assert.equal(documentEvidence.method, 'eid');
    assert.equal(documentEvidence.verifier.organization, expectedIssuerDid);
    assert.equal(Array.isArray(documentEvidence.check_details), true);
    assert.equal(documentEvidence.check_details?.length, 2);
    assert.equal(documentEvidence.check_details?.[0]?.check_method, 'vdig');
    assert.equal(documentEvidence.check_details?.[1]?.check_method, 'vcrypt');
    assert.equal(documentEvidence.attachments?.digest.alg, 'sha3-384');
    assert.equal(documentEvidence.attachments?.digest.value, '3q2+7w==');
    assert.match(documentEvidence.attachments?.url || '', /^urn:uuid:/);
    assert.equal(documentEvidence.document_details?.type, 'terms-and-conditions');
    assert.equal(documentEvidence.document_details?.document_number, '202630011200');
    assert.equal(documentEvidence.document_details?.serial_number, '00AA11');
    assert.equal(documentEvidence.document_details?.issuer?.id, expectedIssuerDid);
    assert.equal(documentEvidence.document_details?.issuer?.type, 'TrustServiceProvider');
    assert.equal(documentEvidence.document_details?.issuer?.country_code, 'ES');
    assert.equal(documentEvidence.document_details?.issuer?.jurisdiction, 'ES');
  } finally {
    if (previousIssuerDid === undefined) {
      delete process.env.ICA_DIDCOMM_ISSUER_DID;
    } else {
      process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    }
    if (previousExternalDomain === undefined) {
      delete process.env.ICA_EXTERNAL_DOMAIN;
    } else {
      process.env.ICA_EXTERNAL_DOMAIN = previousExternalDomain;
    }
  }
});

test('buildVerificationVcBundle does not expose non-schema.org controller field', () => {
  const previousControllerKid = process.env.ICA_SELF_CONTROLLER_KID;
  const previousControllerEmail = process.env.ICA_SELF_CONTROLLER_EMAIL;
  process.env.ICA_SELF_CONTROLLER_KID = 'controller-bootstrap-kid';
  process.env.ICA_SELF_CONTROLLER_EMAIL = 'it-director@example.org';
  resetActiveSigningKeysStateForTests();

  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed?.ok, true);
    if (!parsed || !parsed.ok) return;

    const bundle = buildVerificationVcBundle(parsed.context, {
      ...buildTestVerifyResult('controller-bootstrap'),
      signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
    });

    const organizationResource = bundle.data[0]?.resource as Record<string, any>;
    const organizationSubject = organizationResource.credentialSubject as Record<string, any>;
    assert.equal(organizationSubject.controller, undefined);

    const organizationEvidence = organizationResource.evidence as Array<Record<string, any>>;
    const documentEvidence = organizationEvidence[1];
    assert.equal(documentEvidence.document_details?.controller, undefined);

    const personResource = bundle.data[1]?.resource as Record<string, any>;
    const personSubject = personResource.credentialSubject as Record<string, any>;
    assert.equal(personSubject.email, undefined);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousControllerKid === undefined) delete process.env.ICA_SELF_CONTROLLER_KID;
    else process.env.ICA_SELF_CONTROLLER_KID = previousControllerKid;
    if (previousControllerEmail === undefined) delete process.env.ICA_SELF_CONTROLLER_EMAIL;
    else process.env.ICA_SELF_CONTROLLER_EMAIL = previousControllerEmail;
  }
});

test('buildVerificationVcBundle uses external audit attachment when available', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const bundle = buildVerificationVcBundle(parsed.context, {
    ...buildTestVerifyResult('audit-external'),
    auditDocument: {
      provider: 'filesystem',
      objectId: 'f8f45d4d-39da-4bf5-908f-0879dd6f9b6f',
      objectKey: 'ica-audit/animal-care/es/202630011200/2026-03-05/f8f45d4d-39da-4bf5-908f-0879dd6f9b6f.pdf',
      attachmentUrl: 'urn:uuid:f8f45d4d-39da-4bf5-908f-0879dd6f9b6f',
      contentType: 'application/pdf',
      sizeBytes: 1024,
      storedAt: '2026-03-05T00:00:00.000Z',
    },
  });

  const organizationResource = bundle.data[0].resource as Record<string, any>;
  const organizationEvidence = organizationResource.evidence as Array<Record<string, any>>;
  const documentEvidence = organizationEvidence[1];
  assert.equal(documentEvidence.attachments?.url, 'urn:uuid:f8f45d4d-39da-4bf5-908f-0879dd6f9b6f');
  assert.equal(documentEvidence.check_details?.[0]?.txn?.startsWith('audit:filesystem:'), true);
  assert.equal(documentEvidence.check_details?.[1]?.txn?.startsWith('audit:filesystem:'), true);
});

test('buildVerificationVcBundle maps annex form fields into credential subjects and evidence details', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const bundle = buildVerificationVcBundle(parsed.context, {
    ...buildTestVerifyResult('annex-fields'),
    signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
    annexFormFields: {
      'Organization.sameAs': 'did:web:member.example.org',
      'Organization.url': 'member.example.org',
      'Organization.additionalType': 'sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider',
      'Organization.alternateName': 'acme',
      'Organization.registrationNumber': 'ES-SAN-REG-0001',
      'Organization.email': 'zOrgContactHash',
      'Person.email': 'zControllerHash',
      'Person.alternateName': 'controller-es384-20260309',
      'Person.additionalType': 'ES384',
    },
  });

  const organizationResource = bundle.data[0].resource as Record<string, any>;
  const personResource = bundle.data[1].resource as Record<string, any>;
  const organizationSubject = organizationResource.credentialSubject as Record<string, any>;
  const personSubject = personResource.credentialSubject as Record<string, any>;
  const organizationEvidence = organizationResource.evidence as Array<Record<string, any>>;
  const documentEvidence = organizationEvidence[1] as Record<string, any>;

  assert.equal(organizationSubject.id, 'did:web:member.example.org');
  assert.equal(organizationSubject.sameAs, 'did:web:member.example.org');
  assert.equal(
    organizationSubject.additionalType,
    'sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider',
  );
  assert.equal(organizationSubject.alternateName, 'acme');
  assert.equal(organizationSubject.registrationNumber, 'ES-SAN-REG-0001');
  assert.equal(organizationSubject.email, 'zOrgContactHash');
  assert.equal(organizationSubject.url, 'member.example.org');
  assert.equal(personSubject.email, 'zControllerHash');
  assert.equal(personSubject.alternateName, 'controller-es384-20260309');
  assert.equal(personSubject.additionalType, 'ES384');
  assert.equal(personSubject.memberOf?.alternateName, undefined);
  assert.equal(personSubject.memberOf?.additionalType, undefined);
  assert.equal(personSubject.memberOf?.email, undefined);
  assert.equal(organizationSubject.controller, undefined);
  assert.equal(
    documentEvidence.document_details?.annexFormFields?.['Organization.sameAs'],
    'did:web:member.example.org',
  );
});

test('buildVerificationVcBundle omits intermediate crl_check_all verify_error when fallback succeeds', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const bundle = buildVerificationVcBundle(parsed.context, {
    ok: true,
    verifiedAt: '2026-03-05T00:00:00.000Z',
    templateUrl: 'https://example.test/template.pdf',
    templateMatch: true,
    signatureValid: true,
    chainValid: true,
    revocationStatus: 'good',
    digest: {
      alg: 'sha3-384',
      signedPdfHex: 'deadbeef',
      unsignedPdfHex: 'beadfeed',
      templateHex: 'cafebabe',
    },
    signerCertificateSerialNumber: '00AA11',
    signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
    signerIssuer: 'CN=FNMT Intermediate',
    hashes: {
      signedPdfSha256Hex: 'deadbeef',
      unsignedPdfSha256Hex: 'beadfeed',
      templateSha256Hex: 'cafebabe',
    },
    notes: [
      'CMS signature and authenticated attributes validated.',
      'Signer chain validated against FNMT root/intermediate.',
      'FNMT root loaded from https://www.sede.fnmt.gob.es/root.cer',
      'FNMT intermediate loaded from https://www.sede.fnmt.gob.es/intermediate.cer',
      'CRL loaded from http://www.cert.fnmt.es/crls/one.crl',
    ],
    revocationDebug: {
      finalStatus: 'good',
      checks: [
        { phase: 'discovery', status: 'ok', message: 'Discovered 1 CRL URL(s).' },
        { phase: 'verify', status: 'verify_error', message: 'mode=-crl_check_all different crl scope' },
        { phase: 'verify', status: 'ok', message: 'OpenSSL CRL verification passed (mode=-crl_check fallback).' },
      ],
    },
  });

  const resource = bundle.data[0].resource as Record<string, any>;
  const rawAttachment = resource.evidence?.[0]?.attachments?.[0]?.content || '';
  const payloadBase64 = String(rawAttachment).replace(/^data:application\/json;base64,/, '');
  const attachmentPayload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8')) as {
    verificationTrace?: { revocationChecks?: Array<{ status?: string; message?: string }> };
  };

  const checks = attachmentPayload.verificationTrace?.revocationChecks || [];
  assert.equal(
    checks.some((check) =>
      check.status === 'verify_error' && (check.message || '').includes('mode=-crl_check_all')
    ),
    false,
  );
  assert.equal(
    checks.some((check) =>
      check.status === 'ok' && (check.message || '').includes('mode=-crl_check fallback')
    ),
    true,
  );
});

test('buildVerificationVcBundle filters intermediate CA URLs to signer issuer profile', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const bundle = buildVerificationVcBundle(parsed.context, {
    ok: true,
    verifiedAt: '2026-03-05T00:00:00.000Z',
    templateUrl: 'https://example.test/template.pdf',
    templateMatch: true,
    signatureValid: true,
    chainValid: true,
    revocationStatus: 'good',
    digest: {
      alg: 'sha3-384',
      signedPdfHex: 'deadbeef',
      unsignedPdfHex: 'beadfeed',
      templateHex: 'cafebabe',
    },
    signerCertificateSerialNumber: '00AA11',
    signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
    signerIssuer: 'C=ES,O=FNMT-RCM,OU=CERES,CN=AC Representación',
    hashes: {
      signedPdfSha256Hex: 'deadbeef',
      unsignedPdfSha256Hex: 'beadfeed',
      templateSha256Hex: 'cafebabe',
    },
    notes: [
      'CMS signature and authenticated attributes validated.',
      'Signer chain validated against FNMT root/intermediate.',
      'FNMT intermediate loaded from https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_Representacion.cer, https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_Sector_Publico.cer, https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_FNMT_Usuarios.cer',
    ],
    revocationDebug: {
      finalStatus: 'good',
      checks: [],
    },
  });

  const resource = bundle.data[0].resource as Record<string, any>;
  const rawAttachment = resource.evidence?.[0]?.attachments?.[0]?.content || '';
  const payloadBase64 = String(rawAttachment).replace(/^data:application\/json;base64,/, '');
  const attachmentPayload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8')) as {
    verificationTrace?: { intermediates?: string[] };
  };

  const intermediates = attachmentPayload.verificationTrace?.intermediates || [];
  assert.equal(intermediates.length, 1);
  assert.equal(intermediates[0].includes('AC_Representacion.cer'), true);
});
