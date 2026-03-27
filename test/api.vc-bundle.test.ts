import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVerifyRoute } from '../src/api/path.ts';
import { buildVerificationVcBundle } from '../src/api/server.ts';
import { resetActiveSigningKeysStateForTests, activateSigningKey } from '../src/api/tools/active-signing-keys.ts';
import { PRIVATE_KEY_PEM, PUBLIC_JWK } from './test-signing-key.fixture.js';
  // Clave activa para pruebas
  resetActiveSigningKeysStateForTests();
  activateSigningKey({
    kid: 'test-key-1',
    alg: 'ES384',
    publicJwk: PUBLIC_JWK,
    privateKeyPem: PRIVATE_KEY_PEM,
  });
import { normalizeSameAsHash } from '../src/api/tools/multihash.ts';
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
    signerSubject: 'CN=Signer,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
    signerIssuer: 'CN=FNMT',
    signerSigningTime: '2026-03-05T00:00:00.000Z',
    hashes: {
      signedPdfSha256Hex: 'a',
      unsignedPdfSha256Hex: 'b',
      templateSha256Hex: 'c',
    },
    notes: [label],
  };
}

test('buildVerificationVcBundle returns two VCs each with evidence', () => {
  resetActiveSigningKeysStateForTests();
  activateSigningKey({
    kid: 'test-key-1',
    alg: 'ES384',
    publicJwk: { kty: 'EC', crv: 'P-384', x: 'x1', y: 'y1' },
    privateKeyPem: `-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICv1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1oAoGCCqGSM49\nAwEHoUQDQgAEx1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1\ny1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1y1==\n-----END EC PRIVATE KEY-----`,
  });
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousExternalDomain = process.env.ICA_EXTERNAL_DOMAIN;
  const previousOrganizationDidPublicDomain = process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR;
  delete process.env.ICA_DIDCOMM_ISSUER_DID;
  delete process.env.ICA_EXTERNAL_DOMAIN;
  delete process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR;
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
    assert.equal(organizationSubject.id, 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678');
    assert.equal(organizationSubject['@type'], 'Organization');
    assert.equal(organizationSubject.legalName, 'Acme Health SL');
    assert.equal(organizationSubject.taxID, 'VATES-A12345678');
    assert.equal(organizationSubject.sameAs, undefined);
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

    const expectedVerifierDid = 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678';
    const documentEvidence = organizationEvidence[1];
    assert.equal(documentEvidence.type, 'document');
    assert.equal(documentEvidence.method, 'eid');
    assert.equal(documentEvidence.verifier.organization, expectedVerifierDid);
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
    assert.equal(documentEvidence.document_details?.issuer?.id, expectedVerifierDid);
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
    if (previousOrganizationDidPublicDomain === undefined) {
      delete process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR;
    } else {
      process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR = previousOrganizationDidPublicDomain;
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
    assert.equal(personSubject.sameAs, undefined);
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
  const previousOrganizationDidPublicDomain = process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR;
  process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR = 'globaldatacare.es';
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) {
    if (previousOrganizationDidPublicDomain === undefined) delete process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR;
    else process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR = previousOrganizationDidPublicDomain;
    return;
  }

  try {
    const bundle = buildVerificationVcBundle(parsed.context, {
      ...buildTestVerifyResult('annex-fields'),
      signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
      annexFormFields: {
        'Organization.sameAs': 'did:web:member.example.org',
        'Organization.url': 'member.example.org',
        'Organization.additionalType': 'sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider',
        'Organization.alternateName': 'acme',
        'Organization.registrationNumber': 'ES-SAN-REG-0001',
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

    assert.equal(organizationSubject.id, 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678');
    assert.equal(organizationSubject.sameAs, 'did:web:member.example.org');
    assert.equal(
      organizationSubject.additionalType,
      'sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider',
    );
    assert.equal(organizationSubject.alternateName, 'acme');
    assert.equal(organizationSubject.registrationNumber, 'ES-SAN-REG-0001');
    assert.equal(organizationSubject.email, undefined);
    assert.equal(organizationSubject.url, 'member.example.org');
    assert.equal(personSubject.email, undefined);
    assert.equal(personSubject.sameAs, 'urn:multibase:zControllerHash');
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
  } finally {
    if (previousOrganizationDidPublicDomain === undefined) delete process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR;
    else process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR = previousOrganizationDidPublicDomain;
  }
});

test('buildVerificationVcBundle hashes plain controller email into credentialSubject.sameAs', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const bundle = buildVerificationVcBundle(parsed.context, {
    ...buildTestVerifyResult('plain-controller-email'),
    signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,EMAILADDRESS=Jane.Doe@Example.org,C=ES',
  });

  const personResource = bundle.data[1].resource as Record<string, any>;
  const personSubject = personResource.credentialSubject as Record<string, any>;
  assert.equal(personSubject.email, undefined);
  assert.equal(personSubject.sameAs, normalizeSameAsHash('Jane.Doe@Example.org'));
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

test('buildVerificationVcBundle ignores arbitrary payload fields not extracted from PDF', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const bundle = buildVerificationVcBundle(parsed.context, {
    ...buildTestVerifyResult('cert-vs-payload'),
    signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
    organizationPayload: {
      legalName: 'Payload Org Name',
      taxID: 'VATES-PAYLOADTAX',
      address: {
        '@type': 'PostalAddress',
        addressLine: '123 Fake St',
      },
      telephone: '+34000000000'
    },
    legalRepresentativePayload: {
      givenName: 'Payload Given Name',
      familyName: 'Payload Family Name',
      identifier: 'PAYLOAD-ID',
      jobTitle: 'Payload Job Title'
    },
  });

  const organizationResource = bundle.data[0].resource as Record<string, any>;
  const personResource = bundle.data[1].resource as Record<string, any>;
  
  const organizationSubject = organizationResource.credentialSubject as Record<string, any>;
  const personSubject = personResource.credentialSubject as Record<string, any>;

  assert.equal(organizationSubject.taxID, 'VATES-A12345678');
  assert.equal(organizationSubject.legalName, 'Acme Health SL');
  assert.equal(organizationSubject.telephone, undefined);
  assert.equal(organizationSubject.address?.addressLine, undefined);

  assert.equal(personSubject.name, 'Jane Doe');
  assert.equal(personSubject.identifier, '12345678Z');
  assert.equal(personSubject.jobTitle, undefined);

  const orgEvidence = organizationResource.evidence as Array<Record<string, any>>;
  assert.ok(orgEvidence);
  assert.equal(orgEvidence.length, 2);
  assert.equal(orgEvidence[0]?.type, 'electronic_signature');
  assert.equal(orgEvidence[1]?.type, 'document');
});

test('buildVerificationVcBundle allows payload merge when environment variable is set', () => {
  const previousFlag = process.env.ICA_ALLOW_UNVERIFIED_CREDENTIAL_PAYLOADS;
  process.env.ICA_ALLOW_UNVERIFIED_CREDENTIAL_PAYLOADS = 'true';
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;

    const bundle = buildVerificationVcBundle(parsed.context, {
      ...buildTestVerifyResult('cert-vs-payload'),
      signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
      organizationPayload: {
        legalName: 'Payload Org Name',
        taxID: 'VATES-PAYLOADTAX',
        address: {
          '@type': 'PostalAddress',
          addressLine: '123 Fake St',
        },
        telephone: '+34000000000'
      },
      legalRepresentativePayload: {
        givenName: 'Payload Given Name',
        familyName: 'Payload Family Name',
        identifier: 'PAYLOAD-ID',
        jobTitle: 'Payload Job Title'
      },
    });

    const organizationResource = bundle.data[0].resource as Record<string, any>;
    const personResource = bundle.data[1].resource as Record<string, any>;
    
    const organizationSubject = organizationResource.credentialSubject as Record<string, any>;
    const personSubject = personResource.credentialSubject as Record<string, any>;

    assert.equal(organizationSubject.taxID, 'VATES-A12345678');
    assert.equal(organizationSubject.legalName, 'Acme Health SL');
    assert.equal(organizationSubject.telephone, '+34000000000');
    assert.deepEqual(organizationSubject.address, {
      '@type': 'PostalAddress',
      addressCountry: 'ES',
      addressLine: '123 Fake St'
    });

    assert.equal(personSubject.name, 'Jane Doe');
    assert.equal(personSubject.identifier, '12345678Z');
    assert.equal(personSubject.jobTitle, 'Payload Job Title');

    const orgEvidence = organizationResource.evidence as Array<Record<string, any>>;
    assert.ok(orgEvidence);
    assert.equal(orgEvidence.length, 2);
    assert.equal(orgEvidence[0]?.type, 'electronic_signature');
    assert.equal(orgEvidence[1]?.type, 'document');
  } finally {
    if (previousFlag === undefined) {
      delete process.env.ICA_ALLOW_UNVERIFIED_CREDENTIAL_PAYLOADS;
    } else {
      process.env.ICA_ALLOW_UNVERIFIED_CREDENTIAL_PAYLOADS = previousFlag;
    }
  }
});

test('buildVerificationVcBundle uses visible PDF organization identity when signer certificate is personal', () => {
  const previousJurisdictions = process.env.ICA_SUPPORTED_JURISDICTIONS;
  process.env.ICA_SUPPORTED_JURISDICTIONS = 'ES';
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/contract/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;

    const bundle = buildVerificationVcBundle(parsed.context, {
      ...buildTestVerifyResult('pdf-org-identity'),
      signerSubject: 'CN=Jane Doe,SERIALNUMBER=12345678Z,C=ES',
      annexFormFields: {
        'Organization.taxID': 'ES-B123 45678',
        'Organization.legalName': 'Acme Health SL',
      },
    });

    const organizationResource = bundle.data[0].resource as Record<string, any>;
    const personResource = bundle.data[1].resource as Record<string, any>;
    const organizationSubject = organizationResource.credentialSubject as Record<string, any>;
    const personSubject = personResource.credentialSubject as Record<string, any>;

    assert.equal(organizationSubject.id, 'did:web:globaldatacare.es:animal-care:organization:taxid:ES-B12345678');
    assert.equal(organizationSubject.taxID, 'ES-B12345678');
    assert.equal(organizationSubject.legalName, 'ACME HEALTH SL');
    assert.equal(personSubject.memberOf?.taxID, 'ES-B12345678');
    assert.equal(personSubject.memberOf?.legalName, 'ACME HEALTH SL');
  } finally {
    if (previousJurisdictions === undefined) {
      delete process.env.ICA_SUPPORTED_JURISDICTIONS;
    } else {
      process.env.ICA_SUPPORTED_JURISDICTIONS = previousJurisdictions;
    }
  }
});

test('buildVerificationVcBundle does not duplicate the country prefix when PDF tax ID already starts with it', () => {
  const previousJurisdictions = process.env.ICA_SUPPORTED_JURISDICTIONS;
  process.env.ICA_SUPPORTED_JURISDICTIONS = 'ES';
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/contract/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;

    const bundle = buildVerificationVcBundle(parsed.context, {
      ...buildTestVerifyResult('pdf-org-prefix'),
      signerSubject: 'CN=Jane Doe,SERIALNUMBER=12345678Z,C=ES',
      annexFormFields: {
        'organization.taxId': 'ES-B12345678',
        'organization.legalName': 'ProcureData S.L.',
      },
    });

    const organizationResource = bundle.data[0].resource as Record<string, any>;
    const organizationSubject = organizationResource.credentialSubject as Record<string, any>;
    assert.equal(organizationSubject.taxID, 'ES-B12345678');
    assert.equal(organizationSubject.legalName, 'PROCUREDATA S.L.');
  } finally {
    if (previousJurisdictions === undefined) {
      delete process.env.ICA_SUPPORTED_JURISDICTIONS;
    } else {
      process.env.ICA_SUPPORTED_JURISDICTIONS = previousJurisdictions;
    }
  }
});

test('buildVerificationVcBundle requires visible PDF organization legal name when signer certificate is personal', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/contract/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  assert.throws(
    () => buildVerificationVcBundle(parsed.context, {
      ...buildTestVerifyResult('pdf-org-missing-name'),
      signerSubject: 'CN=Jane Doe,SERIALNUMBER=12345678Z,C=ES',
      annexFormFields: {
        'organization.taxID': 'ES-B12345678',
      },
    }),
    /visible organization legal name field/i,
  );
});

test('buildVerificationVcBundle uses deterministic VC/document IDs when DETERMINISTIC_VC_BY_CONTRACT=true', () => {
    // Clave determinista activa
    resetActiveSigningKeysStateForTests();
    activateSigningKey({
      kid: 'deterministic-key-1',
      alg: 'ES384',
      publicJwk: PUBLIC_JWK,
      privateKeyPem: PRIVATE_KEY_PEM,
    });
  resetActiveSigningKeysStateForTests();
  activateSigningKey({
    kid: 'deterministic-key-1',
    alg: 'ES384',
    publicJwk: { kty: 'EC', crv: 'P-384', x: 'u5v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1', y: 'v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5' },
    privateKeyPem: `-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICv1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1oAoGCCqGSM49\nAwEHoUQDQgAEu5v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1\nv5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5v5==\n-----END EC PRIVATE KEY-----`,
  });
  const previousFlag = process.env.DETERMINISTIC_VC_BY_CONTRACT;
  const previousNamespace = process.env.DATASPACE_URN_NAMESPACE;
  process.env.DETERMINISTIC_VC_BY_CONTRACT = 'true';
  process.env.DATASPACE_URN_NAMESPACE = 'GlobalDataCare';
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;

    const verifyResult = {
      ...buildTestVerifyResult('deterministic-vc'),
      digest: {
        alg: 'sha3-384',
        signedPdfHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        unsignedPdfHex: 'b',
        templateHex: 'c',
      },
      hashes: {
        signedPdfSha256Hex: 'a',
        unsignedPdfSha256Hex: 'b',
        templateSha256Hex: 'c',
      },
    } as VerifyResult;

    const bundleA = buildVerificationVcBundle(parsed.context, verifyResult);
    const bundleB = buildVerificationVcBundle(parsed.context, verifyResult);

    const orgA = bundleA.data[0].resource as Record<string, any>;
    const orgB = bundleB.data[0].resource as Record<string, any>;
    const personA = bundleA.data[1].resource as Record<string, any>;
    const personB = bundleB.data[1].resource as Record<string, any>;

    assert.equal(orgA.id, orgB.id);
    assert.equal(personA.id, personB.id);
    assert.match(String(orgA.id || ''), /^urn:globaldatacare:animal-care:organization:vc:z/);
    assert.match(String(personA.id || ''), /^urn:globaldatacare:animal-care:organization-representative:vc:z/);

    const orgEvidenceA = orgA.evidence as Array<Record<string, any>>;
    const docEvidenceA = orgEvidenceA[1];
    const attachmentUrl = String(docEvidenceA.attachments?.url || '');

    assert.match(attachmentUrl, /^ipfs:\/\/z/);
    assert.equal(String(docEvidenceA.attachments?.url || '').startsWith('urn:uuid:'), false);
    assert.equal(attachmentUrl.includes(String(orgA.id).split(':vc:')[1]), true);
  } finally {
    if (previousFlag === undefined) {
      delete process.env.DETERMINISTIC_VC_BY_CONTRACT;
    } else {
      process.env.DETERMINISTIC_VC_BY_CONTRACT = previousFlag;
    }
    if (previousNamespace === undefined) {
      delete process.env.DATASPACE_URN_NAMESPACE;
    } else {
      process.env.DATASPACE_URN_NAMESPACE = previousNamespace;
    }
  }
});
