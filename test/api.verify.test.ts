import { PRIVATE_KEY_PEM, PUBLIC_JWK } from './test-signing-key.fixture.js';
import { resetActiveSigningKeysStateForTests, activateSigningKey } from '../src/api/tools/active-signing-keys.ts';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { InMemoryVerificationJobStore } from '../src/api/job-store.ts';
import {
  buildAddEvidenceResponseLocation,
  buildDelegationPolicyResponseLocation,
  buildCredentialRevokeResponseLocation,
  buildCredentialStatusResponseLocation,
  buildIssueCredentialResponseLocation,
  buildVerifyResponseLocation,
  parseDcatCatalogDdoDatasetRoute,
  parseDcatCatalogDdoRequestRoute,
  parseDcatCatalogDatasetRoute,
  parseDcatCatalogRequestRoute,
  parseAddEvidenceRoute,
  parseDelegationPolicyRoute,
  parseCredentialRevokeRoute,
  parseSpacesRoute,
  parseCredentialStatusRoute,
  parseIssueCredentialRoute,
  parseVerifyRoute,
} from '../src/api/path.ts';
import { VerifyRequestManager } from '../src/api/managers/verify-request-manager.ts';
import { VerifyResponseManager } from '../src/api/managers/verify-response-manager.ts';
import { buildVerificationVcBundle } from '../src/api/server.ts';
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import {
  assertVerifierCounterpartySignaturePair,
  computePdfLogicalFingerprint,
  FnmtPdfVerificationService,
  parseVatIdFromSubjectDn,
  resolveTemplateResourceVersion,
  selectPrimaryCredentialSignature,
} from '../src/api/cert-pdf-verifier.ts';
import { AuditDocumentStorageService } from '../src/api/tools/audit-document-storage.ts';
import { buildDidcommMessage } from '../src/api/tools/didcomm-message.ts';
import { parseSpacesReplaceSubmission } from '../src/api/request-parsing.ts';
import {
  VerificationCollectionsService,
  resetVerificationCollectionsMemStateForTests,
} from '../src/api/tools/verification-collections-storage.ts';
import type {
  VerifyResult,
  VerifySubmission,
} from '../src/api/types.ts';

function buildTestVerifyResult(label: string): VerifyResult {
  const validSha3_384Hex = 'a'.repeat(96);
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
      signedPdfHex: validSha3_384Hex,
      unsignedPdfHex: validSha3_384Hex,
      templateHex: validSha3_384Hex,
    },
    signerCertificateSerialNumber: '00AA11',
    signerSubject: 'CN=Signer,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
    signerIssuer: 'CN=FNMT',
    signerSigningTime: '2026-03-05T00:00:00.000Z',
    hashes: {
      signedPdfSha256Hex: 'a'.repeat(64),
      unsignedPdfSha256Hex: 'b'.repeat(64),
      templateSha256Hex: 'c'.repeat(64),
    },
    notes: [label],
  };
}

function hashVcResource(resource: unknown): string {
  return createHash('sha256').update(JSON.stringify(resource)).digest('hex');
}

function hashVcResourceWithoutProof(resource: unknown): string {
  if (!resource || typeof resource !== 'object') {
    return createHash('sha256').update(JSON.stringify(resource)).digest('hex');
  }
  const normalized = { ...(resource as Record<string, unknown>) };
  delete normalized.proof;
  return createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
}

function buildMinimalPdf(contentStream: string, pageExtra = '', extraObjects = ''): Buffer {
  const streamBuffer = Buffer.from(contentStream, 'latin1');
  const pageDictionaryExtra = pageExtra ? ` ${pageExtra}` : '';
  const extra = extraObjects ? `\n${extraObjects}\n` : '\n';
  return Buffer.from(
    [
      '%PDF-1.4',
      '1 0 obj',
      '<< /Type /Catalog /Pages 2 0 R >>',
      'endobj',
      '2 0 obj',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      'endobj',
      '3 0 obj',
      `<< /Type /Page /Parent 2 0 R /Contents 4 0 R${pageDictionaryExtra} >>`,
      'endobj',
      '4 0 obj',
      `<< /Length ${streamBuffer.length} >>`,
      'stream',
      contentStream,
      'endstream',
      'endobj',
      extra,
      '%%EOF',
      '',
    ].join('\n'),
    'latin1',
  );
}

const REAL_FNMT_FIXTURES_DIR = '/Users/fernando/GITS/gdc-workspace/examples';
const REAL_MULTISIGN_PDF_FILENAME = 'prueba-TEST-A4-multisign-fnmt.pdf';
const REAL_THREE_SIGN_PDF_FILENAME = 'prueba-TEST-A4-firmas-3-fnmt.pdf';
const REAL_MULTISIGN_PDF_PATH = path.join(REAL_FNMT_FIXTURES_DIR, REAL_MULTISIGN_PDF_FILENAME);
const REAL_THREE_SIGN_PDF_PATH = path.join(REAL_FNMT_FIXTURES_DIR, REAL_THREE_SIGN_PDF_FILENAME);

function splitPemCertificates(rawPem: string): string[] {
  return rawPem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
}

function extractSignerVatIdsFromRealPdf(pdfPath: string): string[] {
  const pdfBytes = readFileSync(pdfPath);
  const pdfAsLatin1 = pdfBytes.toString('latin1');
  const byteRangeRegex = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  const tempDir = mkdtempSync(path.join(tmpdir(), 'ica-multisign-test-'));
  const vatIds: string[] = [];

  try {
    let match: RegExpExecArray | null;
    let signatureIndex = 0;
    while ((match = byteRangeRegex.exec(pdfAsLatin1))) {
      const start1 = Number.parseInt(match[1], 10);
      const length1 = Number.parseInt(match[2], 10);
      const start2 = Number.parseInt(match[3], 10);
      const length2 = Number.parseInt(match[4], 10);
      const signatureWindow = pdfBytes.subarray(start1 + length1, start2);
      const lt = signatureWindow.indexOf(0x3c);
      const gt = signatureWindow.lastIndexOf(0x3e);
      let hex = signatureWindow.subarray(lt + 1, gt).toString('latin1').replace(/[^0-9a-fA-F]/g, '');
      while (hex.endsWith('00')) {
        hex = hex.slice(0, -2);
      }

      const signatureDerPath = path.join(tempDir, `signature-${signatureIndex}.der`);
      const certsPath = path.join(tempDir, `signature-${signatureIndex}.pem`);
      writeFileSync(signatureDerPath, Buffer.from(hex, 'hex'));
      execFileSync('openssl', ['pkcs7', '-inform', 'DER', '-in', signatureDerPath, '-print_certs', '-out', certsPath]);

      const certs = splitPemCertificates(readFileSync(certsPath, 'utf8'));
      let signerVatId: string | undefined;
      for (const [certIndex, certPem] of certs.entries()) {
        const certPath = path.join(tempDir, `signature-${signatureIndex}-cert-${certIndex}.pem`);
        writeFileSync(certPath, `${certPem}\n`);
        const certSubject = execFileSync(
          'openssl',
          ['x509', '-in', certPath, '-noout', '-subject', '-nameopt', 'RFC2253'],
          { encoding: 'utf8' },
        ).trim();
        signerVatId = parseVatIdFromSubjectDn(certSubject);
        if (signerVatId) {
          break;
        }
      }
      assert.ok(signerVatId, `missing VATES identifier in signature ${signatureIndex + 1}`);
      vatIds.push(signerVatId);
      signatureIndex += 1;
    }

    return vatIds;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

test('parseVerifyRoute accepts valid _verify route', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'acme');
  assert.equal(parsed.context.jurisdiction, 'ES');
  assert.equal(parsed.context.sector, 'animal-care');
  assert.equal(parsed.context.action, '_verify');
});

test('parseVerifyRoute rejects unsupported sector', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/legal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.equal(parsed.statusCode, 400);
});

test('parseVerifyRoute rejects sectors outside configured supported list', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-veterinary/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed?.ok, false);
  if (!parsed || parsed.ok) return;
  assert.equal(parsed.statusCode, 400);
  assert.match(parsed.message, /sector must be one of/i);
});

test('parseVerifyRoute rejects invalid version token', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/not-a-version/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.equal(parsed.statusCode, 400);
  assert.match(parsed.message, /resourceType/i);
});

test('parseVerifyRoute accepts resourceType=contract without requiring a version token', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/contract/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  assert.equal(parsed.context.resourceType, 'contract');
});

test('parseVatIdFromSubjectDn extracts VATES identifier from certificate subject', () => {
  const vatId = parseVatIdFromSubjectDn('CN=Acme Hosting,O=Acme,organizationIdentifier=VATES-B12345678,C=ES');
  assert.equal(vatId, 'VATES-B12345678');
});

test('selectPrimaryCredentialSignature ignores verifier signatures from VERIFIERS_VAT_LIST', () => {
  const selected = selectPrimaryCredentialSignature(
    [
      { signatureIndex: 0, signerVatId: 'VATES-A11111111' },
      { signatureIndex: 1, signerVatId: 'VATES-B22222222' },
      { signatureIndex: 2, signerVatId: 'VATES-Z99999999' },
    ],
    ['VATES-Z99999999'],
    [],
  );
  assert.deepEqual(selected, { signatureIndex: 1, signerVatId: 'VATES-B22222222' });
});

test('assertVerifierCounterpartySignaturePair requires one verifier VAT and one different counterparty VAT', () => {
  assert.doesNotThrow(() => {
    assertVerifierCounterpartySignaturePair(
      [
        { signatureIndex: 0, signerVatId: 'VATES-G02793479' },
        { signatureIndex: 1, signerVatId: 'VATES-B42215152' },
      ],
      ['VATES-G02793479', 'VATES-B87617981'],
      [],
    );
  });

  assert.throws(
    () => {
      assertVerifierCounterpartySignaturePair(
        [{ signatureIndex: 0, signerVatId: 'VATES-B42215152' }],
        ['VATES-G02793479', 'VATES-B87617981'],
        [],
      );
    },
    /at least one verifier signature/i,
  );

  assert.throws(
    () => {
      assertVerifierCounterpartySignaturePair(
        [
          { signatureIndex: 0, signerVatId: 'VATES-G02793479' },
          { signatureIndex: 1, signerVatId: 'VATES-B87617981' },
        ],
        ['VATES-G02793479', 'VATES-B87617981'],
        [],
      );
    },
    /at least one non-verifier counterparty signature/i,
  );
});

test('assertVerifierCounterpartySignaturePair handles verification partners correctly', () => {
  assert.doesNotThrow(() => {
    assertVerifierCounterpartySignaturePair(
      [
        { signatureIndex: 0, signerVatId: 'VATES-VERIFIER' },
        { signatureIndex: 1, signerVatId: 'VATES-PARTNER' },
        { signatureIndex: 2, signerVatId: 'VATES-MEMBER' },
      ],
      ['VATES-VERIFIER'],
      ['VATES-PARTNER'],
    );
  });

  assert.doesNotThrow(() => {
    assertVerifierCounterpartySignaturePair(
      [
        { signatureIndex: 0, signerVatId: 'VATES-VERIFIER' },
        { signatureIndex: 1, signerVatId: 'VATES-PARTNER' },
      ],
      ['VATES-VERIFIER'],
      [],
    );
  });

  assert.throws(
    () => {
      assertVerifierCounterpartySignaturePair(
        [
          { signatureIndex: 0, signerVatId: 'VATES-VERIFIER' },
          { signatureIndex: 1, signerVatId: 'VATES-MEMBER' },
        ],
        ['VATES-VERIFIER'],
        ['VATES-PARTNER'],
      );
    },
    /at least one verification partner signature/i,
  );
});

test('assertVerifierCounterpartySignaturePair accepts verifier plus personal signer when PDF shows organization identity', () => {
  assert.doesNotThrow(() => {
    assertVerifierCounterpartySignaturePair(
      [
        { signatureIndex: 0, signerVatId: 'VATES-VERIFIER' },
        { signatureIndex: 1, signerVatId: undefined },
      ],
      ['VATES-VERIFIER'],
      [],
      undefined,
      {
        'Organization.taxID': 'ES-B12345678',
        'Organization.legalName': 'Acme Health SL',
      },
    );
  });
});

test('assertVerifierCounterpartySignaturePair still rejects verifier-only PDFs without visible organization identity', () => {
  assert.throws(
    () => {
      assertVerifierCounterpartySignaturePair(
        [
          { signatureIndex: 0, signerVatId: 'VATES-VERIFIER' },
          { signatureIndex: 1, signerVatId: undefined },
        ],
        ['VATES-VERIFIER'],
        [],
      );
    },
    /visible organization VAT\/CIF and legal name fields/i,
  );
});

test(
  'selectPrimaryCredentialSignature handles the real FNMT three-signature PDF regardless of which verifier/partner VAT is configured',
  { skip: !existsSync(REAL_THREE_SIGN_PDF_PATH) },
  () => {
    const signerVatIds = extractSignerVatIdsFromRealPdf(REAL_THREE_SIGN_PDF_PATH);
    assert.deepEqual(signerVatIds, ['VATES-B42215152', 'VATES-G02793479', 'VATES-N0377833I']);

    const signatures = signerVatIds.map((signerVatId, signatureIndex) => ({ signatureIndex, signerVatId }));

    const primarySignature = selectPrimaryCredentialSignature(signatures, ['VATES-G02793479'], ['VATES-B42215152']);
    assert.deepEqual(primarySignature, { signatureIndex: 2, signerVatId: 'VATES-N0377833I' });
  },
);

test(
  'selectPrimaryCredentialSignature handles the real FNMT multisign PDF regardless of which verifier VAT is configured',
  { skip: !existsSync(REAL_MULTISIGN_PDF_PATH) },
  () => {
    const signerVatIds = extractSignerVatIdsFromRealPdf(REAL_MULTISIGN_PDF_PATH);
    assert.deepEqual(signerVatIds, ['VATES-B42215152', 'VATES-G02793479']);

    const signatures = signerVatIds.map((signerVatId, signatureIndex) => ({ signatureIndex, signerVatId }));

    const verifierIsUnid = selectPrimaryCredentialSignature(signatures, ['VATES-G02793479'], []);
    assert.deepEqual(verifierIsUnid, { signatureIndex: 0, signerVatId: 'VATES-B42215152' });

    const verifierIsConectate = selectPrimaryCredentialSignature(signatures, ['VATES-B42215152'], []);
    assert.deepEqual(verifierIsConectate, { signatureIndex: 1, signerVatId: 'VATES-G02793479' });
  },
);

test(
  'FnmtPdfVerificationService verifies all signatures before choosing which one feeds credential extraction',
  { skip: !existsSync(REAL_MULTISIGN_PDF_PATH) },
  async () => {
    const pdfBytes = readFileSync(REAL_MULTISIGN_PDF_PATH);
    const service = new FnmtPdfVerificationService({
      fnmtRootCertPath: path.resolve('certs/fnmt/fnmt-root.pem'),
      fnmtIntermediateCertPath: path.resolve('certs/fnmt/fnmt-intermediate.pem'),
      fnmtAutoDownload: false,
      knownRootCertUrls: [],
      knownIntermediateCertUrls: [],
      templateUrlPattern: 'https://example.test/{resourceVersion}.pdf',
      strictRevocation: true,
      strictTemplateMatch: true,
      templateMatchMode: 'strict-bytes',
      verifierVatList: ['VATES-G02793479'],
      allowVerificationPartners: false,
      verificationPartnersVatList: [],
      digestAlgorithm: 'sha256',
      templateCacheTtlSeconds: 0,
      templateCacheMaxEntries: 0,
      templatePreloadEnabled: false,
      templatePreloadTenantId: 'ica',
      templatePreloadJurisdictions: ['ES'],
      templatePreloadSectors: ['animal-care'],
      templatePreloadResourceTypes: [],
      templateUseTestPrefix: false,
      fnmtIntermediateCertUrls: [],
      fnmtIntermediateCertPinsSha256: [],
      fnmtIntermediateCertPinsSha1: [],
    });

    (service as any).trustAnchorsPromise = Promise.resolve({
      rootPem: 'root',
      intermediatePems: [],
      rootSource: 'test',
      intermediateSources: ['test'],
    });

    const verifiedIndexes: number[] = [];
    (service as any).verifyPdfSignature = async (signature: { signatureIndex: number; signedData: Buffer }) => {
      verifiedIndexes.push(signature.signatureIndex);
      const signerVatId = signature.signatureIndex === 0 ? 'VATES-B42215152' : 'VATES-G02793479';
      return {
        signatureIndex: signature.signatureIndex,
        signerCert: {
          serialNumber: `serial-${signature.signatureIndex}`,
          subject: `subject-${signerVatId}`,
          issuer: 'issuer-test',
        },
        signerVatId,
        revocationStatus: 'good',
        revocationDebug: { finalStatus: 'good', checks: [] },
        notes: [`verified-${signature.signatureIndex}`],
        signedData: signature.signedData,
      };
    };

    const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/contract/_verify');
    assert.ok(parsed);
    assert.equal(parsed?.ok, true);
    if (!parsed || !parsed.ok) return;

    const result = await service.verify(parsed.context, {
      thid: 'thid-multisign-real-001',
      pdfBytes,
      contentType: 'application/pdf',
    });

    assert.deepEqual(verifiedIndexes, [0, 1]);
    assert.equal(result.signerSubject, 'subject-VATES-B42215152');
    assert.equal(
      result.notes.some((note) => note.includes('Signature 2 ignored for credential extraction')),
      true,
    );
    assert.equal(
      result.notes.some((note) => note.includes('Content/template validation skipped because resourceType=contract.')),
      true,
    );
  },
);

test('parseAddEvidenceRoute accepts valid _add route', () => {
  const parsed = parseAddEvidenceRoute('/ica/cds-ES/v1/animal-care/network/evidence/official-registry/_add');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.evidenceType, 'official-registry');
  assert.equal(parsed.context.action, '_add');
  assert.equal(
    buildAddEvidenceResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/network/evidence/official-registry/_add-response',
  );
});

test('parseIssueCredentialRoute accepts valid _issue route', () => {
  const parsed = parseIssueCredentialRoute('/ica/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.credentialType, 'member-onboarding');
  assert.equal(parsed.context.action, '_issue');
  assert.equal(
    buildIssueCredentialResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue-response',
  );
});

test('parseDelegationPolicyRoute accepts valid _upsert route', () => {
  const parsed = parseDelegationPolicyRoute('/ica/cds-ES/v1/animal-care/network/policies/delegations/_upsert');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.policyType, 'delegations');
  assert.equal(parsed.context.action, '_upsert');
  assert.equal(
    buildDelegationPolicyResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/network/policies/delegations/_upsert-response',
  );
});

test('parseCredentialStatusRoute accepts valid _status route', () => {
  const parsed = parseCredentialStatusRoute('/ica/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.credentialType, 'member-onboarding');
  assert.equal(parsed.context.action, '_status');
  assert.equal(
    buildCredentialStatusResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status-response',
  );
});

test('parseCredentialRevokeRoute accepts valid _revoke route', () => {
  const parsed = parseCredentialRevokeRoute('/ica/cds-ES/v1/animal-care/network/credentials/member-onboarding/_revoke');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.credentialType, 'member-onboarding');
  assert.equal(parsed.context.action, '_revoke');
  assert.equal(
    buildCredentialRevokeResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/network/credentials/member-onboarding/_revoke-response',
  );
});

test('parseDcatCatalogRequestRoute accepts valid catalog request route', () => {
  const parsed = parseDcatCatalogRequestRoute('/ica/cds-ES/v1/animal-care/dcat3/catalog/request');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.jurisdiction, 'ES');
  assert.equal(parsed.context.sector, 'animal-care');
  assert.equal(parsed.context.action, 'request');
});

test('parseDcatCatalogDatasetRoute accepts valid dataset route', () => {
  const parsed = parseDcatCatalogDatasetRoute('/ica/cds-ES/v1/animal-care/dcat3/catalog/datasets/zQmTaxIdHash');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.datasetId, 'zQmTaxIdHash');
  assert.equal(parsed.context.action, 'dataset');
});

test('parseDcatCatalogDdoRequestRoute accepts valid DDO catalog request route', () => {
  const parsed = parseDcatCatalogDdoRequestRoute('/ica/cds-ES/v1/animal-care/dcat3/catalog/ddo/request');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.jurisdiction, 'ES');
  assert.equal(parsed.context.sector, 'animal-care');
  assert.equal(parsed.context.action, 'ddo-request');
});

test('parseDcatCatalogDdoDatasetRoute accepts valid DDO dataset route', () => {
  const parsed = parseDcatCatalogDdoDatasetRoute('/ica/cds-ES/v1/animal-care/dcat3/catalog/ddo/datasets/zQmTaxIdHash');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.datasetId, 'zQmTaxIdHash');
  assert.equal(parsed.context.action, 'ddo-dataset');
});

test('parseSpacesRoute accepts valid _list and _replace routes', () => {
  const parsedList = parseSpacesRoute('/ica/cds-ES/v1/animal-care/network/spaces/_list');
  assert.ok(parsedList);
  assert.equal(parsedList?.ok, true);
  if (!parsedList || !parsedList.ok) return;
  assert.equal(parsedList.context.action, '_list');

  const parsedReplace = parseSpacesRoute('/ica/cds-ES/v1/animal-care/network/spaces/_replace');
  assert.ok(parsedReplace);
  assert.equal(parsedReplace?.ok, true);
  if (!parsedReplace || !parsedReplace.ok) return;
  assert.equal(parsedReplace.context.action, '_replace');
});

test('parseSpacesReplaceSubmission accepts @type and resourceType for RuntimePlatform targets', async () => {
  const payload = Buffer.from(JSON.stringify({
    type: 'https://globaldatacare.es/didcomm/ica/network/spaces/replace-request/v1',
    thid: 'spaces-replace-001',
    body: {
      data: [
        {
          '@type': 'RuntimePlatform',
          identifier: 'did:web:pontusx.example.org',
          url: 'https://adapter.example.org/metadata',
          license: 'secret-a',
        },
        {
          resourceType: 'SoftwareApplication',
          did: 'did:web:another-space.example',
          endpointUrl: 'https://another.example/metadata',
          apiKey: 'secret-b',
        },
      ],
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/ica/cds-ES/v1/animal-care/network/spaces/_replace';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseSpacesReplaceSubmission(req);
  assert.equal(parsed.thid, 'spaces-replace-001');
  assert.equal(parsed.targets.length, 2);
  assert.equal(parsed.targets[0]?.did, 'did:web:pontusx.example.org');
  assert.equal(parsed.targets[1]?.did, 'did:web:another-space.example');
});

test('parseSpacesReplaceSubmission rejects legacy target type field', async () => {
  const payload = Buffer.from(JSON.stringify({
    type: 'https://globaldatacare.es/didcomm/ica/network/spaces/replace-request/v1',
    thid: 'spaces-replace-legacy-001',
    body: {
      data: [
        {
          type: 'RuntimePlatform',
          did: 'did:web:pontusx.example.org',
          endpointUrl: 'https://adapter.example.org/metadata',
        },
      ],
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/ica/cds-ES/v1/animal-care/network/spaces/_replace';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  await assert.rejects(
    async () => parseSpacesReplaceSubmission(req),
    /unsupported field "type"/i,
  );
});

test('resolveTemplateResourceVersion respects template test prefix mode', () => {
  assert.equal(resolveTemplateResourceVersion('202603051133', false), '202603051133');
  assert.equal(resolveTemplateResourceVersion('202603051133', true), 'test-202603051133');
  assert.equal(resolveTemplateResourceVersion('test-202603051133', true), 'test-202603051133');
});

test('computePdfLogicalFingerprint ignores signature dictionary noise', () => {
  const basePdf = buildMinimalPdf(
    'BT /F1 12 Tf (HELLO TERMS) Tj ET',
  );
  const signedLikePdf = buildMinimalPdf(
    'BT /F1 12 Tf (HELLO TERMS) Tj ET',
    '/Annots [6 0 R]',
    [
      '5 0 obj',
      '<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 10 20 30] /Contents <00> >>',
      'endobj',
      '6 0 obj',
      '<< /Type /Annot /Subtype /Widget /P 3 0 R /V 5 0 R >>',
      'endobj',
    ].join('\n'),
  );

  const baseFingerprint = computePdfLogicalFingerprint(basePdf);
  const signedFingerprint = computePdfLogicalFingerprint(signedLikePdf);
  assert.ok(baseFingerprint);
  assert.ok(signedFingerprint);
  assert.equal(baseFingerprint?.hash, signedFingerprint?.hash);
});

test('computePdfLogicalFingerprint changes when page content changes', () => {
  const basePdf = buildMinimalPdf('BT /F1 12 Tf (HELLO TERMS) Tj ET');
  const changedPdf = buildMinimalPdf('BT /F1 12 Tf (HELLO OTHER) Tj ET');

  const baseFingerprint = computePdfLogicalFingerprint(basePdf);
  const changedFingerprint = computePdfLogicalFingerprint(changedPdf);
  assert.ok(baseFingerprint);
  assert.ok(changedFingerprint);
  assert.notEqual(baseFingerprint?.hash, changedFingerprint?.hash);
});

test('AuditDocumentStorageService stores verified pdf using filesystem adapter', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-audit-storage-test-'));
  try {
    const service = new AuditDocumentStorageService({
      mode: 'filesystem',
      required: true,
      attachmentUrlPattern: 'urn:uuid:{objectId}',
      filesystemDirectory: tempDir,
      gcsObjectPrefix: 'ica-audit',
    });
    const submission: VerifySubmission = {
      thid: 'thid-audit-storage-001',
      pdfBytes: Buffer.from('%PDF-1.4\nfake-pdf\n%%EOF\n', 'latin1'),
      contentType: 'application/pdf',
    };

    const enriched = await service.persistVerifiedPdf(
      parsed.context,
      submission,
      buildTestVerifyResult('audit-storage'),
    );

    assert.equal(enriched.auditDocument?.provider, 'filesystem');
    assert.equal((enriched.auditDocument?.attachmentUrl || '').startsWith('urn:uuid:'), true);
    assert.equal(typeof enriched.auditDocument?.objectKey, 'string');
    const stored = await readFile(path.join(tempDir, enriched.auditDocument?.objectKey || ''));
    assert.deepEqual(stored, submission.pdfBytes);
    assert.equal(enriched.notes.some((note) => note.includes('Audit document stored')), true);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('parseVerifyRoute rejects test-prefixed resourceType by default', () => {
  const previousUnifiedFlag = process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
  const previousLegacyFlag = process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
  delete process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
  delete process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/test-202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, false);
    if (parsed.ok) return;
    assert.equal(parsed.statusCode, 400);
    assert.match(parsed.message, /disabled/i);
  } finally {
    if (previousUnifiedFlag === undefined) {
      delete process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
    } else {
      process.env.ICA_ENABLE_TEST_TERMS_PREFIX = previousUnifiedFlag;
    }
    if (previousLegacyFlag === undefined) {
      delete process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
    } else {
      process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX = previousLegacyFlag;
    }
  }
});

test('parseVerifyRoute accepts test-prefixed resourceType when enabled', () => {
  const previousUnifiedFlag = process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
  process.env.ICA_ENABLE_TEST_TERMS_PREFIX = 'true';
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/test-202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;
    assert.equal(parsed.context.resourceType, 'test-202630011200');
  } finally {
    if (previousUnifiedFlag === undefined) {
      delete process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
    } else {
      process.env.ICA_ENABLE_TEST_TERMS_PREFIX = previousUnifiedFlag;
    }
  }
});

test('parseVerifyRoute rejects resourceType not present in ICA_TERMS_ACTIVE_RESOURCE_TYPES', () => {
  const previousActive = process.env.ICA_TERMS_ACTIVE_RESOURCE_TYPES;
  process.env.ICA_TERMS_ACTIVE_RESOURCE_TYPES = '202630011200';
  try {
    const rejected = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/202730011200/_verify');
    assert.ok(rejected);
    assert.equal(rejected.ok, false);
    if (rejected.ok) return;
    assert.equal(rejected.statusCode, 400);
    assert.match(rejected.message, /not active/i);

    const accepted = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/202630011200/_verify');
    assert.ok(accepted);
    assert.equal(accepted.ok, true);
  } finally {
    if (previousActive === undefined) {
      delete process.env.ICA_TERMS_ACTIVE_RESOURCE_TYPES;
    } else {
      process.env.ICA_TERMS_ACTIVE_RESOURCE_TYPES = previousActive;
    }
  }
});

test('parseVerifyRoute enforces ICA_LOCAL_TENANT_ID when configured', () => {
  const previousLocalTenantId = process.env.ICA_LOCAL_TENANT_ID;
  process.env.ICA_LOCAL_TENANT_ID = 'ica';
  try {
    const rejected = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/202630011200/_verify');
    assert.ok(rejected);
    assert.equal(rejected.ok, false);
    if (rejected.ok) return;
    assert.equal(rejected.statusCode, 400);
    assert.match(rejected.message, /tenantId must be "ica"/i);

    const accepted = parseVerifyRoute('/ica/cds-ES/v1/health-care/terms/pdf/202630011200/_verify');
    assert.ok(accepted);
    assert.equal(accepted.ok, true);
    if (!accepted.ok) return;
    assert.equal(accepted.context.tenantId, 'ica');
  } finally {
    if (previousLocalTenantId === undefined) {
      delete process.env.ICA_LOCAL_TENANT_ID;
    } else {
      process.env.ICA_LOCAL_TENANT_ID = previousLocalTenantId;
    }
  }
});

test('buildVerifyResponseLocation builds canonical polling path', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  const location = buildVerifyResponseLocation(parsed.context);
  assert.equal(location, '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response');
});

test('InMemoryVerificationJobStore tracks queued running and succeeded states', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  const job = store.enqueue('thid-1', parsed.context);
  assert.equal(job.status, 'queued');

  store.markRunning('thid-1');
  assert.equal(store.get('thid-1')?.status, 'running');

  store.markSucceeded('thid-1', {
    ok: true,
    verifiedAt: '2026-03-05T00:00:00.000Z',
    templateUrl: 'https://example.test/template.pdf',
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
    hashes: {
      signedPdfSha256Hex: 'a',
      unsignedPdfSha256Hex: 'b',
      templateSha256Hex: 'c',
    },
    notes: [],
  });
  assert.equal(store.get('thid-1')?.status, 'succeeded');
});

test('VerifyRequestManager accepted job includes thid query in Location', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  const manager = new VerifyRequestManager(store, {
    verify: async () => buildTestVerifyResult('fnmt-es'),
  });

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-submit-001',
    thid: 'thid-submit-001',
    type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
    attachments: [
      {
        id: 'pdf-1',
        media_type: 'application/pdf',
        data: {
          base64: Buffer.from('pdf-bytes').toString('base64'),
        },
      },
    ],
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const outcome = await manager.submit(parsed.context, req);
  assert.equal(outcome.type, 'accepted');
  if (outcome.type !== 'accepted') return;
  assert.equal(
    outcome.location,
    '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-submit-001',
  );
  assert.equal(outcome.retryAfter, 5);
});

test('VerifyRequestManager accepts DIDComm plaintext attachment payload', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  let capturedSubmission: VerifySubmission | undefined;
  const manager = new VerifyRequestManager(store, {
    verify: async (_route, submission) => {
      capturedSubmission = submission;
      return buildTestVerifyResult('fnmt-es');
    },
  });

  const payload = Buffer.from(JSON.stringify({
    jti: 'didcomm-message-001',
    thid: 'thid-didcomm-attach-001',
    type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
    body: {
      sector: 'animal-care',
    },
    attachments: [
      {
        id: 'pdf-1',
        media_type: 'application/pdf',
        data: {
          base64: Buffer.from('pdf-bytes-didcomm').toString('base64'),
        },
      },
    ],
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const outcome = await manager.submit(parsed.context, req);
  assert.equal(outcome.type, 'accepted');
  if (outcome.type !== 'accepted') return;
  assert.equal(
    outcome.location,
    '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-didcomm-attach-001',
  );
  assert.equal(outcome.retryAfter, 5);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(capturedSubmission?.thid, 'thid-didcomm-attach-001');
  assert.equal(capturedSubmission?.pdfBytes.toString('utf8'), 'pdf-bytes-didcomm');
});

test('VerifyRequestManager captures controller meta.jws key and organization JWK attachment', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  let capturedSubmission: VerifySubmission | undefined;
  const manager = new VerifyRequestManager(store, {
    verify: async (_route, submission) => {
      capturedSubmission = submission;
      return buildTestVerifyResult('fnmt-es');
    },
  });

  const payload = Buffer.from(JSON.stringify({
    jti: 'didcomm-message-keys-001',
    thid: 'thid-didcomm-keys-001',
    type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
    meta: {
      jws: {
        protected: {
          alg: 'ES384',
          kid: 'controller-es384-001',
          jwk: {
            kty: 'EC',
            crv: 'P-384',
            x: 'controller-x',
            y: 'controller-y',
          },
        },
      },
    },
    attachments: [
      {
        id: 'pdf-1',
        media_type: 'application/pdf',
        data: {
          base64: Buffer.from('pdf-bytes-didcomm').toString('base64'),
        },
      },
      {
        id: 'org-jwk-1',
        media_type: 'application/jwk+json',
        filename: 'organization-public-key.jwk.json',
        data: {
          json: {
            kty: 'EC',
            crv: 'P-384',
            x: 'org-x',
            y: 'org-y',
          },
        },
      },
    ],
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const outcome = await manager.submit(parsed.context, req);
  assert.equal(outcome.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(capturedSubmission?.controllerPublicKeyJwk?.kid, 'controller-es384-001');
  assert.equal(capturedSubmission?.organizationPublicKeyJwk?.alg, 'ES384');
  assert.equal(capturedSubmission?.organizationPublicKeyJwk?.x, 'org-x');
});

test('VerifyResponseManager returns generated organization keypair and controller public key outside resource', async () => {
  resetVerificationCollectionsMemStateForTests();
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-generated-keys-001', parsed.context);
  store.markSucceeded('thid-generated-keys-001', {
    ...buildTestVerifyResult('fnmt-es'),
    signerSubject: 'OID.2.5.4.97=VATES-B00000000, E=controller@example.org, CN=Signer',
    controllerPublicKeyJwk: {
      kty: 'EC',
      crv: 'P-384',
      x: 'controller-x',
      y: 'controller-y',
      alg: 'ES384',
      kid: 'controller-es384-001',
    },
    organizationPublicKeyJwk: {
      kty: 'EC',
      crv: 'P-384',
      x: 'org-x',
      y: 'org-y',
      alg: 'ES384',
      kid: 'org-es384-001',
    },
    organizationPrivateKeyJwk: {
      kty: 'EC',
      crv: 'P-384',
      x: 'org-x',
      y: 'org-y',
      d: 'org-d',
      alg: 'ES384',
      kid: 'org-es384-001',
    },
    organizationKeySource: 'generated',
  });

  const collectionsService = new VerificationCollectionsService();
  const manager = new VerifyResponseManager(store, collectionsService);
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;

  const outcome = await manager.poll(
    parsed.context,
    req,
    new URL('http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-generated-keys-001'),
  );
  assert.equal(outcome.type, 'succeeded');
  if (outcome.type !== 'succeeded') return;
  const payload = outcome.payload as Record<string, any>;
  assert.equal(payload.body?.data?.[0]?.publicKeyJwk?.kid, 'org-es384-001');
  assert.equal(payload.body?.data?.[0]?.privateKeyJwk?.d, 'org-d');
  assert.equal(payload.body?.data?.[0]?.keySource, 'generated');
  assert.equal(payload.body?.data?.[1]?.publicKeyJwk?.kid, 'controller-es384-001');

  const didBindings = await collectionsService.listDidBindings();
  assert.equal(didBindings.length, 1);
  assert.equal(didBindings[0]?.status, 'draft');
  assert.equal(didBindings[0]?.taxId, 'VATES-B00000000');
  assert.equal(didBindings[0]?.organizationKeySource, 'generated');
  assert.equal(didBindings[0]?.organizationPublicKeyJwk?.kid, 'org-es384-001');
  assert.equal(didBindings[0]?.controllerPublicKeyJwk?.kid, 'controller-es384-001');
  resetVerificationCollectionsMemStateForTests();
});

test('VerifyRequestManager rejects non-DIDComm content types', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  const manager = new VerifyRequestManager(store, {
    verify: async () => buildTestVerifyResult('fnmt-es'),
  });

  const payload = Buffer.from(JSON.stringify({
    thid: 'thid-json-legacy-001',
    dataBase64: Buffer.from('pdf-bytes').toString('base64'),
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/json',
    'content-length': String(payload.length),
  };

  const outcome = await manager.submit(parsed.context, req);
  assert.equal(outcome.type, 'error');
  if (outcome.type !== 'error') return;
  assert.equal(outcome.statusCode, 415);
  assert.match(outcome.message, /didcomm-plain\+json/i);
});

test('VerifyRequestManager rejects compressed DIDComm payloads', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  const manager = new VerifyRequestManager(store, {
    verify: async () => buildTestVerifyResult('fnmt-es'),
  });

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-gzip-001',
    thid: 'thid-gzip-001',
    type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
    attachments: [
      {
        id: 'pdf-1',
        media_type: 'application/pdf',
        data: { base64: Buffer.from('pdf-bytes').toString('base64') },
      },
    ],
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-encoding': 'gzip',
    'content-length': String(payload.length),
  };

  const outcome = await manager.submit(parsed.context, req);
  assert.equal(outcome.type, 'error');
  if (outcome.type !== 'error') return;
  assert.equal(outcome.statusCode, 415);
  assert.match(outcome.message, /unsupported content-encoding/i);
});

test('VerifyRequestManager sanitizes verbose openssl chain diagnostics before storing job failure', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  const manager = new VerifyRequestManager(store, {
    verify: async () => {
      throw new Error(
        'Signature 1 failed: Certificate chain validation failed: Command failed: openssl verify -CAfile /var/folders/x/y/fnmt-root.pem -untrusted /var/folders/x/y/untrusted.pem /var/folders/x/y/signer.pem C=ES, O=UANATACA error 20 at 1 depth lookup: unable to get local issuer certificate error /var/folders/x/y/signer.pem: verification failed',
      );
    },
  });

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-openssl-sanitize-001',
    thid: 'thid-openssl-sanitize-001',
    type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
    attachments: [
      {
        id: 'pdf-1',
        media_type: 'application/pdf',
        data: { base64: Buffer.from('pdf-bytes').toString('base64') },
      },
    ],
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const outcome = await manager.submit(parsed.context, req);
  assert.equal(outcome.type, 'accepted');

  await new Promise((resolve) => setImmediate(resolve));
  const job = store.get('thid-openssl-sanitize-001');
  assert.equal(job?.status, 'failed');
  assert.equal(
    job?.error,
    'Signature 1 failed: Certificate chain validation failed: unable to get local issuer certificate.',
  );
});

test(
  'buildVerificationVcBundle generates stable organization-representative VC IDs from real PDF digest',
  { skip: !existsSync(REAL_MULTISIGN_PDF_PATH) },
  () => {
    resetActiveSigningKeysStateForTests();
    activateSigningKey({
      kid: 'deterministic-key-1',
      alg: 'ES384',
      publicJwk: PUBLIC_JWK,
      privateKeyPem: PRIVATE_KEY_PEM,
    });
    const previousFlag = process.env.DETERMINISTIC_VC_BY_CONTRACT;
    const previousNamespace = process.env.DATASPACE_URN_NAMESPACE;
    process.env.DETERMINISTIC_VC_BY_CONTRACT = 'true';
    process.env.DATASPACE_URN_NAMESPACE = 'GlobalDataCare';
    try {
      const pdfBytes = readFileSync(REAL_MULTISIGN_PDF_PATH);
      const realSha3_384Hex = createHash('sha3-384').update(pdfBytes).digest('hex');
      assert.equal(realSha3_384Hex.length, 96);

      const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/contract/_verify');
      assert.ok(parsed);
      assert.equal(parsed.ok, true);
      if (!parsed.ok) return;

      const verifyResult: VerifyResult = {
        ...buildTestVerifyResult('real-pdf-deterministic'),
        digest: {
          alg: 'sha3-384',
          signedPdfHex: realSha3_384Hex,
          unsignedPdfHex: realSha3_384Hex,
          templateHex: realSha3_384Hex,
        },
        hashes: {
          signedPdfSha256Hex: 'a'.repeat(64),
          unsignedPdfSha256Hex: 'b'.repeat(64),
          templateSha256Hex: 'c'.repeat(64),
        },
      };

      const bundleA = buildVerificationVcBundle(parsed.context, verifyResult);
      const bundleB = buildVerificationVcBundle(parsed.context, verifyResult);

      const orgA = bundleA.data[0].resource as Record<string, any>;
      const orgB = bundleB.data[0].resource as Record<string, any>;
      const repA = bundleA.data[1].resource as Record<string, any>;
      const repB = bundleB.data[1].resource as Record<string, any>;

      // IDs are stable across calls with the same digest
      assert.equal(orgA.id, orgB.id);
      assert.equal(repA.id, repB.id);

      // Format: urn:<namespace>:<sector>:organization:vc:z<cidv1>
      assert.match(String(orgA.id || ''), /^urn:globaldatacare:animal-care:organization:vc:z/);
      // Representative VC uses organization-representative segment
      assert.match(String(repA.id || ''), /^urn:globaldatacare:animal-care:organization-representative:vc:z/);

      // CID in vc.id matches CID in ipfs:// attachment URL
      const docEvidence = (orgA.evidence as Array<Record<string, any>>)[1];
      assert.match(String(docEvidence.attachments?.url || ''), /^\/\/z|\/\/z|^ipfs:\/\/z/);
      assert.equal(
        String(docEvidence.attachments?.url || '').includes(String(orgA.id).split(':vc:')[1]),
        true,
      );
    } finally {
      if (previousFlag === undefined) delete process.env.DETERMINISTIC_VC_BY_CONTRACT;
      else process.env.DETERMINISTIC_VC_BY_CONTRACT = previousFlag;
      if (previousNamespace === undefined) delete process.env.DATASPACE_URN_NAMESPACE;
      else process.env.DATASPACE_URN_NAMESPACE = previousNamespace;
    }
  },
);

test(
  'buildVerificationVcBundle real prueba PDF: VC hashes with/without proof remain equal en deterministic mode and differ in non-deterministic mode',
  { skip: !existsSync(REAL_MULTISIGN_PDF_PATH) },
  () => {
    resetActiveSigningKeysStateForTests();
    activateSigningKey({
      kid: 'deterministic-key-1',
      alg: 'ES384',
      publicJwk: PUBLIC_JWK,
      privateKeyPem: PRIVATE_KEY_PEM,
    });
    const previousFlag = process.env.DETERMINISTIC_VC_BY_CONTRACT;
    const previousNamespace = process.env.DATASPACE_URN_NAMESPACE;
    try {
      const pdfBytes = readFileSync(REAL_MULTISIGN_PDF_PATH);
      const realSha3_384Hex = createHash('sha3-384').update(pdfBytes).digest('hex');

      const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/contract/_verify');
      assert.ok(parsed);
      assert.equal(parsed.ok, true);
      if (!parsed.ok) return;

      const verifyResult: VerifyResult = {
        ...buildTestVerifyResult('real-pdf-deterministic-vs-nondeterministic'),
        digest: {
          alg: 'sha3-384',
          signedPdfHex: realSha3_384Hex,
          unsignedPdfHex: realSha3_384Hex,
          templateHex: realSha3_384Hex,
        },
        hashes: {
          signedPdfSha256Hex: 'a'.repeat(64),
          unsignedPdfSha256Hex: 'b'.repeat(64),
          templateSha256Hex: 'c'.repeat(64),
        },
      };

      process.env.DETERMINISTIC_VC_BY_CONTRACT = 'true';
      process.env.DATASPACE_URN_NAMESPACE = 'GlobalDataCare';

      const deterministicA = buildVerificationVcBundle(parsed.context, verifyResult);
      const deterministicB = buildVerificationVcBundle(parsed.context, verifyResult);

      const orgDetAHash = hashVcResource(deterministicA.data[0].resource);
      const orgDetBHash = hashVcResource(deterministicB.data[0].resource);
      const repDetAHash = hashVcResource(deterministicA.data[1].resource);
      const repDetBHash = hashVcResource(deterministicB.data[1].resource);
      const orgDetAHashWithoutProof = hashVcResourceWithoutProof(deterministicA.data[0].resource);
      const orgDetBHashWithoutProof = hashVcResourceWithoutProof(deterministicB.data[0].resource);
      const repDetAHashWithoutProof = hashVcResourceWithoutProof(deterministicA.data[1].resource);
      const repDetBHashWithoutProof = hashVcResourceWithoutProof(deterministicB.data[1].resource);

      assert.equal(orgDetAHash, orgDetBHash);
      assert.equal(repDetAHash, repDetBHash);
      assert.equal(orgDetAHashWithoutProof, orgDetBHashWithoutProof);
      assert.equal(repDetAHashWithoutProof, repDetBHashWithoutProof);

      delete process.env.DETERMINISTIC_VC_BY_CONTRACT;

      const nonDeterministicA = buildVerificationVcBundle(parsed.context, verifyResult);
      const nonDeterministicB = buildVerificationVcBundle(parsed.context, verifyResult);

      const orgNonDetAHash = hashVcResource(nonDeterministicA.data[0].resource);
      const orgNonDetBHash = hashVcResource(nonDeterministicB.data[0].resource);
      const repNonDetAHash = hashVcResource(nonDeterministicA.data[1].resource);
      const repNonDetBHash = hashVcResource(nonDeterministicB.data[1].resource);
      const orgNonDetAHashWithoutProof = hashVcResourceWithoutProof(nonDeterministicA.data[0].resource);
      const orgNonDetBHashWithoutProof = hashVcResourceWithoutProof(nonDeterministicB.data[0].resource);
      const repNonDetAHashWithoutProof = hashVcResourceWithoutProof(nonDeterministicA.data[1].resource);
      const repNonDetBHashWithoutProof = hashVcResourceWithoutProof(nonDeterministicB.data[1].resource);

      assert.notEqual(orgNonDetAHash, orgNonDetBHash);
      assert.notEqual(repNonDetAHash, repNonDetBHash);
      assert.notEqual(orgNonDetAHashWithoutProof, orgNonDetBHashWithoutProof);
      assert.notEqual(repNonDetAHashWithoutProof, repNonDetBHashWithoutProof);
    } finally {
      if (previousFlag === undefined) delete process.env.DETERMINISTIC_VC_BY_CONTRACT;
      else process.env.DETERMINISTIC_VC_BY_CONTRACT = previousFlag;
      if (previousNamespace === undefined) delete process.env.DATASPACE_URN_NAMESPACE;
      else process.env.DATASPACE_URN_NAMESPACE = previousNamespace;
    }
  },
);
