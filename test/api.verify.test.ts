import assert from 'node:assert/strict';
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
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import {
  computePdfLogicalFingerprint,
  FnmtPdfVerificationService,
  parseVatIdFromSubjectDn,
  resolveTemplateResourceVersion,
  selectPrimaryCredentialSignature,
} from '../src/api/fnmt-pdf-verifier.ts';
import { AuditDocumentStorageService } from '../src/api/tools/audit-document-storage.ts';
import { buildDidcommMessage } from '../src/api/tools/didcomm-message.ts';
import { parseSpacesReplaceSubmission } from '../src/api/request-parsing.ts';
import type {
  VerifyResult,
  VerifySubmission,
} from '../src/api/types.ts';

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

const REAL_MULTISIGN_PDF_PATH = '/Users/fernando/GITS/gdc-workspace/TEST-A4-multisign-fnmt.pdf';

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

test('parseVerifyRoute accepts onehealth-prefixed sector variants', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-veterinary/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.sector, 'health-veterinary');
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
  );
  assert.deepEqual(selected, { signatureIndex: 1, signerVatId: 'VATES-B22222222' });
});

test(
  'selectPrimaryCredentialSignature handles the real FNMT multisign PDF regardless of which verifier VAT is configured',
  { skip: !existsSync(REAL_MULTISIGN_PDF_PATH) },
  () => {
    const signerVatIds = extractSignerVatIdsFromRealPdf(REAL_MULTISIGN_PDF_PATH);
    assert.deepEqual(signerVatIds, ['VATES-B42215152', 'VATES-G02793479']);

    const signatures = signerVatIds.map((signerVatId, signatureIndex) => ({ signatureIndex, signerVatId }));

    const verifierIsUnid = selectPrimaryCredentialSignature(signatures, ['VATES-G02793479']);
    assert.deepEqual(verifierIsUnid, { signatureIndex: 0, signerVatId: 'VATES-B42215152' });

    const verifierIsConectate = selectPrimaryCredentialSignature(signatures, ['VATES-B42215152']);
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
      templateUrlPattern: 'https://example.test/{resourceVersion}.pdf',
      strictRevocation: true,
      strictTemplateMatch: true,
      templateMatchMode: 'strict-bytes',
      verifierVatList: ['VATES-G02793479'],
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
    signerSubject: 'CN=Signer',
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
