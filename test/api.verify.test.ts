import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { InMemoryVerificationJobStore } from '../src/api/job-store.ts';
import { InMemoryActivationJobStore } from '../src/api/activation-job-store.ts';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import {
  buildActivateResponseLocation,
  buildAddEvidenceResponseLocation,
  buildCredentialRevokeResponseLocation,
  buildCredentialStatusResponseLocation,
  buildIssueCredentialResponseLocation,
  buildRotateResponseLocation,
  buildVerifyResponseLocation,
  parseActivateRoute,
  parseAddEvidenceRoute,
  parseCredentialRevokeRoute,
  parseCredentialStatusRoute,
  parseIssueCredentialRoute,
  parseRotateRoute,
  parseVerifyRoute,
} from '../src/api/path.ts';
import { buildVerificationVcBundle } from '../src/api/server.ts';
import { ActivateRequestManager } from '../src/api/managers/activate-request-manager.ts';
import { AddEvidenceRequestManager } from '../src/api/managers/add-evidence-request-manager.ts';
import { AddEvidenceResponseManager } from '../src/api/managers/add-evidence-response-manager.ts';
import { CredentialRevokeRequestManager } from '../src/api/managers/credential-revoke-request-manager.ts';
import { CredentialRevokeResponseManager } from '../src/api/managers/credential-revoke-response-manager.ts';
import { CredentialStatusRequestManager } from '../src/api/managers/credential-status-request-manager.ts';
import { CredentialStatusResponseManager } from '../src/api/managers/credential-status-response-manager.ts';
import { IssueCredentialRequestManager } from '../src/api/managers/issue-credential-request-manager.ts';
import { IssueCredentialResponseManager } from '../src/api/managers/issue-credential-response-manager.ts';
import { VerifyRequestManager } from '../src/api/managers/verify-request-manager.ts';
import { VerifyResponseManager } from '../src/api/managers/verify-response-manager.ts';
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import { computePdfLogicalFingerprint, resolveTemplateResourceVersion } from '../src/api/fnmt-pdf-verifier.ts';
import { parseActivateSigningKeySubmission } from '../src/api/request-parsing.ts';
import { SignatureVerificationManager } from '../src/api/signature-verification-manager.ts';
import { AuditDocumentStorageService } from '../src/api/tools/audit-document-storage.ts';
import { buildDidcommMessage } from '../src/api/tools/didcomm-message.ts';
import { attachProofToCredential, buildIcaDidDocument } from '../src/api/tools/ica-identity.ts';
import { activateSigningKey, resetActiveSigningKeysStateForTests } from '../src/api/tools/active-signing-keys.ts';
import {
  computeRfc7638JwkThumbprint,
  deriveDeterministicEcPrivateKeyPem,
} from '../src/api/tools/deterministic-key-material.ts';
import {
  resetVerificationCollectionsMemStateForTests,
  VerificationCollectionsService,
} from '../src/api/tools/verification-collections-storage.ts';
import type {
  AddEvidenceResult,
  AddEvidenceRouteContext,
  CredentialRevokeResult,
  CredentialRevokeRouteContext,
  CredentialStatusResult,
  CredentialStatusRouteContext,
  IssueCredentialResult,
  IssueCredentialRouteContext,
  SignatureVerifierAdapter,
  VerificationErrorDetails,
  VerifyResult,
  VerifySubmission,
} from '../src/api/types.ts';

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

test('parseVerifyRoute rejects invalid version token', () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/not-a-version/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.equal(parsed.statusCode, 400);
  assert.match(parsed.message, /resourceType/i);
});

test('parseActivateRoute accepts valid _activate route', () => {
  const parsed = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.jurisdiction, 'ES');
  assert.equal(parsed.context.sector, 'animal-care');
  assert.equal(parsed.context.action, '_activate');
});

test('buildActivateResponseLocation builds canonical polling path', () => {
  const parsed = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(
    buildActivateResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate-response',
  );
});

test('parseRotateRoute accepts credentials and communications rotate routes', () => {
  const credentials = parseRotateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_rotate');
  assert.ok(credentials);
  assert.equal(credentials?.ok, true);
  if (!credentials || !credentials.ok) return;
  assert.equal(credentials.context.resourceType, 'credentials');
  assert.equal(credentials.context.action, '_rotate');
  assert.equal(
    buildRotateResponseLocation(credentials.context),
    '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_rotate-response',
  );

  const communications = parseRotateRoute('/ica/cds-ES/v1/animal-care/entity/keys/communications/_rotate');
  assert.ok(communications);
  assert.equal(communications?.ok, true);
  if (!communications || !communications.ok) return;
  assert.equal(communications.context.resourceType, 'communications');
  assert.equal(communications.context.action, '_rotate');
  assert.equal(
    buildRotateResponseLocation(communications.context),
    '/ica/cds-ES/v1/animal-care/entity/keys/communications/_rotate-response',
  );
});

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
  const previousFlag = process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
  delete process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/test-202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, false);
    if (parsed.ok) return;
    assert.equal(parsed.statusCode, 400);
    assert.match(parsed.message, /disabled/i);
  } finally {
    if (previousFlag === undefined) {
      delete process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
    } else {
      process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX = previousFlag;
    }
  }
});

test('parseVerifyRoute accepts test-prefixed resourceType when enabled', () => {
  const previousFlag = process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
  process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX = 'true';
  try {
    const parsed = parseVerifyRoute('/acme/cds-ES/v1/health-care/terms/pdf/test-202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;
    assert.equal(parsed.context.resourceType, 'test-202630011200');
  } finally {
    if (previousFlag === undefined) {
      delete process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
    } else {
      process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX = previousFlag;
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

test('VerifyRequestManager accepted job returns Location without thid query', async () => {
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
  assert.equal(outcome.location, '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response');
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
  assert.equal(outcome.location, '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response');
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

test('parseActivateSigningKeySubmission supports body.data[] for multiple keys', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'activate-multi-001',
    thid: 'activate-multi-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
    body: {
      data: [
        {
          key: {
            kid: 'ica-es384-001',
            alg: 'ES384',
            privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nES384\\n-----END PRIVATE KEY-----',
          },
        },
        {
          key: {
            kid: 'ica-es256k-001',
            alg: 'ES256K',
            privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nES256K\\n-----END PRIVATE KEY-----',
            x5c: ['MIIBTESTX5C'],
          },
        },
      ],
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseActivateSigningKeySubmission(req);
  assert.equal(parsed.thid, 'activate-multi-001');
  assert.equal(Array.isArray(parsed.keys), true);
  assert.equal(parsed.keys.length, 2);
  assert.equal(parsed.keys[0]?.kid, 'ica-es384-001');
  assert.equal(parsed.keys[0]?.alg, 'ES384');
  assert.equal(parsed.keys[1]?.kid, 'ica-es256k-001');
  assert.equal(parsed.keys[1]?.alg, 'ES256K');
  assert.equal(parsed.keys[1]?.x5c?.[0], 'MIIBTESTX5C');
});

test('parseActivateSigningKeySubmission keeps single-key body.key compatibility', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'activate-single-001',
    thid: 'activate-single-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
    body: {
      key: {
        kid: 'ica-es384-legacy',
        alg: 'ES384',
        privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nLEGACY\\n-----END PRIVATE KEY-----',
      },
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseActivateSigningKeySubmission(req);
  assert.equal(parsed.thid, 'activate-single-001');
  assert.equal(parsed.keys.length, 1);
  assert.equal(parsed.keys[0]?.kid, 'ica-es384-legacy');
  assert.equal(parsed.keys[0]?.alg, 'ES384');
});

test('ActivateRequestManager imports deterministic ES384 and ES256K keys using RFC7638 thumbprint as kid', async () => {
  const parsedRoute = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const previousActiveKeysFile = process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-activate-deterministic-test-'));
  process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = path.join(tempDir, 'active-signing-keys.json');
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  resetActiveSigningKeysStateForTests();

  try {
    const es384 = deriveDeterministicEcPrivateKeyPem('ica-seed-es384', 'P-384');
    const es256k = deriveDeterministicEcPrivateKeyPem('ica-seed-es256k', 'secp256k1');
    const expectedKidEs384 = computeRfc7638JwkThumbprint(es384.publicJwk);
    const expectedKidEs256k = computeRfc7638JwkThumbprint(es256k.publicJwk);

    const payload = Buffer.from(JSON.stringify({
      jti: 'activate-deterministic-001',
      thid: 'activate-deterministic-001',
      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
      body: {
        data: [
          {
            key: {
              alg: 'ES384',
              privateKeyPem: es384.privateKeyPem,
            },
          },
          {
            key: {
              alg: 'ES256K',
              privateKeyPem: es256k.privateKeyPem,
            },
          },
        ],
      },
    }));
    const req = Readable.from([payload]) as unknown as IncomingMessage;
    (req as any).method = 'POST';
    (req as any).url = '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate';
    (req as any).headers = {
      host: 'localhost:3310',
      'content-type': 'application/didcomm-plain+json',
      'content-length': String(payload.length),
    };

    const jobStore = new InMemoryActivationJobStore(60);
    const manager = new ActivateRequestManager(jobStore);
    const outcome = await manager.submit(parsedRoute.context, req);
    assert.equal(outcome.type, 'accepted');
    if (outcome.type !== 'accepted') return;
    assert.equal(
      outcome.location,
      '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate-response',
    );
    await new Promise((resolve) => setImmediate(resolve));
    const job = jobStore.get('activate-deterministic-001');
    assert.ok(job);
    assert.equal(job?.status, 'succeeded');
    assert.equal(job?.result?.issuerDid, 'did:web:ica.example.com');
    assert.equal(job?.result?.activated?.length, 2);
    assert.equal(job?.result?.activated?.[0]?.kid, expectedKidEs384);
    assert.equal(job?.result?.activated?.[0]?.alg, 'ES384');
    assert.equal(job?.result?.activated?.[1]?.kid, expectedKidEs256k);
    assert.equal(job?.result?.activated?.[1]?.alg, 'ES256K');
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(tempDir, { recursive: true, force: true });
    if (previousActiveKeysFile === undefined) delete process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
    else process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = previousActiveKeysFile;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
  }
});

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
    assert.equal(personSubject.name, 'Jane Doe');
    assert.equal(personSubject.identifier, '12345678Z');
    assert.equal(personSubject.roleName, 'legal-representative');
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

test('attachProofToCredential generates invalid detached JWS proof for test resourceType', () => {
  const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/test-202603051133/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, false);
  const previousFlag = process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
  process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX = 'true';
  const parsedAllowed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/test-202603051133/_verify');
  assert.ok(parsedAllowed);
  assert.equal(parsedAllowed?.ok, true);
  if (!parsedAllowed || !parsedAllowed.ok) return;

  try {
    const vc = attachProofToCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'LegalRepresentativeCredential'],
        issuer: 'did:web:ica.example.com',
        validFrom: '2026-03-05T00:00:00.000Z',
        credentialSubject: { id: 'did:web:holder.example.com' },
      },
      parsedAllowed.context,
    );

    assert.equal(typeof vc.proof, 'object');
    const proof = Array.isArray(vc.proof) ? vc.proof[0] : vc.proof;
    assert.equal(proof?.type, 'JsonWebSignature2020');
    assert.equal(proof?.proofPurpose, 'assertionMethod');
    assert.match(String(proof?.jws || ''), /\.\./);
  } finally {
    if (previousFlag === undefined) delete process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX;
    else process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX = previousFlag;
  }
});

test('buildIcaDidDocument and production VC proof use configured signing key', () => {
  const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/202603051133/_verify');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const previousPrivateKeyPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const previousSigningAlg = process.env.ICA_VC_SIGNING_ALG;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousSigningKeyId = process.env.ICA_VC_SIGNING_KEY_ID;
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  process.env.ICA_VC_SIGNING_ALG = 'RS256';
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.ICA_VC_SIGNING_KEY_ID = 'ica-signing-key-1';
  resetActiveSigningKeysStateForTests();
  try {
    const didDocument = buildIcaDidDocument() as Record<string, unknown>;
    assert.equal(didDocument.id, 'did:web:ica.example.com');
    assert.equal(Array.isArray(didDocument.verificationMethod), true);
    assert.equal(Array.isArray(didDocument.assertionMethod), true);

    const vc = attachProofToCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'OrganizationCredential'],
        issuer: 'did:web:ica.example.com',
        validFrom: '2026-03-05T00:00:00.000Z',
        credentialSubject: { id: 'urn:organization:taxid:VATES-A12345678' },
      },
      parsed.context,
    );

    assert.equal(typeof vc.proof, 'object');
    const proof = Array.isArray(vc.proof) ? vc.proof[0] : vc.proof;
    assert.equal(proof?.verificationMethod, 'did:web:ica.example.com#ica-signing-key-1');
    assert.match(String(proof?.jws || ''), /\.\./);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousPrivateKeyPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousPrivateKeyPem;
    if (previousSigningAlg === undefined) delete process.env.ICA_VC_SIGNING_ALG;
    else process.env.ICA_VC_SIGNING_ALG = previousSigningAlg;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousSigningKeyId === undefined) delete process.env.ICA_VC_SIGNING_KEY_ID;
    else process.env.ICA_VC_SIGNING_KEY_ID = previousSigningKeyId;
  }
});

test('activated signing key is reflected in DID document immediately', async () => {
  const previousActiveKeysFile = process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousPrivateKeyPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-signing-state-test-'));
  process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = path.join(tempDir, 'active-signing-keys.json');
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const activated = activateSigningKey({
      kid: 'ica-es384-test',
      alg: 'ES384',
      privateKeyPem,
      x5c: ['MIIBTESTCHAINBASE64'],
    });

    const didDocument = buildIcaDidDocument() as Record<string, any>;
    assert.equal(didDocument.id, 'did:web:ica.example.com');
    const verificationMethod = Array.isArray(didDocument.verificationMethod)
      ? didDocument.verificationMethod
      : [];
    const method = verificationMethod.find((entry: Record<string, unknown>) => entry.id === `did:web:ica.example.com#${activated.kid}`);
    assert.ok(method);
    assert.equal(method?.publicKeyJwk?.alg, 'ES384');
    assert.equal(Array.isArray(method?.publicKeyJwk?.x5c), true);
    assert.equal(method?.publicKeyJwk?.x5c?.[0], 'MIIBTESTCHAINBASE64');
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(tempDir, { recursive: true, force: true });
    if (previousActiveKeysFile === undefined) delete process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
    else process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = previousActiveKeysFile;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousPrivateKeyPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousPrivateKeyPem;
  }
});

test('production VC proof uses recently activated signing key', async () => {
  const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/202603051133/_verify');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const previousActiveKeysFile = process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousPrivateKeyPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-signing-proof-test-'));
  process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = path.join(tempDir, 'active-signing-keys.json');
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    activateSigningKey({
      kid: 'ica-es384-proof',
      alg: 'ES384',
      privateKeyPem,
    });

    const vc = attachProofToCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'OrganizationCredential'],
        issuer: 'did:web:ica.example.com',
        validFrom: '2026-03-05T00:00:00.000Z',
        credentialSubject: { id: 'urn:organization:taxid:VATES-A12345678' },
      },
      parsed.context,
    );

    const proof = Array.isArray(vc.proof) ? vc.proof[0] : vc.proof;
    assert.equal(proof?.verificationMethod, 'did:web:ica.example.com#ica-es384-proof');
    assert.match(String(proof?.jws || ''), /\.\./);
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(tempDir, { recursive: true, force: true });
    if (previousActiveKeysFile === undefined) delete process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
    else process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = previousActiveKeysFile;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousPrivateKeyPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousPrivateKeyPem;
  }
});

test('VerifyResponseManager failed job returns bundle with resource + outcome', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-failed-001', parsed.context);
  store.markFailed('thid-failed-001', 'Signature verification failed.');

  const manager = new VerifyResponseManager(store);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-failed-001',
  );
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'failed');
  if (outcome.type !== 'failed') return;
  const payload = outcome.payload as {
    jti?: string;
    iss?: string;
    aud?: string;
    thid?: string;
    type?: string;
    body?: {
      data?: Array<{
        resource?: Record<string, unknown>;
        response?: { status?: string; outcome?: { resourceType?: string } };
      }>;
    };
  };
  assert.match(payload.jti || '', /^urn:uuid:/);
  assert.match(payload.iss || '', /^did:web:/);
  assert.match(payload.aud || '', /^did:web:/);
  assert.equal(payload.thid, 'thid-failed-001');
  assert.equal(payload.type, 'application/bundle-api+json');
  assert.equal(Array.isArray(payload.body?.data), true);
  assert.equal(payload.body?.data?.length, 1);
  assert.equal(payload.body?.data?.[0]?.response?.status, '500');
  assert.equal(payload.body?.data?.[0]?.response?.outcome?.resourceType, 'OperationOutcome');
  assert.equal(typeof payload.body?.data?.[0]?.resource?.id, 'string');
});

test('VerifyResponseManager failed job includes revocation debug details when available', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-failed-debug-001', parsed.context);
  const errorDetails: VerificationErrorDetails = {
    revocation: {
      finalStatus: 'unknown',
      checks: [
        {
          phase: 'download',
          status: 'http_error',
          url: 'http://crl.example/1.crl',
          httpStatus: 404,
          message: 'HTTP 404',
        },
        {
          phase: 'download',
          status: 'timeout',
          url: 'http://crl.example/2.crl',
          message: 'The operation was aborted due to timeout',
        },
        {
          phase: 'download',
          status: 'parse_error',
          url: 'http://crl.example/3.crl',
          message: 'unable to load CRL',
        },
      ],
    },
  };
  store.markFailed(
    'thid-failed-debug-001',
    'Revocation check did not pass (status=unknown).',
    errorDetails,
  );

  const manager = new VerifyResponseManager(store);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-failed-debug-001',
  );
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'failed');
  if (outcome.type !== 'failed') return;

  const payload = outcome.payload as {
    body?: {
      issues?: {
        issue?: Array<{ severity?: string; code?: string; diagnostics?: string }>;
      };
      data?: Array<{
        resource?: {
          content?: Array<{
            error?: string;
          }>;
        };
        response?: {
          outcome?: {
            issue?: Array<{ severity?: string; code?: string; diagnostics?: string }>;
          };
        };
      }>;
    };
  };
  const content = payload.body?.data?.[0]?.resource?.content;
  assert.equal(content?.[0]?.error, 'Revocation check did not pass (status=unknown).');
  const issues = payload.body?.issues?.issue || [];
  assert.equal(issues.length >= 4, true);
  assert.equal(issues[1]?.code, 'transient');
  assert.match(issues[1]?.diagnostics || '', /status=http_error/);
  assert.equal(issues[2]?.code, 'timeout');
  assert.match(issues[2]?.diagnostics || '', /status=timeout/);
  assert.equal(issues[3]?.code, 'structure');
  assert.match(issues[3]?.diagnostics || '', /status=parse_error/);

  const entryIssues = payload.body?.data?.[0]?.response?.outcome?.issue || [];
  assert.equal(entryIssues.length, issues.length);
});

test('VerifyResponseManager pending job returns Location without thid query', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-pending-001', parsed.context);

  const manager = new VerifyResponseManager(store);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-pending-001',
  );
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'pending');
  if (outcome.type !== 'pending') return;
  assert.equal(outcome.location, '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response');
  assert.equal(outcome.retryAfter, 5);
});

test('VerifyResponseManager uses issuer DID as aud in local-tenant mode by default', async () => {
  const previousLocalTenantId = process.env.ICA_LOCAL_TENANT_ID;
  const previousExternalDomain = process.env.ICA_EXTERNAL_DOMAIN;
  const previousAudienceDid = process.env.ICA_DIDCOMM_AUDIENCE_DID;
  process.env.ICA_LOCAL_TENANT_ID = 'ica';
  process.env.ICA_EXTERNAL_DOMAIN = 'ica.example.com';
  delete process.env.ICA_DIDCOMM_AUDIENCE_DID;
  try {
    const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;

    const store = new InMemoryVerificationJobStore(60);
    store.enqueue('thid-fixed-tenant-001', parsed.context);
    store.markFailed('thid-fixed-tenant-001', 'Signature verification failed.');

    const manager = new VerifyResponseManager(store);
    const requestUrl = new URL(
      'http://localhost/ica/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-fixed-tenant-001',
    );
    const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
    const outcome = await manager.poll(parsed.context, req, requestUrl);
    assert.equal(outcome.type, 'failed');
    if (outcome.type !== 'failed') return;

    const payload = outcome.payload as { iss?: string; aud?: string };
    assert.equal(payload.iss, 'did:web:ica.example.com');
    assert.equal(payload.aud, 'did:web:ica.example.com');
  } finally {
    if (previousLocalTenantId === undefined) {
      delete process.env.ICA_LOCAL_TENANT_ID;
    } else {
      process.env.ICA_LOCAL_TENANT_ID = previousLocalTenantId;
    }
    if (previousExternalDomain === undefined) {
      delete process.env.ICA_EXTERNAL_DOMAIN;
    } else {
      process.env.ICA_EXTERNAL_DOMAIN = previousExternalDomain;
    }
    if (previousAudienceDid === undefined) {
      delete process.env.ICA_DIDCOMM_AUDIENCE_DID;
    } else {
      process.env.ICA_DIDCOMM_AUDIENCE_DID = previousAudienceDid;
    }
  }
});

test('buildIcaVerifyOpenApiSpec exposes verify and polling paths', () => {
  const openApi = buildIcaVerifyOpenApiSpec();
  assert.equal(openApi.openapi, '3.1.0');
  assert.match(openApi.info.description, /alternateName \"ica\"/i);
  assert.ok(openApi.paths['/.well-known/did.json']);
  assert.ok(openApi.paths['/did.json']);
  assert.ok(Array.isArray(openApi.tags));
  assert.equal(openApi.tags.some((tag) => tag.name === 'terms/pdf'), true);
  assert.equal(openApi.tags.some((tag) => tag.name === 'network/evidence'), true);
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate'],
  );
  assert.ok(openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify']);
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response'],
  );
  const activateDidcommExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.examples;
  const activateDidcommSchema =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.schema as any;
  assert.ok(activateDidcommExamples?.activateEs384);
  assert.ok(activateDidcommExamples?.activateMultipleKeys);
  assert.ok(activateDidcommSchema?.properties?.body?.properties?.data);
  assert.equal(Array.isArray(activateDidcommSchema?.properties?.body?.oneOf), true);

  const addDidcommExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  const addDidcommSchema =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.schema as any;
  assert.ok(addDidcommExamples?.addOfficialRegistryEvidence);
  assert.ok(addDidcommExamples?.addOfficialRegistryEvidenceBatch);
  assert.ok(addDidcommSchema?.properties?.body?.properties?.data);
  assert.equal(Array.isArray(addDidcommSchema?.properties?.body?.oneOf), true);

  const verifyErrorSchema =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify']
      ?.post
      ?.responses?.['400']
      ?.content?.['application/didcomm-plain+json']
      ?.schema as any;
  assert.equal(verifyErrorSchema?.properties?.body?.properties?.total?.enum?.[0], 0);
  assert.equal(verifyErrorSchema?.properties?.body?.properties?.data?.maxItems, 0);
  assert.deepEqual(verifyErrorSchema?.properties?.body?.properties?.data?.example, []);
  assert.deepEqual(verifyErrorSchema?.properties?.body?.example?.data, []);
  assert.equal(verifyErrorSchema?.properties?.body?.properties?.result, undefined);

  const verifyPollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  const verifySuccessData = verifyPollingExamples?.verificationSucceededWithEvidence?.value?.body?.data;
  assert.ok(Array.isArray(verifySuccessData));
  assert.equal(verifySuccessData?.length, 2);
  assert.ok(Array.isArray(verifySuccessData?.[0]?.resource?.evidence));
  assert.ok(Array.isArray(verifySuccessData?.[1]?.resource?.evidence));
  assert.ok(verifyPollingExamples?.verificationFailed);

  const activatePollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.ok(Array.isArray(activatePollingExamples?.activationCompleted?.value?.body?.data?.[0]?.resource?.content));
  assert.equal(
    activatePollingExamples?.activationCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.alg,
    'ES384',
  );

  const addPollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    addPollingExamples?.addEvidenceCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.evidenceType,
    'official-registry',
  );
  assert.equal(
    addPollingExamples?.addEvidenceCompleted?.value?.body?.issues?.issue?.[0]?.diagnostics,
    'Evidence record(s) stored: 2.',
  );

  const issuePollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    issuePollingExamples?.issueCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.credentialType,
    'member-onboarding',
  );

  const statusPollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    statusPollingExamples?.statusCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.status,
    'good',
  );

  const revokePollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    revokePollingExamples?.revokeCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.status,
    'revoked',
  );
});

test('buildDidcommMessage defaults to bundle api type and keeps query thid', () => {
  const req = {
    headers: { host: 'localhost:3310' },
    url: '/ica/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-from-query-001',
  } as unknown as IncomingMessage;
  const payload = buildDidcommMessage(req, {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 0,
    data: [],
  });
  assert.equal(payload.type, 'application/bundle-api+json');
  assert.equal(payload.thid, 'thid-from-query-001');
  assert.match(payload.iss || '', /^did:web:/);
  assert.match(payload.aud || '', /^did:web:/);
});

test('buildDidcommMessage supports empty correlation fields for early errors', () => {
  const req = {
    headers: { host: 'localhost:3310' },
    url: '/unknown-endpoint',
  } as unknown as IncomingMessage;
  const payload = buildDidcommMessage(req, {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 0,
    data: [],
  }, {
    thidFallback: 'empty',
    audFallback: 'empty',
  });
  assert.equal(payload.type, 'application/bundle-api+json');
  assert.equal(payload.thid, '');
  assert.equal(payload.aud, '');
  assert.match(payload.iss || '', /^did:web:/);
});

test('VerifyResponseManager succeeded job returns result inside body', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const verifyResult: VerifyResult = {
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
  };

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-ok-001', parsed.context);
  store.markSucceeded('thid-ok-001', verifyResult);

  const manager = new VerifyResponseManager(store);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-ok-001',
  );
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'succeeded');
  if (outcome.type !== 'succeeded') return;

  const payload = outcome.payload as {
    jti?: string;
    iss?: string;
    aud?: string;
    thid?: string;
    type?: string;
    result?: unknown;
    body?: {
      result?: { ok?: boolean; templateUrl?: string };
    };
  };
  assert.match(payload.jti || '', /^urn:uuid:/);
  assert.match(payload.iss || '', /^did:web:/);
  assert.match(payload.aud || '', /^did:web:/);
  assert.equal(payload.thid, 'thid-ok-001');
  assert.equal(payload.type, 'application/bundle-api+json');
  assert.equal(payload.result, undefined);
  assert.equal(payload.body?.result?.ok, true);
  assert.equal(payload.body?.result?.templateUrl, 'https://example.test/template.pdf');
});

test('VerifyResponseManager stores issued credentials and evidence using mem collections adapter', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
    issuedCredentialsCollection: 'issued_credentials',
    evidenceCollection: 'evidence_records',
  });

  const verifyResult: VerifyResult = {
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
    notes: [],
  };

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-persist-001', parsed.context);
  store.markSucceeded('thid-persist-001', verifyResult);

  const manager = new VerifyResponseManager(store, collectionsService);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-persist-001',
  );
  const req = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'succeeded');

  const issued = (await collectionsService.listIssuedCredentials())
    .filter((item) => item.thid === 'thid-persist-001');
  const evidence = (await collectionsService.listEvidenceRecords())
    .filter((item) => item.thid === 'thid-persist-001');
  assert.equal(issued.length, 2);
  assert.equal(evidence.length, 4);
  assert.equal(issued.every((item) => item.tenantId === 'acme'), true);
  assert.equal(evidence.every((item) => item.tenantId === 'acme'), true);
});

test('AddEvidence managers persist evidence records using mem collections adapter', async () => {
  const parsed = parseAddEvidenceRoute('/acme/cds-ES/v1/animal-care/network/evidence/official-registry/_add');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
    issuedCredentialsCollection: 'issued_credentials',
    evidenceCollection: 'evidence_records',
  });

  const store = new InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>(60);
  const requestManager = new AddEvidenceRequestManager(store, collectionsService);
  const responseManager = new AddEvidenceResponseManager(store);

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-evidence-add-001',
    thid: 'thid-evidence-add-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
    body: {
      data: [
        {
          issuedCredentialRecordId: 'urn:uuid:issued-existing-001',
          operatorDid: 'did:web:ica.example.com#employee-1',
          evidence: {
            type: 'electronic_record',
            time: '2026-03-06T10:00:00.000Z',
            verifier: {
              organization: 'did:web:localhost%3A3310',
            },
            record: {
              type: 'official-registry',
              source: {
                id: 'did:web:registry.example.org',
                type: 'PublicRegistry',
              },
            },
            attachments: [
              {
                digest: {
                  alg: 'sha3-384',
                  value: 'c2lnbmF0dXJl',
                },
                url: 'urn:uuid:evidence-doc-001',
              },
            ],
          },
        },
        {
          issuedCredentialRecordId: 'urn:uuid:issued-existing-001',
          operatorDid: 'did:web:ica.example.com#employee-2',
          evidence: {
            type: 'document',
            method: 'eid',
            time: '2026-03-06T10:05:00.000Z',
            verifier: {
              organization: 'did:web:localhost%3A3310',
            },
            document_details: {
              type: 'official-registry-certificate',
              document_number: 'B-123456',
            },
            attachments: {
              digest: {
                alg: 'sha3-384',
                value: 'ZG9jdW1lbnQ=',
              },
              url: 'urn:uuid:evidence-doc-002',
            },
          },
        },
      ],
    },
  }));

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/evidence/official-registry/_add';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsed.context, req);
  assert.equal(submitOutcome.type, 'accepted');
  if (submitOutcome.type !== 'accepted') return;
  assert.equal(
    submitOutcome.location,
    '/acme/cds-ES/v1/animal-care/network/evidence/official-registry/_add-response',
  );
  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/evidence/official-registry/_add-response?thid=thid-evidence-add-001',
  );
  const pollOutcome = await responseManager.poll(parsed.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');

  const evidence = (await collectionsService.listEvidenceRecords())
    .filter((item) => item.thid === 'thid-evidence-add-001');
  assert.equal(evidence.length, 2);
  assert.equal(evidence[0]?.evidenceType, 'official-registry');
  assert.equal(evidence[0]?.tenantId, 'acme');
  if (pollOutcome.type === 'succeeded') {
    const payloadBody = (pollOutcome.payload as any)?.body;
    assert.equal(payloadBody?.data?.[0]?.resource?.content?.length, 2);
  }
});

test('AddEvidence managers reject non-OIDC4IDA evidence payload', async () => {
  const parsed = parseAddEvidenceRoute('/acme/cds-ES/v1/animal-care/network/evidence/address/_add');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const store = new InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>(60);
  const requestManager = new AddEvidenceRequestManager(store);
  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-evidence-add-invalid-001',
    thid: 'thid-evidence-add-invalid-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
    body: {
      evidence: {
        type: 'address',
        checkedAt: '2026-03-06T10:00:00.000Z',
      },
    },
  }));

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/evidence/address/_add';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const outcome = await requestManager.submit(parsed.context, req);
  assert.equal(outcome.type, 'error');
  if (outcome.type !== 'error') return;
  assert.equal(outcome.statusCode, 400);
  assert.match(outcome.message, /Invalid OIDC4IDA evidence payload/i);
  assert.match(outcome.message, /body\.evidence\.type must be one of/i);
});

test('IssueCredential managers persist credential and evidence records using mem collections adapter', async () => {
  const parsed = parseIssueCredentialRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
    issuedCredentialsCollection: 'issued_credentials',
    evidenceCollection: 'evidence_records',
  });

  const store = new InMemoryEntityJobStore<IssueCredentialRouteContext, IssueCredentialResult>(60);
  const requestManager = new IssueCredentialRequestManager(store, collectionsService);
  const responseManager = new IssueCredentialResponseManager(store);

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-credential-issue-001',
    thid: 'thid-credential-issue-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/issue-request/v1',
    body: {
      credential: {
        id: 'urn:uuid:vc-member-001',
        type: ['VerifiableCredential', 'MemberCredential'],
        issuer: 'did:web:ica.example.com',
        credentialSubject: {
          id: 'mailto:member@example.org',
          memberNumber: 'COL-0001',
        },
        evidence: [
          {
            type: 'official-registry',
            checkedAt: '2026-03-06T10:01:00.000Z',
          },
        ],
      },
      evidence: [
        {
          type: 'qualification',
          checkedAt: '2026-03-06T10:02:00.000Z',
        },
      ],
    },
  }));

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsed.context, req);
  assert.equal(submitOutcome.type, 'accepted');
  if (submitOutcome.type !== 'accepted') return;
  assert.equal(
    submitOutcome.location,
    '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue-response',
  );
  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue-response?thid=thid-credential-issue-001',
  );
  const pollOutcome = await responseManager.poll(parsed.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');

  const issued = (await collectionsService.listIssuedCredentials())
    .filter((item) => item.thid === 'thid-credential-issue-001');
  const evidence = (await collectionsService.listEvidenceRecords())
    .filter((item) => item.thid === 'thid-credential-issue-001');
  assert.equal(issued.length, 1);
  assert.equal(issued[0]?.credentialType, 'member-onboarding');
  assert.equal(issued[0]?.subjectId, 'mailto:member@example.org');
  assert.equal(evidence.length, 2);
});

test('Credential status and revoke managers resolve and update revocation state', async () => {
  const parsedIssue = parseIssueCredentialRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue');
  const parsedStatus = parseCredentialStatusRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status');
  const parsedRevoke = parseCredentialRevokeRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_revoke');
  assert.ok(parsedIssue && parsedIssue.ok);
  assert.ok(parsedStatus && parsedStatus.ok);
  assert.ok(parsedRevoke && parsedRevoke.ok);
  if (!parsedIssue || !parsedIssue.ok || !parsedStatus || !parsedStatus.ok || !parsedRevoke || !parsedRevoke.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
    issuedCredentialsCollection: 'issued_credentials',
    evidenceCollection: 'evidence_records',
  });

  const issueStore = new InMemoryEntityJobStore<IssueCredentialRouteContext, IssueCredentialResult>(60);
  const issueRequestManager = new IssueCredentialRequestManager(issueStore, collectionsService);
  const issueResponseManager = new IssueCredentialResponseManager(issueStore);
  const statusStore = new InMemoryEntityJobStore<CredentialStatusRouteContext, CredentialStatusResult>(60);
  const statusRequestManager = new CredentialStatusRequestManager(statusStore, collectionsService);
  const statusResponseManager = new CredentialStatusResponseManager(statusStore);
  const revokeStore = new InMemoryEntityJobStore<CredentialRevokeRouteContext, CredentialRevokeResult>(60);
  const revokeRequestManager = new CredentialRevokeRequestManager(revokeStore, collectionsService);
  const revokeResponseManager = new CredentialRevokeResponseManager(revokeStore);

  const credentialId = 'urn:uuid:vc-member-status-001';
  const issuePayload = Buffer.from(JSON.stringify({
    jti: 'msg-credential-issue-status-001',
    thid: 'thid-credential-issue-status-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/issue-request/v1',
    body: {
      credential: {
        id: credentialId,
        type: ['VerifiableCredential', 'MemberCredential'],
        issuer: 'did:web:ica.example.com',
        credentialSubject: {
          id: 'mailto:member-status@example.org',
        },
      },
      evidence: [],
    },
  }));
  const issueReq = Readable.from([issuePayload]) as unknown as IncomingMessage;
  (issueReq as any).method = 'POST';
  (issueReq as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue';
  (issueReq as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(issuePayload.length),
  };
  const issueSubmitOutcome = await issueRequestManager.submit(parsedIssue.context, issueReq);
  assert.equal(issueSubmitOutcome.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const issuePollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const issuePollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue-response?thid=thid-credential-issue-status-001',
  );
  const issuePollOutcome = await issueResponseManager.poll(parsedIssue.context, issuePollReq, issuePollUrl);
  assert.equal(issuePollOutcome.type, 'succeeded');

  const statusPayloadBefore = Buffer.from(JSON.stringify({
    jti: 'msg-credential-status-before-001',
    thid: 'thid-credential-status-before-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/status-request/v1',
    body: {
      credentialId,
    },
  }));
  const statusReqBefore = Readable.from([statusPayloadBefore]) as unknown as IncomingMessage;
  (statusReqBefore as any).method = 'POST';
  (statusReqBefore as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status';
  (statusReqBefore as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(statusPayloadBefore.length),
  };
  const statusSubmitBefore = await statusRequestManager.submit(parsedStatus.context, statusReqBefore);
  assert.equal(statusSubmitBefore.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const statusPollReqBefore = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const statusPollUrlBefore = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status-response?thid=thid-credential-status-before-001',
  );
  const statusPollOutcomeBefore = await statusResponseManager.poll(
    parsedStatus.context,
    statusPollReqBefore,
    statusPollUrlBefore,
  );
  assert.equal(statusPollOutcomeBefore.type, 'succeeded');
  if (statusPollOutcomeBefore.type !== 'succeeded') return;
  const statusPayloadResolvedBefore = statusPollOutcomeBefore.payload as {
    body?: { data?: Array<{ resource?: { content?: Array<{ status?: string }> } }> };
  };
  assert.equal(statusPayloadResolvedBefore.body?.data?.[0]?.resource?.content?.[0]?.status, 'good');

  const revokePayload = Buffer.from(JSON.stringify({
    jti: 'msg-credential-revoke-001',
    thid: 'thid-credential-revoke-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/revoke-request/v1',
    body: {
      credentialId,
      reason: 'membership-terminated',
      revokedBy: 'did:web:ica.example.com#employee-07',
    },
  }));
  const revokeReq = Readable.from([revokePayload]) as unknown as IncomingMessage;
  (revokeReq as any).method = 'POST';
  (revokeReq as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_revoke';
  (revokeReq as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(revokePayload.length),
  };
  const revokeSubmitOutcome = await revokeRequestManager.submit(parsedRevoke.context, revokeReq);
  assert.equal(revokeSubmitOutcome.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const revokePollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const revokePollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_revoke-response?thid=thid-credential-revoke-001',
  );
  const revokePollOutcome = await revokeResponseManager.poll(parsedRevoke.context, revokePollReq, revokePollUrl);
  assert.equal(revokePollOutcome.type, 'succeeded');

  const statusPayloadAfter = Buffer.from(JSON.stringify({
    jti: 'msg-credential-status-after-001',
    thid: 'thid-credential-status-after-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/status-request/v1',
    body: {
      credentialId,
    },
  }));
  const statusReqAfter = Readable.from([statusPayloadAfter]) as unknown as IncomingMessage;
  (statusReqAfter as any).method = 'POST';
  (statusReqAfter as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status';
  (statusReqAfter as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(statusPayloadAfter.length),
  };
  const statusSubmitAfter = await statusRequestManager.submit(parsedStatus.context, statusReqAfter);
  assert.equal(statusSubmitAfter.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const statusPollReqAfter = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const statusPollUrlAfter = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status-response?thid=thid-credential-status-after-001',
  );
  const statusPollOutcomeAfter = await statusResponseManager.poll(
    parsedStatus.context,
    statusPollReqAfter,
    statusPollUrlAfter,
  );
  assert.equal(statusPollOutcomeAfter.type, 'succeeded');
  if (statusPollOutcomeAfter.type !== 'succeeded') return;
  const statusPayloadResolvedAfter = statusPollOutcomeAfter.payload as {
    body?: {
      data?: Array<{ resource?: { content?: Array<{ status?: string; revokedAt?: string }> } }>;
    };
  };
  assert.equal(statusPayloadResolvedAfter.body?.data?.[0]?.resource?.content?.[0]?.status, 'revoked');
  assert.equal(Boolean(statusPayloadResolvedAfter.body?.data?.[0]?.resource?.content?.[0]?.revokedAt), true);

  const issued = await collectionsService.listIssuedCredentials();
  const updated = issued.find((entry) => entry.credentialId === credentialId);
  assert.ok(updated);
  const credentialStatus = (updated?.credential?.credentialStatus || {}) as Record<string, unknown>;
  assert.equal(credentialStatus.status, 'revoked');
});

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

function buildAdapter(
  id: string,
  supportsJurisdiction: string,
  calls: string[],
): SignatureVerifierAdapter {
  return {
    id,
    supports: (route) => route.jurisdiction.toLowerCase() === supportsJurisdiction.toLowerCase(),
    verify: async (_route, _submission) => {
      calls.push(id);
      return buildTestVerifyResult(id);
    },
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

test('SignatureVerificationManager uses preferred adapter when supported', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const calls: string[] = [];
  const manager = new SignatureVerificationManager(
    [
      buildAdapter('fnmt-es', 'ES', calls),
      buildAdapter('camerfirma-es', 'ES', calls),
    ],
    {
      preferredAdapterId: 'camerfirma-es',
      strictPreferredAdapter: true,
    },
  );

  const submission: VerifySubmission = {
    thid: 'thid-adapter-1',
    pdfBytes: Buffer.from('pdf'),
    contentType: 'application/pdf',
  };
  const result = await manager.verify(parsed.context, submission);
  assert.deepEqual(calls, ['camerfirma-es']);
  assert.equal(result.notes[0], 'camerfirma-es');
});

test('SignatureVerificationManager falls back when preferred adapter is unsupported and strict=false', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const calls: string[] = [];
  const manager = new SignatureVerificationManager(
    [
      buildAdapter('fnmt-es', 'ES', calls),
      buildAdapter('camerfirma-pt', 'PT', calls),
    ],
    {
      preferredAdapterId: 'camerfirma-pt',
      strictPreferredAdapter: false,
    },
  );

  const submission: VerifySubmission = {
    thid: 'thid-adapter-2',
    pdfBytes: Buffer.from('pdf'),
    contentType: 'application/pdf',
  };
  const result = await manager.verify(parsed.context, submission);
  assert.deepEqual(calls, ['fnmt-es']);
  assert.equal(result.notes[0], 'fnmt-es');
});

test('SignatureVerificationManager fails when no adapter supports the request', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const manager = new SignatureVerificationManager([
    {
      id: 'camerfirma-pt',
      supports: () => false,
      verify: async () => buildTestVerifyResult('camerfirma-pt'),
    },
  ]);

  const submission: VerifySubmission = {
    thid: 'thid-adapter-3',
    pdfBytes: Buffer.from('pdf'),
    contentType: 'application/pdf',
  };

  await assert.rejects(
    async () => manager.verify(parsed.context, submission),
    /No signature verifier adapter supports jurisdiction/i,
  );
});
