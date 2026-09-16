// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import test from 'node:test';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import {
  extractVisibleOrganizationIdentityFromPdfText,
  parseLegacyContractEmailFieldsFromPlainText,
} from '../src/api/tools/terms-annex-form.ts';
import { parseVerifySubmission } from '../src/api/request-parsing.ts';
import { parseVerifyRoute } from '../src/api/path.ts';
import { InMemoryVerificationJobStore } from '../src/api/job-store.ts';
import { VerifyRequestManager } from '../src/api/managers/verify-request-manager.ts';
import type { VerifyResult, VerifySubmission } from '../src/api/types.ts';

const at = String.fromCharCode(64);
const mailbox = (localPart: string, domain: string): string => `${localPart}${at}${domain}`;

async function buildVisibleActorEmailPdf(representative: string, controller: string): Promise<Buffer> {
  const document = await PDFDocument.create();
  const font = await document.embedFont(StandardFonts.Helvetica);
  const page = document.addPage();
  page.drawText(`Nombre, cargo y correo electronico: ${representative}`, { x: 40, y: 740, font, size: 11 });
  page.drawText(`E-mail del tecnico que actuara como contacto: ${controller}`, { x: 40, y: 700, font, size: 11 });
  return Buffer.from(await document.save());
}

function buildVerifyRequest(pdfBytes: Buffer, thid: string): IncomingMessage {
  const payload = Buffer.from(JSON.stringify({
    thid,
    attachments: [{
      media_type: 'application/pdf',
      data: { base64: pdfBytes.toString('base64') },
    }],
  }));
  const request = Readable.from([payload]) as unknown as IncomingMessage;
  request.headers = {
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };
  return request;
}

function buildSuccessfulVerificationResult(): VerifyResult {
  const sha3Digest = 'a'.repeat(96);
  return {
    ok: true,
    verifiedAt: '2026-09-16T00:00:00.000Z',
    templateUrl: '',
    templateMatch: true,
    signatureValid: true,
    chainValid: true,
    revocationStatus: 'good',
    digest: {
      alg: 'sha3-384',
      signedPdfHex: sha3Digest,
      unsignedPdfHex: sha3Digest,
      templateHex: sha3Digest,
    },
    signerCertificateSerialNumber: 'synthetic-certificate',
    signerSubject: 'CN=Synthetic Signer,O=Synthetic Member,OID.2.5.4.97=VATES-TSTMEMBER01,C=ES',
    signerIssuer: 'CN=Synthetic Issuer',
    signerSigningTime: '2026-09-16T00:00:00.000Z',
    hashes: {
      signedPdfSha256Hex: 'a'.repeat(64),
      unsignedPdfSha256Hex: 'b'.repeat(64),
      templateSha256Hex: 'c'.repeat(64),
    },
    notes: [],
  };
}

test('legacy signed text maps the representative and explicitly labelled technical contact separately', () => {
  const memberDomain = ['member', 'invalid'].join('.');
  const representative = mailbox('representative', memberDomain);
  const controller = mailbox('technical', memberDomain);

  const parsed = parseLegacyContractEmailFieldsFromPlainText([
    `Nombre, cargo y correo electronico: ${representative}`,
    'Clausulas firmadas del contrato de adhesion',
    `E-mail del tecnico que actuara como contacto: ${controller}`,
  ].join('\n'));

  assert.equal(parsed.representativeEmail, representative);
  assert.equal(parsed.controllerEmail, controller);
  assert.deepEqual(parsed.warnings, []);
});

test('legacy signed text may use the third address only when it uniquely returns to the representative domain', () => {
  const memberDomain = ['member', 'invalid'].join('.');
  const verifierDomain = ['verifier', 'invalid'].join('.');
  const representative = mailbox('representative', memberDomain);
  const promoter = mailbox('promoter', verifierDomain);
  const controller = mailbox('technical', memberDomain);

  const parsed = parseLegacyContractEmailFieldsFromPlainText([
    `Parte adherente: ${representative}`,
    `Entidad promotora: ${promoter}`,
    `Contacto adicional: ${controller}`,
  ].join('\n'));

  assert.equal(parsed.representativeEmail, representative);
  assert.equal(parsed.controllerEmail, controller);
  assert.deepEqual(parsed.warnings, []);
});

test('legacy signed text fails closed when an ordinal controller inference is ambiguous', () => {
  const memberDomain = ['member', 'invalid'].join('.');
  const parsed = parseLegacyContractEmailFieldsFromPlainText([
    mailbox('first', memberDomain),
    mailbox('second', memberDomain),
    mailbox('third', memberDomain),
  ].join('\n'));

  assert.equal(parsed.representativeEmail, undefined);
  assert.equal(parsed.controllerEmail, undefined);
  assert.match(parsed.warnings.join(' '), /ambiguous/i);
});

test('legacy signed text keeps only the first labelled controller until multi-controller issuance exists', () => {
  const memberDomain = ['member', 'invalid'].join('.');
  const representative = mailbox('representative', memberDomain);
  const firstController = mailbox('technical-one', memberDomain);
  const secondController = mailbox('technical-two', memberDomain);

  const parsed = parseLegacyContractEmailFieldsFromPlainText([
    `Nombre, cargo y correo electronico: ${representative}`,
    `E-mail del tecnico: ${firstController}`,
    `E-mail del tecnico suplente: ${secondController}`,
  ].join('\n'));

  assert.equal(parsed.representativeEmail, representative);
  assert.equal(parsed.controllerEmail, firstController);
  assert.match(parsed.warnings.join(' '), /multiple technical controller/i);
});

test('visible PDF extraction preserves separate representative and controller evidence', async () => {
  const memberDomain = ['member', 'invalid'].join('.');
  const representative = mailbox('representative', memberDomain);
  const controller = mailbox('technical', memberDomain);

  const extracted = await extractVisibleOrganizationIdentityFromPdfText(
    await buildVisibleActorEmailPdf(representative, controller),
    [],
    'ES',
    { legacyContractEmails: true },
  );

  assert.equal(extracted.representativeEmail, representative);
  assert.equal(extracted.controllerEmail, controller);
});

test('compat legacy verify parsing promotes visible actor emails into signed annex fields', async () => {
  const previous = {
    mode: process.env.SECURITY_MODE,
    legacy: process.env.ICA_ALLOW_LEGACY_CONTRACT,
    inline: process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION,
  };
  const memberDomain = ['member', 'invalid'].join('.');
  const representative = mailbox('representative', memberDomain);
  const controller = mailbox('technical', memberDomain);
  const pdfBytes = await buildVisibleActorEmailPdf(representative, controller);

  try {
    process.env.SECURITY_MODE = 'compat';
    process.env.ICA_ALLOW_LEGACY_CONTRACT = 'true';
    process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION = 'true';
    const parsed = await parseVerifySubmission(
      buildVerifyRequest(pdfBytes, 'legacy-visible-actor-emails'),
      { jurisdiction: 'ES' },
    );

    assert.equal(parsed.annexFormFields?.['person.email'], representative);
    assert.equal(parsed.annexFormFields?.['organization.contactPoint.email'], controller);
  } finally {
    if (previous.mode === undefined) delete process.env.SECURITY_MODE;
    else process.env.SECURITY_MODE = previous.mode;
    if (previous.legacy === undefined) delete process.env.ICA_ALLOW_LEGACY_CONTRACT;
    else process.env.ICA_ALLOW_LEGACY_CONTRACT = previous.legacy;
    if (previous.inline === undefined) delete process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION;
    else process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION = previous.inline;
  }
});

test('strict verify parsing does not promote inferred visible actor emails', async () => {
  const previous = {
    mode: process.env.SECURITY_MODE,
    legacy: process.env.ICA_ALLOW_LEGACY_CONTRACT,
    inline: process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION,
  };
  const memberDomain = ['member', 'invalid'].join('.');
  const representative = mailbox('representative', memberDomain);
  const controller = mailbox('technical', memberDomain);
  const pdfBytes = await buildVisibleActorEmailPdf(representative, controller);

  try {
    process.env.SECURITY_MODE = 'strict';
    process.env.ICA_ALLOW_LEGACY_CONTRACT = 'true';
    process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION = 'true';
    const parsed = await parseVerifySubmission(
      buildVerifyRequest(pdfBytes, 'strict-visible-actor-emails'),
      { jurisdiction: 'ES' },
    );

    assert.equal(parsed.annexFormFields?.['person.email'], undefined);
    assert.equal(parsed.annexFormFields?.['organization.contactPoint.email'], undefined);
  } finally {
    if (previous.mode === undefined) delete process.env.SECURITY_MODE;
    else process.env.SECURITY_MODE = previous.mode;
    if (previous.legacy === undefined) delete process.env.ICA_ALLOW_LEGACY_CONTRACT;
    else process.env.ICA_ALLOW_LEGACY_CONTRACT = previous.legacy;
    if (previous.inline === undefined) delete process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION;
    else process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION = previous.inline;
  }
});

test('deferred verify extraction passes distinct visible actors to the PDF verifier', async () => {
  const previous = {
    mode: process.env.SECURITY_MODE,
    legacy: process.env.ICA_ALLOW_LEGACY_CONTRACT,
    inline: process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION,
    deferred: process.env.ICA_VERIFY_DEFER_VISIBLE_EXTRACTION,
  };
  const memberDomain = ['member', 'invalid'].join('.');
  const representative = mailbox('representative', memberDomain);
  const controller = mailbox('technical', memberDomain);
  const pdfBytes = await buildVisibleActorEmailPdf(representative, controller);
  const parsedRoute = parseVerifyRoute('/ica/cds-ES/v1/health-care/terms/pdf/202630011200/_verify');
  assert.ok(parsedRoute?.ok);
  if (!parsedRoute?.ok) return;

  let resolveSubmission: (submission: VerifySubmission) => void = () => undefined;
  const observedSubmission = new Promise<VerifySubmission>((resolve) => {
    resolveSubmission = resolve;
  });
  const manager = new VerifyRequestManager(new InMemoryVerificationJobStore(60), {
    verify: async (_route, submission) => {
      resolveSubmission(submission);
      return buildSuccessfulVerificationResult();
    },
  });

  try {
    process.env.SECURITY_MODE = 'compat';
    process.env.ICA_ALLOW_LEGACY_CONTRACT = 'true';
    process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION = 'false';
    process.env.ICA_VERIFY_DEFER_VISIBLE_EXTRACTION = 'true';
    const submitted = await manager.submit(
      parsedRoute.context,
      buildVerifyRequest(pdfBytes, 'deferred-visible-actor-emails'),
    );
    assert.equal(submitted.type, 'accepted');

    const observed = await Promise.race([
      observedSubmission,
      new Promise<never>((_resolve, reject) => {
        setTimeout(() => reject(new Error('deferred verifier input was not observed')), 5000);
      }),
    ]);
    assert.equal(observed.annexFormFields?.['person.email'], representative);
    assert.equal(observed.annexFormFields?.['organization.contactPoint.email'], controller);
  } finally {
    if (previous.mode === undefined) delete process.env.SECURITY_MODE;
    else process.env.SECURITY_MODE = previous.mode;
    if (previous.legacy === undefined) delete process.env.ICA_ALLOW_LEGACY_CONTRACT;
    else process.env.ICA_ALLOW_LEGACY_CONTRACT = previous.legacy;
    if (previous.inline === undefined) delete process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION;
    else process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION = previous.inline;
    if (previous.deferred === undefined) delete process.env.ICA_VERIFY_DEFER_VISIBLE_EXTRACTION;
    else process.env.ICA_VERIFY_DEFER_VISIBLE_EXTRACTION = previous.deferred;
  }
});
