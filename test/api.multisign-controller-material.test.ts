import assert from 'node:assert/strict';
import type { IncomingMessage } from 'node:http';
import test from 'node:test';
import { readFileSync, existsSync } from 'node:fs';
import { Readable } from 'node:stream';
import path from 'node:path';
import { homedir } from 'node:os';
import { toJwkThumbprintSha256Urn } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import { parseVerifyRoute, parseCredentialRetrieveRoute } from '../src/api/path.ts';
import { InMemoryVerificationJobStore } from '../src/api/job-store.ts';
import { VerifyRequestManager } from '../src/api/managers/verify-request-manager.ts';
import { VerifyResponseManager } from '../src/api/managers/verify-response-manager.ts';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import { CredentialRetrieveRequestManager } from '../src/api/managers/credential-retrieve-request-manager.ts';
import {
  VerificationCollectionsService,
  resetVerificationCollectionsMemStateForTests,
} from '../src/api/tools/verification-collections-storage.ts';
import { deriveDeterministicEcPrivateKeyPem } from '../src/api/tools/deterministic-key-material.ts';
import type {
  CredentialRetrieveResult,
  CredentialRetrieveRouteContext,
  PdfVerificationService,
  VerifyResult,
  VerifySubmission,
} from '../src/api/types.ts';

const REAL_FNMT_FIXTURES_DIR = path.join(homedir(), 'GITS', 'gdc-workspace', 'examples');
const REAL_MULTISIGN_PDF_PATH = path.join(REAL_FNMT_FIXTURES_DIR, 'prueba-TEST-A4-multisign-fnmt.pdf');

function buildMockVerifyResult(): VerifyResult {
  const validSha3_384Hex = 'a'.repeat(96);
  return {
    ok: true,
    verifiedAt: '2026-03-05T00:00:00.000Z',
    templateUrl: 'https://example.test/prueba-TEST-A4-multisign-fnmt.pdf',
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
    signerSubject: 'CN=TEST LEGAL REPRESENTATIVE, O=TEST HEALTHCARE SL, OID.2.5.4.97=VATES-B00112233, SERIALNUMBER=12345678Z, C=ES',
    signerIssuer: 'CN=FNMT',
    signerSigningTime: '2026-03-05T00:00:00.000Z',
    hashes: {
      signedPdfSha256Hex: 'a'.repeat(64),
      unsignedPdfSha256Hex: 'b'.repeat(64),
      templateSha256Hex: 'c'.repeat(64),
    },
    notes: ['multisign-fixture-local-test'],
  };
}

test(
  'real multisign PDF + controller JWK in _verify persists binding and retrieve v2 returns expected representative fields',
  { skip: !existsSync(REAL_MULTISIGN_PDF_PATH) },
  async () => {
    const previousDidWebDomain = process.env.DID_WEB_DOMAIN;
    process.env.DID_WEB_DOMAIN = 'did:web:globaldatacare.es';
    resetVerificationCollectionsMemStateForTests();

    try {
      const controllerKey = deriveDeterministicEcPrivateKeyPem('multisign-controller-binding', 'P-384');
      const pdfBytes = readFileSync(REAL_MULTISIGN_PDF_PATH);

      const verifyParsed = parseVerifyRoute('/ica/cds-ES/v1/health-care/terms/pdf/contract/_verify');
      assert.ok(verifyParsed && verifyParsed.ok);
      if (!verifyParsed || !verifyParsed.ok) return;

      let capturedSubmission: VerifySubmission | undefined;
      const verifier: PdfVerificationService = {
        verify: async (_route, submission) => {
          capturedSubmission = submission;
          return buildMockVerifyResult();
        },
      };

      const verifyStore = new InMemoryVerificationJobStore(60);
      const verifyManager = new VerifyRequestManager(verifyStore, verifier);
      const collectionsService = new VerificationCollectionsService({
        provider: 'mem',
        required: true,
        firestoreCollectionPrefix: 'ica',
      });
      const verifyResponseManager = new VerifyResponseManager(verifyStore, collectionsService);

      const verifyPayload = Buffer.from(JSON.stringify({
        id: 'didcomm-verify-real-multisign-001',
        thid: 'thid-verify-real-multisign-001',
        type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
        body: {
          data: [
            {
              resource: {
                controller: {
                  publicKeyJwk: controllerKey.publicJwk,
                },
              },
            },
          ],
        },
        attachments: [
          {
            id: 'pdf-1',
            media_type: 'application/pdf',
            data: {
              base64: pdfBytes.toString('base64'),
            },
          },
        ],
      }));

      const verifyReq = Readable.from([verifyPayload]) as unknown as IncomingMessage;
      (verifyReq as any).method = 'POST';
      (verifyReq as any).url = '/ica/cds-ES/v1/health-care/terms/pdf/contract/_verify';
      (verifyReq as any).headers = {
        host: 'localhost:3310',
        'content-type': 'application/didcomm-plain+json',
        'content-length': String(verifyPayload.length),
      };

      const submitOutcome = await verifyManager.submit(verifyParsed.context, verifyReq);
      assert.equal(submitOutcome.type, 'accepted');
      await new Promise((resolve) => setImmediate(resolve));

      assert.equal(
        toJwkThumbprintSha256Urn(capturedSubmission?.controllerPublicKeyJwk as Record<string, unknown>),
        toJwkThumbprintSha256Urn(controllerKey.publicJwk as Record<string, unknown>),
      );

      const verifyPollParsed = parseVerifyRoute('/ica/cds-ES/v1/health-care/terms/pdf/contract/_verify-response');
      assert.ok(verifyPollParsed && verifyPollParsed.ok);
      if (!verifyPollParsed || !verifyPollParsed.ok) return;

      const verifyPollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
      const verifyPollUrl = new URL(
        'http://localhost/ica/cds-ES/v1/health-care/terms/pdf/contract/_verify-response?thid=thid-verify-real-multisign-001',
      );
      const verifyPollOutcome = await verifyResponseManager.poll(verifyPollParsed.context, verifyPollReq, verifyPollUrl);
      assert.equal(verifyPollOutcome.type, 'succeeded');

      const didBindings = await collectionsService.listDidBindings();
      assert.equal(didBindings.length, 1);
      assert.equal(didBindings[0]?.taxId, 'VATES-B00112233');
      assert.equal(
        toJwkThumbprintSha256Urn(didBindings[0]?.controllerPublicKeyJwk as Record<string, unknown>),
        toJwkThumbprintSha256Urn(controllerKey.publicJwk as Record<string, unknown>),
      );

      const retrieveParsed = parseCredentialRetrieveRoute('/ica/cds-ES/v1/health-care/network/credentials/contract/_retrieve');
      assert.ok(retrieveParsed && retrieveParsed.ok);
      if (!retrieveParsed || !retrieveParsed.ok) return;

      const retrieveStore = new InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>(60);
      const retrieveManager = new CredentialRetrieveRequestManager(retrieveStore, collectionsService);
      const retrieveUrl = new URL(
        'http://localhost/ica/cds-ES/v1/health-care/network/credentials/contract/_retrieve?identifier=VATES-B00112233&type=LegalRepresentativeCredential&format=vc+json&version=v2',
      );
      const retrieveOutcome = await retrieveManager.retrieveDirect(
        retrieveParsed.context,
        retrieveUrl,
        'application/vc+json',
      );
      assert.equal(retrieveOutcome.type, 'succeeded');
      if (retrieveOutcome.type !== 'succeeded') return;

      const vcTypes = retrieveOutcome.credential?.type as unknown[];
      const credentialSubject = retrieveOutcome.credential?.credentialSubject as Record<string, unknown>;
      const memberOf = credentialSubject?.memberOf as Record<string, unknown>;
      const occupation = credentialSubject?.hasOccupation as Record<string, unknown>;
      const hasCredential = credentialSubject?.hasCredential as Record<string, unknown>;
      assert.deepEqual(vcTypes, [
        'VerifiableCredential',
        'PersonCredential',
        'LegalRepresentativeCredential',
      ]);
      assert.equal(typeof retrieveOutcome.credential?.issuer, 'string');
      assert.equal(String(retrieveOutcome.credential?.issuer || '').startsWith('did:'), true);
      assert.equal(typeof retrieveOutcome.credential?.id, 'string');
      assert.equal(String(retrieveOutcome.credential?.id || '').startsWith('urn:'), true);
      assert.equal(credentialSubject?.['@type'], 'Person');
      assert.equal(credentialSubject?.identifier, '12345678Z');
      assert.equal(credentialSubject?.id, 'urn:person:identifier:12345678Z');
      assert.equal(credentialSubject?.name, 'TEST LEGAL REPRESENTATIVE');
      assert.equal(credentialSubject?.nationality, 'ES');
      assert.equal(occupation?.['@type'], 'Occupation');
      assert.equal(occupation?.name, undefined);
      assert.equal(occupation?.occupationalCategory, 'ISCO-08|1120');
      assert.equal(memberOf?.['@type'], 'Organization');
      assert.equal(memberOf?.taxID, 'VATES-B00112233');
      assert.equal(memberOf?.legalName, 'TEST HEALTHCARE SL');
      assert.equal(
        hasCredential?.material,
        toJwkThumbprintSha256Urn(controllerKey.publicJwk),
      );
    } finally {
      resetVerificationCollectionsMemStateForTests();
      if (previousDidWebDomain === undefined) delete process.env.DID_WEB_DOMAIN;
      else process.env.DID_WEB_DOMAIN = previousDidWebDomain;
    }
  },
);
