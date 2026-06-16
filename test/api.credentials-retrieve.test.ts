import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { toJwkThumbprintSha256Urn } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import {
  buildCredentialRetrieveResponseLocation,
  parseCredentialRetrieveRoute,
} from '../src/api/path.ts';
import { CredentialRetrieveRequestManager } from '../src/api/managers/credential-retrieve-request-manager.ts';
import { CredentialRetrieveResponseManager } from '../src/api/managers/credential-retrieve-response-manager.ts';
import type {
  CredentialRetrieveResult,
  CredentialRetrieveRouteContext,
} from '../src/api/types.ts';
import {
  resetVerificationCollectionsMemStateForTests,
  VerificationCollectionsService,
} from '../src/api/tools/verification-collections-storage.ts';
import { deriveDeterministicEcPrivateKeyPem } from '../src/api/tools/deterministic-key-material.ts';

function buildDidcommRetrievePayload(thid: string, identifier: string): Buffer {
  return Buffer.from(JSON.stringify({
    jti: `req-${thid}`,
    thid,
    type: 'application/bundle-api+json',
    body: {
      data: [
        {
          identifier,
        },
      ],
    },
  }));
}

async function seedIssuedCredentials(service: VerificationCollectionsService): Promise<void> {
  const controllerKey = deriveDeterministicEcPrivateKeyPem('credential-retrieve-controller-binding', 'P-384');
  await service.storeIssuedCredentials([
    {
      id: 'urn:uuid:issued-org-old',
      tenantId: 'acme',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'contract',
      thid: 'thid-verify-old',
      credentialType: 'member-onboarding',
      credentialId: 'urn:uuid:vc-org-old',
      subjectId: 'did:web:member.example.org',
      issuerId: 'did:web:ica.example.org',
      credential: {
        id: 'urn:uuid:vc-org-old',
        issuer: 'did:web:ica.example.org',
        type: ['VerifiableCredential', 'OrganizationCredential'],
        evidence: [
          {
            type: 'document',
            attachments: {
              url: 'urn:audit:gcs:bucket/ica-audit/animal-care/es/contract/2026-03-28/old.pdf',
            },
          },
        ],
        credentialSubject: {
          id: 'did:web:member.example.org',
          '@type': 'Organization',
          legalName: 'Acme Org OLD',
          taxID: 'VATES-A12345678',
        },
      },
      createdAt: '2026-03-28T09:00:00.000Z',
      updatedAt: '2026-03-28T09:00:00.000Z',
    },
    {
      id: 'urn:uuid:issued-org-new',
      tenantId: 'acme',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'contract',
      thid: 'thid-verify-new',
      credentialType: 'member-onboarding',
      credentialId: 'urn:uuid:vc-org-new',
      subjectId: 'did:web:member.example.org',
      issuerId: 'did:web:ica.example.org',
      credential: {
        id: 'urn:uuid:vc-org-new',
        issuer: 'did:web:ica.example.org',
        type: ['VerifiableCredential', 'OrganizationCredential'],
        evidence: [
          {
            type: 'document',
            attachments: {
              url: 'ipfs://zPdfCidNew001',
            },
          },
        ],
        credentialSubject: {
          id: 'did:web:member.example.org',
          '@type': 'Organization',
          legalName: 'Acme Org NEW',
          taxID: 'VATES-A12345678',
        },
      },
      createdAt: '2026-03-29T09:00:00.000Z',
      updatedAt: '2026-03-29T10:00:00.000Z',
    },
    {
      id: 'urn:uuid:issued-person-001',
      tenantId: 'acme',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'contract',
      thid: 'thid-verify-person',
      credentialType: 'member-onboarding',
      credentialId: 'urn:uuid:vc-person-001',
      subjectId: 'urn:person:identifier:IDCES-12345678Z',
      issuerId: 'did:web:ica.example.org',
      credential: {
        id: 'urn:uuid:vc-person-001',
        issuer: 'did:web:ica.example.org',
        type: ['VerifiableCredential', 'PersonCredential', 'LegalRepresentativeCredential'],
        credentialSubject: {
          id: 'urn:person:identifier:IDCES-12345678Z',
          '@type': 'Person',
          name: 'Jane Doe',
          memberOf: {
            '@type': 'Organization',
            taxID: 'VATES-A12345678',
          },
        },
      },
      createdAt: '2026-03-29T09:05:00.000Z',
      updatedAt: '2026-03-29T10:05:00.000Z',
    },
  ]);
  await service.storeDidBindings([
    {
      id: 'acme::es::animal-care::VATES-A12345678',
      tenantId: 'acme',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'contract',
      thid: 'thid-verify-person',
      taxId: 'VATES-A12345678',
      did: 'did:web:member.example.org',
      controllerPublicKeyJwk: controllerKey.publicJwk,
      status: 'confirmed',
      createdAt: '2026-03-29T10:06:00.000Z',
      updatedAt: '2026-03-29T10:06:00.000Z',
    },
  ]);
}

test('parseCredentialRetrieveRoute accepts valid _retrieve route', () => {
  const parsed = parseCredentialRetrieveRoute('/ica/cds-ES/v1/animal-care/network/credentials/contract/_retrieve');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.credentialType, 'contract');
  assert.equal(parsed.context.action, '_retrieve');
  assert.equal(
    buildCredentialRetrieveResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/network/credentials/contract/_retrieve-response',
  );
});

test('CredentialRetrieve managers support async POST DIDComm + polling and return vc+jwt', async () => {
  const parsedSubmit = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve');
  const parsedPoll = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve-response');
  assert.ok(parsedSubmit && parsedSubmit.ok);
  assert.ok(parsedPoll && parsedPoll.ok);
  if (!parsedSubmit || !parsedSubmit.ok || !parsedPoll || !parsedPoll.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });
  await seedIssuedCredentials(collectionsService);

  const store = new InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>(60);
  const requestManager = new CredentialRetrieveRequestManager(store, collectionsService);
  const responseManager = new CredentialRetrieveResponseManager(store);

  const payload = buildDidcommRetrievePayload('thid-credential-retrieve-001', 'VATES-A12345678');
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve?type=OrganizationCredential&format=vc+jwt&version=v2';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsedSubmit.context, req);
  assert.equal(submitOutcome.type, 'accepted');
  if (submitOutcome.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve-response?thid=thid-credential-retrieve-001',
  );
  const pollOutcome = await responseManager.poll(parsedPoll.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');
  if (pollOutcome.type !== 'succeeded') return;

  const content = ((pollOutcome.payload as any)?.body?.data?.[0]?.resource?.content || []) as Array<Record<string, unknown>>;
  assert.equal(content.length, 1);
  assert.equal(content[0]?.credentialId, 'urn:uuid:vc-org-new');
  const vcJwt = String(content[0]?.vcJwt || '');
  assert.equal(vcJwt.split('.').length, 3);
});

test('CredentialRetrieve direct GET-style path returns signed VC JSON and uses identifier alias', async () => {
  const parsed = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve');
  assert.ok(parsed && parsed.ok);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });
  await seedIssuedCredentials(collectionsService);

  const store = new InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>(60);
  const requestManager = new CredentialRetrieveRequestManager(store, collectionsService);

  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve?identifier=VATES-A12345678&type=OrganizationCredential&version=v2',
  );
  const outcome = await requestManager.retrieveDirect(parsed.context, requestUrl, 'application/vc+json');
  assert.equal(outcome.type, 'succeeded');
  if (outcome.type !== 'succeeded') return;
  assert.equal(outcome.format, 'vc+json');
  assert.equal(outcome.credential?.id, 'urn:uuid:vc-org-new');
  assert.equal((outcome.credential?.credentialSubject as Record<string, unknown>)?.legalName, 'Acme Org NEW');
});

test('CredentialRetrieve v2 injects representative hasCredential.material from did binding', async () => {
  const parsed = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve');
  assert.ok(parsed && parsed.ok);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });
  await seedIssuedCredentials(collectionsService);

  const store = new InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>(60);
  const requestManager = new CredentialRetrieveRequestManager(store, collectionsService);

  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve?identifier=VATES-A12345678&type=LegalRepresentativeCredential&version=v2',
  );
  const outcome = await requestManager.retrieveDirect(parsed.context, requestUrl, 'application/vc+json');
  assert.equal(outcome.type, 'succeeded');
  if (outcome.type !== 'succeeded') return;

  const subject = outcome.credential?.credentialSubject as Record<string, unknown>;
  const hasCredential = subject?.hasCredential as Record<string, unknown>;
  const expected = toJwkThumbprintSha256Urn(
    deriveDeterministicEcPrivateKeyPem('credential-retrieve-controller-binding', 'P-384').publicJwk,
  );
  assert.equal(hasCredential?.material, expected);
});

test('CredentialRetrieve direct GET-style path returns vc+jwt when Accept requests application/vc+jwt', async () => {
  const parsed = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve');
  assert.ok(parsed && parsed.ok);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });
  await seedIssuedCredentials(collectionsService);

  const store = new InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>(60);
  const requestManager = new CredentialRetrieveRequestManager(store, collectionsService);

  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve?identifier=VATES-A12345678&type=OrganizationCredential&version=v2',
  );
  const outcome = await requestManager.retrieveDirect(parsed.context, requestUrl, 'application/vc+jwt');
  assert.equal(outcome.type, 'succeeded');
  if (outcome.type !== 'succeeded') return;
  assert.equal(outcome.format, 'vc+jwt');
  const vcJwt = String(outcome.vcJwt || '');
  assert.equal(vcJwt.split('.').length, 3);
});

test('CredentialRetrieve direct GET-style path with version=v1 returns first stored credential', async () => {
  const parsed = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve');
  assert.ok(parsed && parsed.ok);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });
  await seedIssuedCredentials(collectionsService);

  const store = new InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>(60);
  const requestManager = new CredentialRetrieveRequestManager(store, collectionsService);

  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve?identifier=VATES-A12345678&type=OrganizationCredential&version=v1',
  );
  const outcome = await requestManager.retrieveDirect(parsed.context, requestUrl, 'application/vc+json');
  assert.equal(outcome.type, 'succeeded');
  if (outcome.type !== 'succeeded') return;
  assert.equal(outcome.format, 'vc+json');
  assert.equal(outcome.credential?.id, 'urn:uuid:vc-org-old');
  assert.equal((outcome.credential?.credentialSubject as Record<string, unknown>)?.legalName, 'Acme Org OLD');
});

test('CredentialRetrieve direct GET-style path tries identifier first and falls back to taxId', async () => {
  const parsed = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve');
  assert.ok(parsed && parsed.ok);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });
  await seedIssuedCredentials(collectionsService);

  const store = new InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>(60);
  const requestManager = new CredentialRetrieveRequestManager(store, collectionsService);

  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve?identifier=VATES-NOT-FOUND&taxId=VATES-A12345678&type=OrganizationCredential&version=v2',
  );
  const outcome = await requestManager.retrieveDirect(parsed.context, requestUrl, 'application/vc+json');
  assert.equal(outcome.type, 'succeeded');
  if (outcome.type !== 'succeeded') return;
  assert.equal(outcome.credential?.id, 'urn:uuid:vc-org-new');
});

test('CredentialRetrieve async POST with version=v1 returns first stored credential', async () => {
  const parsedSubmit = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve');
  const parsedPoll = parseCredentialRetrieveRoute('/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve-response');
  assert.ok(parsedSubmit && parsedSubmit.ok);
  assert.ok(parsedPoll && parsedPoll.ok);
  if (!parsedSubmit || !parsedSubmit.ok || !parsedPoll || !parsedPoll.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });
  await seedIssuedCredentials(collectionsService);

  const store = new InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>(60);
  const requestManager = new CredentialRetrieveRequestManager(store, collectionsService);
  const responseManager = new CredentialRetrieveResponseManager(store);

  const payload = buildDidcommRetrievePayload('thid-credential-retrieve-v1-001', 'VATES-A12345678');
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve?type=OrganizationCredential&format=vc+json&version=v1';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsedSubmit.context, req);
  assert.equal(submitOutcome.type, 'accepted');
  if (submitOutcome.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/contract/_retrieve-response?thid=thid-credential-retrieve-v1-001',
  );
  const pollOutcome = await responseManager.poll(parsedPoll.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');
  if (pollOutcome.type !== 'succeeded') return;

  const content = ((pollOutcome.payload as any)?.body?.data?.[0]?.resource?.content || []) as Array<Record<string, unknown>>;
  assert.equal(content.length, 1);
  assert.equal(content[0]?.credentialId, 'urn:uuid:vc-org-old');
});
