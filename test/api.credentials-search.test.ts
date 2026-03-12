import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import {
  buildCredentialSearchResponseLocation,
  parseCredentialSearchRoute,
} from '../src/api/path.ts';
import { CredentialSearchRequestManager } from '../src/api/managers/credential-search-request-manager.ts';
import { CredentialSearchResponseManager } from '../src/api/managers/credential-search-response-manager.ts';
import type { CredentialSearchResult, CredentialSearchRouteContext } from '../src/api/types.ts';
import {
  resetVerificationCollectionsMemStateForTests,
  VerificationCollectionsService,
} from '../src/api/tools/verification-collections-storage.ts';
import { multibase58MultihashSha3_256 } from '../src/api/tools/multihash.ts';

test('parseCredentialSearchRoute accepts valid _search route', () => {
  const parsed = parseCredentialSearchRoute('/ica/cds-ES/v1/animal-care/network/credentials/member-onboarding/_search');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.credentialType, 'member-onboarding');
  assert.equal(parsed.context.action, '_search');
  assert.equal(
    buildCredentialSearchResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/network/credentials/member-onboarding/_search-response',
  );
});

test('CredentialSearch managers support x-www-form-urlencoded unit search and return data[] results', async () => {
  const parsed = parseCredentialSearchRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_search');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });

  await collectionsService.storeIssuedCredentials([
    {
      id: 'urn:uuid:issued-org-001',
      tenantId: 'acme',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'member-onboarding',
      thid: 'thid-issue-001',
      credentialType: 'member-onboarding',
      credentialId: 'urn:uuid:vc-org-001',
      subjectId: 'did:web:member.example.org',
      issuerId: 'did:web:ica.example.org',
      credential: {
        id: 'urn:uuid:vc-org-001',
        type: ['VerifiableCredential', 'OrganizationCredential'],
        credentialSubject: {
          id: 'did:web:member.example.org',
          '@type': 'Organization',
          legalName: 'Acme Health SL',
          taxID: 'VATES-A12345678',
        },
      },
      createdAt: '2026-03-08T00:00:00.000Z',
      updatedAt: '2026-03-08T00:00:00.000Z',
    },
    {
      id: 'urn:uuid:issued-org-002',
      tenantId: 'acme',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'member-onboarding',
      thid: 'thid-issue-002',
      credentialType: 'member-onboarding',
      credentialId: 'urn:uuid:vc-org-002',
      subjectId: 'did:web:other.example.org',
      issuerId: 'did:web:ica.example.org',
      credential: {
        id: 'urn:uuid:vc-org-002',
        type: ['VerifiableCredential', 'OrganizationCredential'],
        credentialSubject: {
          id: 'did:web:other.example.org',
          '@type': 'Organization',
          legalName: 'Other Org SA',
          taxID: 'VATES-B12345678',
        },
      },
      createdAt: '2026-03-08T00:01:00.000Z',
      updatedAt: '2026-03-08T00:01:00.000Z',
    },
  ]);

  const store = new InMemoryEntityJobStore<CredentialSearchRouteContext, CredentialSearchResult>(60);
  const requestManager = new CredentialSearchRequestManager(store, collectionsService);
  const responseManager = new CredentialSearchResponseManager(store);

  const payload = Buffer.from('taxId=VATES-A12345678&text=Acme&thid=thid-credential-search-001');

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_search';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/x-www-form-urlencoded',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsed.context, req);
  assert.equal(submitOutcome.type, 'accepted');
  if (submitOutcome.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_search-response?thid=thid-credential-search-001',
  );
  const pollOutcome = await responseManager.poll(parsed.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');
  if (pollOutcome.type !== 'succeeded') return;

  const content = ((pollOutcome.payload as any)?.body?.data?.[0]?.resource?.content || []) as Array<Record<string, unknown>>;
  assert.equal(content.length, 1);
  assert.equal(content[0]?.credentialId, 'urn:uuid:vc-org-001');
  assert.equal(content[0]?.legalName, 'Acme Health SL');
  assert.equal(content[0]?.taxIdHash, multibase58MultihashSha3_256('VATES-A12345678'));
});

test('CredentialSearch maps id parameter to taxId for credentialType organization-taxid', async () => {
  const parsed = parseCredentialSearchRoute('/acme/cds-ES/v1/animal-care/network/credentials/organization-taxid/_search');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });

  await collectionsService.storeIssuedCredentials([
    {
      id: 'urn:uuid:issued-org-taxid-001',
      tenantId: 'acme',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'organization-taxid',
      thid: 'thid-issue-taxid-001',
      credentialType: 'organization-taxid',
      credentialId: 'urn:uuid:vc-org-taxid-001',
      subjectId: 'did:web:member.example.org',
      issuerId: 'did:web:ica.example.org',
      credential: {
        id: 'urn:uuid:vc-org-taxid-001',
        type: ['VerifiableCredential', 'OrganizationCredential'],
        credentialSubject: {
          id: 'did:web:member.example.org',
          '@type': 'Organization',
          legalName: 'Acme Health SL',
          taxID: 'VATES-A12345678',
        },
      },
      createdAt: '2026-03-08T00:00:00.000Z',
      updatedAt: '2026-03-08T00:00:00.000Z',
    },
  ]);

  const store = new InMemoryEntityJobStore<CredentialSearchRouteContext, CredentialSearchResult>(60);
  const requestManager = new CredentialSearchRequestManager(store, collectionsService);
  const responseManager = new CredentialSearchResponseManager(store);

  const payload = Buffer.from('id=VATES-A12345678&thid=thid-credential-search-taxid-001');
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/organization-taxid/_search';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/x-www-form-urlencoded',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsed.context, req);
  assert.equal(submitOutcome.type, 'accepted');
  if (submitOutcome.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/organization-taxid/_search-response?thid=thid-credential-search-taxid-001',
  );
  const pollOutcome = await responseManager.poll(parsed.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');
  if (pollOutcome.type !== 'succeeded') return;
  const content = ((pollOutcome.payload as any)?.body?.data?.[0]?.resource?.content || []) as Array<Record<string, unknown>>;
  assert.equal(content.length, 1);
  assert.equal(content[0]?.taxId, 'VATES-A12345678');
});
