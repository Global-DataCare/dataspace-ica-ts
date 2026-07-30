import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import {
  buildTermsRemoveResponseLocation,
  parseTermsRemoveRoute,
} from '../src/api/path.ts';
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import { CreateDidDocumentRequestManager } from '../src/api/managers/create-did-document-request-manager.ts';
import { CreateDidDocumentResponseManager } from '../src/api/managers/create-did-document-response-manager.ts';
import { TermsRemoveRequestManager } from '../src/api/managers/terms-remove-request-manager.ts';
import { TermsRemoveResponseManager } from '../src/api/managers/terms-remove-response-manager.ts';
import { parseTermsRemoveSubmission } from '../src/api/request-parsing.ts';
import {
  buildProviderDatasetsFromIssuedCredentials,
  filterProviderDatasetsByActiveDidDocuments,
} from '../src/api/tools/dcat-catalog.ts';
import {
  VerificationCollectionsService,
  resetVerificationCollectionsMemStateForTests,
} from '../src/api/tools/verification-collections-storage.ts';
import type {
  CreateDidDocumentResult,
  CreateDidDocumentRouteContext,
  TermsRemoveResult,
  TermsRemoveRouteContext,
} from '../src/api/types.ts';

function buildDidcommRequest(body: unknown, url: string): IncomingMessage {
  const payload = Buffer.from(JSON.stringify(body));
  const req = Readable.from([payload]) as IncomingMessage & Readable;
  req.method = 'POST';
  req.url = url;
  req.headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };
  return req;
}

function createCollectionsService(): VerificationCollectionsService {
  return new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
  });
}

test('parseTermsRemoveRoute accepts submit and polling routes', () => {
  const submit = parseTermsRemoveRoute('/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove');
  assert.ok(submit);
  assert.equal(submit?.ok, true);
  if (!submit || !submit.ok) return;
  assert.equal(submit.context.action, '_remove');

  const poll = parseTermsRemoveRoute('/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove-response');
  assert.ok(poll);
  assert.equal(poll?.ok, true);
  if (!poll || !poll.ok) return;
  assert.equal(poll.context.action, '_remove-response');
});

test('parseTermsRemoveSubmission resolves controller binding key from meta.jws.protected.jwk', async () => {
  const req = buildDidcommRequest({
    jti: 'req-auto',
    thid: 'thid-auto',
    type: 'https://globaldatacare.es/didcomm/ica/terms/remove-request/v1',
    meta: {
      jws: {
        protected: {
          alg: 'ES384',
          kid: 'controller-msg-es384-001',
          jwk: {
            kty: 'EC',
            crv: 'P-384',
            x: 'controller-x',
            y: 'controller-y',
          },
        },
      },
    },
    body: {
      data: [
        {
          resource: {
            organization: {
              taxID: 'VATES-B00000000',
              identifier: 'did:web:member.example.org',
            },
            controller: {
              sameAs: 'urn:multibase:zControllerHash',
            },
            reason: 'organization-requested-removal',
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove');

  const parsed = await parseTermsRemoveSubmission(req);
  assert.match(parsed.thid, /^thid-/);
  assert.equal(parsed.items.length, 1);
  assert.equal(parsed.items[0]?.organization.taxID, 'VATES-B00000000');
  assert.equal(parsed.items[0]?.controller.sameAs, 'urn:multibase:zControllerHash');
  assert.equal(parsed.items[0]?.controller.publicKeyJwk?.kid, 'controller-msg-es384-001');
  assert.equal(parsed.items[0]?.reason, 'organization-requested-removal');
});

test('parseTermsRemoveSubmission accepts identifier-only organization removal', async () => {
  const req = buildDidcommRequest({
    thid: 'thid-remove-identifier-only',
    type: 'https://globaldatacare.es/didcomm/ica/terms/remove-request/v1',
    meta: {
      jws: {
        protected: {
          alg: 'ES384',
          kid: 'controller-msg-es384-001',
          jwk: {
            kty: 'EC',
            crv: 'P-384',
            x: 'controller-x',
            y: 'controller-y',
          },
        },
      },
    },
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:member.example.org',
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove');

  const parsed = await parseTermsRemoveSubmission(req);
  assert.equal(parsed.items[0]?.organization.identifier, 'did:web:member.example.org');
  assert.equal(parsed.items[0]?.organization.taxID, undefined);
  assert.equal(parsed.items[0]?.controller.publicKeyJwk?.kid, 'controller-msg-es384-001');
});

test('TermsRemove managers remove active binding and did document, then _create requires fresh _verify', async () => {
  resetVerificationCollectionsMemStateForTests();
  const collectionsService = createCollectionsService();
  await collectionsService.storeDidBindings([
    {
      id: 'ica::es::animal-care::VATES-B00000000',
      tenantId: 'ica',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'contract',
      thid: 'thid-verify-001',
      taxId: 'VATES-B00000000',
      did: 'did:web:member.example.org',
      controllerSameAs: 'urn:multibase:zcontrollerhash',
      controllerPublicKeyJwk: {
        kid: 'controller-msg-es384-001',
        alg: 'ES384',
        kty: 'EC',
        crv: 'P-384',
        x: 'controller-x',
        y: 'controller-y',
      },
      organizationPublicKeyJwk: {
        kid: 'org-cred-es384-001',
        kty: 'EC',
        crv: 'P-384',
        x: 'org-x',
        y: 'org-y',
      },
      status: 'confirmed',
      createdAt: '2026-03-17T00:00:00.000Z',
      updatedAt: '2026-03-17T00:00:00.000Z',
      confirmedAt: '2026-03-17T00:00:00.000Z',
    },
  ]);
  await collectionsService.storeDidDocuments([
    {
      id: 'did:web:member.example.org',
      tenantId: 'ica',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'document',
      thid: 'thid-create-001',
      did: 'did:web:member.example.org',
      taxId: 'VATES-B00000000',
      controllerSameAs: 'urn:multibase:zcontrollerhash',
      controllerPublicKeyJwk: {
        kid: 'controller-msg-es384-001',
        alg: 'ES384',
        kty: 'EC',
        crv: 'P-384',
        x: 'controller-x',
        y: 'controller-y',
      },
      organizationPublicKeyJwk: {
        kid: 'org-cred-es384-001',
        kty: 'EC',
        crv: 'P-384',
        x: 'org-x',
        y: 'org-y',
      },
      didDocument: {
        id: 'did:web:member.example.org',
        verificationMethod: [],
      },
      status: 'confirmed',
      createdAt: '2026-03-17T00:00:00.000Z',
      updatedAt: '2026-03-17T00:00:00.000Z',
    },
  ]);

  const route = parseTermsRemoveRoute('/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove');
  const pollRoute = parseTermsRemoveRoute('/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove-response');
  assert.ok(route && route.ok);
  assert.ok(pollRoute && pollRoute.ok);
  if (!route || !route.ok || !pollRoute || !pollRoute.ok) return;

  const store = new InMemoryEntityJobStore<TermsRemoveRouteContext, TermsRemoveResult>(60);
  const requestManager = new TermsRemoveRequestManager(store, collectionsService);
  const responseManager = new TermsRemoveResponseManager(store);
  const req = buildDidcommRequest({
    jti: 'req-remove-001',
    thid: 'thid-remove-001',
    type: 'https://globaldatacare.es/didcomm/ica/terms/remove-request/v1',
    meta: {
      jws: {
        protected: {
          alg: 'ES384',
          kid: 'controller-msg-es384-001',
          jwk: {
            kty: 'EC',
            crv: 'P-384',
            x: 'controller-x',
            y: 'controller-y',
          },
        },
      },
    },
    body: {
      data: [
        {
          resource: {
            organization: {
              taxID: 'VATES-B00000000',
              identifier: 'did:web:member.example.org',
            },
            controller: {
              sameAs: 'urn:multibase:zcontrollerhash',
            },
            reason: 'organization-requested-removal',
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove');

  const outcome = await requestManager.submit(route.context, req);
  assert.equal(outcome.type, 'accepted');
  if (outcome.type !== 'accepted') return;
  assert.equal(
    outcome.location,
    buildTermsRemoveResponseLocation(route.context, { thid: 'thid-remove-001' }),
  );

  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = buildDidcommRequest({}, '/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove-response?thid=thid-remove-001');
  const pollOutcome = await responseManager.poll(
    pollRoute.context,
    pollReq,
    new URL('http://localhost/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove-response?thid=thid-remove-001'),
  );
  assert.equal(pollOutcome.type, 'succeeded');

  const didBindings = await collectionsService.listDidBindings();
  const didDocuments = await collectionsService.listDidDocuments();
  assert.equal(didBindings[0]?.status, 'removed');
  assert.equal(didBindings[0]?.removeReason, 'organization-requested-removal');
  assert.equal(Boolean(didBindings[0]?.removedAt), true);
  assert.equal(didDocuments[0]?.status, 'removed');
  assert.equal(didDocuments[0]?.removeReason, 'organization-requested-removal');
  assert.equal(Boolean(didDocuments[0]?.removedAt), true);

  const createStore = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
  const createRequestManager = new CreateDidDocumentRequestManager(createStore, collectionsService);
  const createResponseManager = new CreateDidDocumentResponseManager(createStore);
  const createRoute = {
    tenantId: 'ica',
    jurisdiction: 'ES',
    sector: 'animal-care',
    section: 'entity',
    format: 'did',
    resourceType: 'document',
    action: '_create',
  } satisfies CreateDidDocumentRouteContext;
  const createPollRoute = {
    ...createRoute,
    action: '_create-response',
  } satisfies CreateDidDocumentRouteContext;
  const createReq = buildDidcommRequest({
    thid: 'thid-create-after-remove-001',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:member.example.org',
              taxID: 'VATES-B00000000',
              publicKeyJwk: {
                kid: 'org-cred-es384-001',
                kty: 'EC',
                crv: 'P-384',
                x: 'org-x',
                y: 'org-y',
              },
            },
            controller: {
              sameAs: 'urn:multibase:zcontrollerhash',
              publicKeyJwk: {
                kid: 'controller-msg-es384-001',
                kty: 'EC',
                crv: 'P-384',
                x: 'controller-x',
                y: 'controller-y',
              },
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const createOutcome = await createRequestManager.submit(createRoute, createReq);
  assert.equal(createOutcome.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const createPollReq = buildDidcommRequest({}, '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-create-after-remove-001');
  const createPollOutcome = await createResponseManager.poll(
    createPollRoute,
    createPollReq,
    new URL('http://localhost/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-create-after-remove-001'),
  );
  assert.equal(createPollOutcome.type, 'failed');
  if (createPollOutcome.type !== 'failed') return;
  const failedPayload = createPollOutcome.payload as {
    body?: { data?: Array<{ resource?: { error?: { message?: string } } }> };
  };
  assert.match(
    failedPayload.body?.data?.[0]?.resource?.error?.message || '',
    /Complete _verify again before calling _create/i,
  );
});

test('TermsRemove manager rejects controller binding mismatch', async () => {
  resetVerificationCollectionsMemStateForTests();
  const collectionsService = createCollectionsService();
  await collectionsService.storeDidBindings([
    {
      id: 'ica::es::animal-care::VATES-B00000000',
      tenantId: 'ica',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'contract',
      thid: 'thid-verify-001',
      taxId: 'VATES-B00000000',
      did: 'did:web:member.example.org',
      controllerPublicKeyJwk: {
        kid: 'controller-msg-es384-001',
        alg: 'ES384',
        kty: 'EC',
        crv: 'P-384',
        x: 'controller-x',
        y: 'controller-y',
      },
      status: 'confirmed',
      createdAt: '2026-03-17T00:00:00.000Z',
      updatedAt: '2026-03-17T00:00:00.000Z',
      confirmedAt: '2026-03-17T00:00:00.000Z',
    },
  ]);
  await collectionsService.storeDidDocuments([
    {
      id: 'did:web:member.example.org',
      tenantId: 'ica',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'document',
      thid: 'thid-create-001',
      did: 'did:web:member.example.org',
      taxId: 'VATES-B00000000',
      didDocument: { id: 'did:web:member.example.org' },
      status: 'confirmed',
      createdAt: '2026-03-17T00:00:00.000Z',
      updatedAt: '2026-03-17T00:00:00.000Z',
    },
  ]);

  const route = parseTermsRemoveRoute('/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove');
  const pollRoute = parseTermsRemoveRoute('/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove-response');
  assert.ok(route && route.ok);
  assert.ok(pollRoute && pollRoute.ok);
  if (!route || !route.ok || !pollRoute || !pollRoute.ok) return;

  const store = new InMemoryEntityJobStore<TermsRemoveRouteContext, TermsRemoveResult>(60);
  const requestManager = new TermsRemoveRequestManager(store, collectionsService);
  const responseManager = new TermsRemoveResponseManager(store);
  const req = buildDidcommRequest({
    thid: 'thid-remove-mismatch-001',
    type: 'https://globaldatacare.es/didcomm/ica/terms/remove-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              taxID: 'VATES-B00000000',
            },
            controller: {
              publicKeyJwk: {
                kid: 'controller-msg-es384-override',
                kty: 'EC',
                crv: 'P-384',
                x: 'other-x',
                y: 'other-y',
              },
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove');

  const outcome = await requestManager.submit(route.context, req);
  assert.equal(outcome.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const pollReq = buildDidcommRequest({}, '/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove-response?thid=thid-remove-mismatch-001');
  const pollOutcome = await responseManager.poll(
    pollRoute.context,
    pollReq,
    new URL('http://localhost/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove-response?thid=thid-remove-mismatch-001'),
  );
  assert.equal(pollOutcome.type, 'failed');
  if (pollOutcome.type !== 'failed') return;
  const failedPayload = pollOutcome.payload as {
    body?: { data?: Array<{ resource?: { error?: { message?: string } } }> };
  };
  assert.match(
    failedPayload.body?.data?.[0]?.resource?.error?.message || '',
    /must match the stored controller binding/i,
  );
});

test('filterProviderDatasetsByActiveDidDocuments hides removed organizations from catalog publication', async () => {
  const datasets = buildProviderDatasetsFromIssuedCredentials([
    {
      id: 'urn:uuid:record-001',
      tenantId: 'ica',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'contract',
      thid: 'thid-001',
      credentialType: 'OrganizationCredential',
      credentialId: 'urn:uuid:record-001',
      subjectId: 'did:web:member.example.org',
      issuerId: 'did:web:ica.example.org',
      credential: {
        id: 'urn:uuid:record-001',
        type: ['VerifiableCredential', 'OrganizationCredential'],
        credentialSubject: {
          id: 'did:web:member.example.org',
          legalName: 'Member Example',
          taxID: 'VATES-B00000000',
          category: 'animal-care',
          addressCountry: 'ES',
        },
      },
      createdAt: '2026-03-17T00:00:00.000Z',
      updatedAt: '2026-03-17T00:00:00.000Z',
    },
  ], {
    tenantId: 'ica',
    jurisdiction: 'ES',
    sector: 'animal-care',
  });

  const filtered = filterProviderDatasetsByActiveDidDocuments(
    datasets,
    [
      {
        id: 'did:web:member.example.org',
        tenantId: 'ica',
        jurisdiction: 'ES',
        sector: 'animal-care',
        resourceType: 'document',
        thid: 'thid-create-001',
        did: 'did:web:member.example.org',
        didDocument: { id: 'did:web:member.example.org' },
        status: 'removed',
        createdAt: '2026-03-17T00:00:00.000Z',
        updatedAt: '2026-03-17T00:00:01.000Z',
        removedAt: '2026-03-17T00:00:01.000Z',
      },
    ],
    {
      tenantId: 'ica',
      jurisdiction: 'ES',
      sector: 'animal-care',
    },
  );

  assert.equal(filtered.length, 0);
});

test('OpenAPI publishes _remove and _remove-response endpoints', () => {
  const openApi = buildIcaVerifyOpenApiSpec({ serverUrl: 'http://localhost:3310' });
  assert.ok(openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_remove']);
  assert.ok(openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_remove-response']);
});
