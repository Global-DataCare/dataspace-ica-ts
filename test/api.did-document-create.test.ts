import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import {
  buildCreateDidDocumentResponseLocation,
  parseCreateDidDocumentRoute,
} from '../src/api/path.ts';
import { CreateDidDocumentRequestManager } from '../src/api/managers/create-did-document-request-manager.ts';
import { CreateDidDocumentResponseManager } from '../src/api/managers/create-did-document-response-manager.ts';
import { parseCreateDidDocumentSubmission, parsePollingThreadId } from '../src/api/request-parsing.ts';
import { validateOrganizationDidInput } from '../src/api/tools/organization-did.ts';
import {
  VerificationCollectionsService,
} from '../src/api/tools/verification-collections-storage.ts';
import { resetVerificationCollectionsMemAdapterStateForTests } from '../src/api/tools/verification-collections/adapters.ts';
import { normalizeSameAsHash } from '../src/api/tools/multihash.ts';
import type {
  CreateDidDocumentResult,
  CreateDidDocumentRouteContext,
} from '../src/api/types.ts';

function buildDidcommRequest(body: unknown, url: string): IncomingMessage {
  const req = Readable.from([JSON.stringify(body)]) as IncomingMessage & Readable;
  req.method = 'POST';
  req.url = url;
  req.headers = {
    'content-type': 'application/didcomm-plain+json',
  };
  return req;
}

test('parseCreateDidDocumentRoute accepts create and polling routes', () => {
  const create = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
  assert.ok(create);
  assert.equal(create?.ok, true);
  if (!create || !create.ok) return;
  assert.equal(create.context.action, '_create');

  const poll = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create-response');
  assert.ok(poll);
  assert.equal(poll?.ok, true);
  if (!poll || !poll.ok) return;
  assert.equal(poll.context.action, '_create-response');
});

test('parseCreateDidDocumentSubmission supports body.data[] and derives thread ids', async () => {
  const req = buildDidcommRequest({
    jti: 'req-auto',
    thid: 'thid-auto',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'abc',
                y: 'def',
              },
            },
            controller: {
              sameAs: 'urn:multibase:zControllerHash',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'ghi',
                y: 'jkl',
              },
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const parsed = await parseCreateDidDocumentSubmission(req);
  assert.match(parsed.thid, /^thid-/);
  assert.equal(parsed.items.length, 1);
  assert.equal(
    parsed.items[0]?.organization.identifier,
    'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
  );
  assert.equal(parsed.items[0]?.organization.taxID, undefined);
  assert.equal(parsed.items[0]?.organization.publicKeyJwk?.x, 'abc');
  assert.equal(parsed.items[0]?.controller.sameAs, 'urn:multibase:zControllerHash');
  assert.equal(parsed.items[0]?.controller.publicKeyJwk?.x, 'ghi');
});

test('parseCreateDidDocumentSubmission hashes plain controller.sameAs email', async () => {
  const req = buildDidcommRequest({
    jti: 'req-auto',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'abc',
                y: 'def',
              },
            },
            controller: {
              sameAs: 'Jane.Doe@Example.org',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'ghi',
                y: 'jkl',
              },
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const parsed = await parseCreateDidDocumentSubmission(req);
  assert.equal(parsed.items[0]?.controller.sameAs, normalizeSameAsHash('Jane.Doe@Example.org'));
});

test('parsePollingThreadId accepts body.thid and does not accept body.jti', async () => {
  const thidReq = buildDidcommRequest(
    { thid: 'thid-create-did-001' },
    '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response',
  );
  const parsedFromThid = await parsePollingThreadId(
    thidReq,
    new URL('http://localhost/ica/cds-ES/v1/animal-care/entity/did/document/_create-response'),
  );
  assert.equal(parsedFromThid, 'thid-create-did-001');

  const jtiReq = buildDidcommRequest(
    { jti: 'req-create-did-001' },
    '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response',
  );
  const parsedFromJti = await parsePollingThreadId(
    jtiReq,
    new URL('http://localhost/ica/cds-ES/v1/animal-care/entity/did/document/_create-response'),
  );
  assert.equal(parsedFromJti, undefined);
});

test('CreateDidDocument managers build derived did:web document asynchronously', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  try {
    const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
    assert.ok(parsedRoute);
    assert.equal(parsedRoute?.ok, true);
    if (!parsedRoute || !parsedRoute.ok) return;

    const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
    const collectionsService = new VerificationCollectionsService();
    await collectionsService.storeIssuedCredentials([
      {
        id: 'org-record-001',
        tenantId: parsedRoute.context.tenantId,
        jurisdiction: parsedRoute.context.jurisdiction,
        sector: parsedRoute.context.sector,
        resourceType: 'contract',
        thid: 'thid-verify-org-001',
        credentialType: 'Organization-verification-v1.0',
        credentialId: 'urn:vc:org:001',
        subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
        issuerId: 'did:web:localhost%3A3310',
        credential: {
          credentialSubject: {
            '@type': 'Organization',
            id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
            taxID: 'VATES-A12345678',
            legalName: 'Acme Health SL',
          },
        },
        createdAt: '2026-03-12T00:00:00.000Z',
        updatedAt: '2026-03-12T00:00:00.000Z',
      },
    ]);
    const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);
    const responseManager = new CreateDidDocumentResponseManager(store);

    const submitReq = buildDidcommRequest({
      jti: 'req-did-create-001',
      thid: 'thid-did-create-001',
      type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
      body: {
        data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'abc',
                y: 'def',
              },
            },
            controller: {
              sameAs: 'urn:multibase:zControllerHash',
                publicKeyJwk: {
                  kty: 'EC',
                  crv: 'P-384',
                  x: 'ghi',
                  y: 'jkl',
                },
              },
            },
          },
        ],
      },
    }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

    const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
    assert.deepEqual(submitOutcome, {
      type: 'accepted',
      location: buildCreateDidDocumentResponseLocation({
        ...parsedRoute.context,
        action: '_create',
      }, { thid: 'thid-did-create-001' }),
      retryAfter: 3,
    });

    await new Promise((resolve) => setImmediate(resolve));

    const pollRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create-response');
    assert.ok(pollRoute);
    assert.equal(pollRoute?.ok, true);
    if (!pollRoute || !pollRoute.ok) return;

    const pollReq = buildDidcommRequest({}, '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-did-create-001');

    const outcome = await responseManager.poll(
      pollRoute.context,
      pollReq,
      new URL('http://localhost/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-did-create-001'),
    );
    assert.equal(outcome.type, 'succeeded');
    if (outcome.type !== 'succeeded') return;
    const payload = outcome.payload as Record<string, any>;
    const resource = payload.body?.data?.[0]?.resource;
    assert.equal(typeof resource?.meta?.createdAt, 'string');
    assert.equal(resource?.meta?.status, undefined);
    assert.match(resource?.didDocument?.controller || '', /^did:key:z/);
    assert.equal(
      resource?.didDocument?.verificationMethod?.[0]?.id,
      'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678#mAHM7GzWdl6cfRveUjFAnDdnhCayzRT8t1mdXxifCHY',
    );
    assert.equal(resource?.didDocument?.verificationMethod?.[0]?.publicKeyJwk?.x, 'abc');
    assert.equal(resource?.didDocument?.alsoKnownAs, undefined);
  } finally {
    resetVerificationCollectionsMemAdapterStateForTests();
  }
});

test('CreateDidDocument derives identifier from organization.url and requires it to match stored organization VC id', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
  const collectionsService = new VerificationCollectionsService();
  await collectionsService.storeIssuedCredentials([
    {
      id: 'org-record-002',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-org-002',
      credentialType: 'Organization-verification-v1.0',
      credentialId: 'urn:vc:org:002',
      subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
      issuerId: 'did:web:localhost%3A3310',
      credential: {
        credentialSubject: {
          '@type': 'Organization',
          id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
          taxID: 'VATES-B00000000',
          legalName: 'Example Data Provider SL',
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);

  const submitReq = buildDidcommRequest({
    jti: 'req-did-create-002',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              url: 'globaldatacare.es',
              taxID: 'VATES-B00000000',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'abc',
                y: 'def',
              },
            },
            controller: {
              sameAs: 'urn:multibase:zControllerHash',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'ghi',
                y: 'jkl',
              },
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
  assert.equal(submitOutcome.type, 'accepted');

  await new Promise((resolve) => setImmediate(resolve));
  const job = store.get('req-did-create-002');
  assert.equal(job?.status, 'succeeded');
  assert.equal(
    job?.result?.items?.[0]?.did,
    'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
  );

  resetVerificationCollectionsMemAdapterStateForTests();
});

test('CreateDidDocument fails when explicit or derived DID does not match stored organization VC id', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
  const collectionsService = new VerificationCollectionsService();
  await collectionsService.storeIssuedCredentials([
    {
      id: 'org-record-003',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-org-003',
      credentialType: 'Organization-verification-v1.0',
      credentialId: 'urn:vc:org:003',
      subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
      issuerId: 'did:web:localhost%3A3310',
      credential: {
        credentialSubject: {
          '@type': 'Organization',
          id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
          taxID: 'VATES-B00000000',
          legalName: 'Example Data Provider SL',
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);

  const submitReq = buildDidcommRequest({
    jti: 'req-did-create-003',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              url: 'provider.example.org',
              taxID: 'VATES-B00000000',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'abc',
                y: 'def',
              },
            },
            controller: {
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'ghi',
                y: 'jkl',
              },
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
  assert.equal(submitOutcome.type, 'accepted');

  await new Promise((resolve) => setImmediate(resolve));
  const job = store.get('req-did-create-003');
  assert.equal(job?.status, 'failed');
  assert.match(job?.error || '', /must match stored organization credentialSubject\.id/i);

  resetVerificationCollectionsMemAdapterStateForTests();
});

test('CreateDidDocument fails when organization and controller keys are the same', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
  const collectionsService = new VerificationCollectionsService();
  await collectionsService.storeIssuedCredentials([
    {
      id: 'org-record-004',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-org-004',
      credentialType: 'Organization-verification-v1.0',
      credentialId: 'urn:vc:org:004',
      subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-C00000000',
      issuerId: 'did:web:localhost%3A3310',
      credential: {
        credentialSubject: {
          '@type': 'Organization',
          id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-C00000000',
          taxID: 'VATES-C00000000',
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);

  const submitReq = buildDidcommRequest({
    jti: 'req-did-create-004',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-C00000000',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'abc',
                y: 'def',
              },
            },
            controller: {
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'abc',
                y: 'def',
              },
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
  assert.equal(submitOutcome.type, 'accepted');

  await new Promise((resolve) => setImmediate(resolve));
  const job = store.get('req-did-create-004');
  assert.equal(job?.status, 'failed');
  assert.match(job?.error || '', /must be different keys/i);

  resetVerificationCollectionsMemAdapterStateForTests();
});

test('CreateDidDocument optionally enforces controller.sameAs against stored person credentialSubject.sameAs', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();
  const previousFlag = process.env.ICA_CREATE_DID_REQUIRE_CONTROLLER_SAMEAS_MATCH;
  process.env.ICA_CREATE_DID_REQUIRE_CONTROLLER_SAMEAS_MATCH = 'true';

  try {
    const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
    assert.ok(parsedRoute);
    assert.equal(parsedRoute?.ok, true);
    if (!parsedRoute || !parsedRoute.ok) return;

    const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
    const collectionsService = new VerificationCollectionsService();
    await collectionsService.storeIssuedCredentials([
      {
        id: 'org-record-005',
        tenantId: parsedRoute.context.tenantId,
        jurisdiction: parsedRoute.context.jurisdiction,
        sector: parsedRoute.context.sector,
        resourceType: 'contract',
        thid: 'thid-verify-org-005',
        credentialType: 'Organization-verification-v1.0',
        credentialId: 'urn:vc:org:005',
        subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-D00000000',
        issuerId: 'did:web:localhost%3A3310',
        credential: {
          credentialSubject: {
            '@type': 'Organization',
            id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-D00000000',
            taxID: 'VATES-D00000000',
          },
        },
        createdAt: '2026-03-12T00:00:00.000Z',
        updatedAt: '2026-03-12T00:00:00.000Z',
      },
      {
        id: 'person-record-005',
        tenantId: parsedRoute.context.tenantId,
        jurisdiction: parsedRoute.context.jurisdiction,
        sector: parsedRoute.context.sector,
        resourceType: 'contract',
        thid: 'thid-verify-person-005',
        credentialType: 'Person-verification-v1.0',
        credentialId: 'urn:vc:person:005',
        subjectId: 'urn:person:identifier:99999999R',
        issuerId: 'did:web:localhost%3A3310',
        credential: {
          credentialSubject: {
            '@type': 'Person',
            sameAs: 'urn:multibase:zExpectedControllerHash',
            memberOf: {
              '@type': 'Organization',
              taxID: 'VATES-D00000000',
            },
          },
        },
        createdAt: '2026-03-12T00:00:00.000Z',
        updatedAt: '2026-03-12T00:00:00.000Z',
      },
    ]);
    const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);

    const submitReq = buildDidcommRequest({
      jti: 'req-did-create-005',
      type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
      body: {
        data: [
          {
            resource: {
              organization: {
                identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-D00000000',
                publicKeyJwk: {
                  kty: 'EC',
                  crv: 'P-384',
                  x: 'abc',
                  y: 'def',
                },
              },
              controller: {
            sameAs: 'different@example.org',
                publicKeyJwk: {
                  kty: 'EC',
                  crv: 'P-384',
                  x: 'ghi',
                  y: 'jkl',
                },
              },
            },
          },
        ],
      },
    }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

    const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
    assert.equal(submitOutcome.type, 'accepted');

    await new Promise((resolve) => setImmediate(resolve));
    const job = store.get('req-did-create-005');
    assert.equal(job?.status, 'failed');
    assert.match(job?.error || '', /stored person credentialSubject\.sameAs/i);
  } finally {
    if (previousFlag === undefined) delete process.env.ICA_CREATE_DID_REQUIRE_CONTROLLER_SAMEAS_MATCH;
    else process.env.ICA_CREATE_DID_REQUIRE_CONTROLLER_SAMEAS_MATCH = previousFlag;
    resetVerificationCollectionsMemAdapterStateForTests();
  }
});

test('validateOrganizationDidInput rejects identifier with sector different from path sector', () => {
  assert.throws(
    () => validateOrganizationDidInput({
      did: 'did:web:globaldatacare.es:health-care:organization:taxid:VATES-A12345678',
      sector: 'animal-care',
      jurisdiction: 'ES',
      taxId: 'VATES-A12345678',
    }),
    /must match path sector/i,
  );
});

test('validateOrganizationDidInput rejects taxID jurisdiction different from path jurisdiction', () => {
  assert.throws(
    () => validateOrganizationDidInput({
      did: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATFR-123456789',
      sector: 'animal-care',
      jurisdiction: 'ES',
      taxId: 'VATFR-123456789',
    }),
    /must match path jurisdiction/i,
  );
});
