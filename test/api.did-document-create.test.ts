// Carga automática de variables de entorno desde .env.local para los tests
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import {
  EXAMPLE_DEFAULT_ICA_DID,
  EXAMPLE_PROVIDER_LEGAL_NAME,
  EXAMPLE_PROVIDER_TAX_ID,
} from 'gdc-common-utils-ts/examples/shared';
import {
  EXAMPLE_VERIFY_RESPONSE_DATE,
  EXAMPLE_VERIFY_RESPONSE_ORG_ENTRY_TYPE,
} from 'gdc-common-utils-ts/examples/ica-verify-response';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import {
  buildCreateDidDocumentResponseLocation,
  parseCreateDidDocumentRoute,
} from '../src/api/path.ts';
import { CreateDidDocumentRequestManager } from '../src/api/managers/create-did-document-request-manager.ts';
import { CreateDidDocumentResponseManager } from '../src/api/managers/create-did-document-response-manager.ts';
import { parseCreateDidDocumentSubmission, parsePollingThreadId } from '../src/api/request-parsing.ts';
import { activateSigningKey, resetActiveSigningKeysStateForTests } from '../src/api/tools/active-signing-keys.ts';
import { deriveDeterministicEcPrivateKeyPem } from '../src/api/tools/deterministic-key-material.ts';
import {
  buildOrganizationDidDocument,
  buildOrganizationDidFromTaxId,
  validateOrganizationDidInput,
} from '../src/api/tools/organization-did.ts';
import {
  VerificationCollectionsService,
} from '../src/api/tools/verification-collections-storage.ts';
import { resetOrganizationSelfCaCacheForTests } from '../src/api/tools/organization-self-ca.ts';
import { resetVerificationCollectionsMemAdapterStateForTests } from '../src/api/tools/verification-collections/adapters.ts';
import { normalizeSameAsHash } from '../src/api/tools/multihash.ts';
import type {
  CreateDidDocumentResult,
  CreateDidDocumentRouteContext,
} from '../src/api/types.ts';


import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const outdir = path.resolve(__dirname, '../artifacts/tests/output');
const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

function writeOutput(name: string, data: unknown) {
  console.log(`[ORG-DID-TEST] About to write output: ${name}`);
  fs.mkdirSync(outdir, { recursive: true });
  fs.writeFileSync(
    path.join(outdir, `organization-did-document.${name}.${timestamp}.json`),
    JSON.stringify(data, null, 2)
  );
  console.log(`[ORG-DID-TEST] Output written: ${name}`);
}

function buildDidcommRequest(body: unknown, url: string): IncomingMessage {
  const req = Readable.from([JSON.stringify(body)]) as IncomingMessage & Readable;
  req.method = 'POST';
  req.url = url;
  req.headers = {
    'content-type': 'application/didcomm-plain+json',
  };
  return req;
}

function readPrimaryVerificationMethodJwk(result: ReturnType<typeof buildOrganizationDidDocument>): Record<string, unknown> {
  const didDocument = result.didDocument as Record<string, unknown>;
  const verificationMethod = didDocument.verificationMethod as Array<Record<string, unknown>>;
  return verificationMethod[0]?.publicKeyJwk as Record<string, unknown>;
}

const ICA_ISSUER_TEST_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDe//4WRdJpBh0HUfhn
RC3KNHZXZ3tI5iFP2tQgix+x1FuIDGb9jbAFL4y9Okx7NiGhZANiAAS67JrcZoTf
bfGNYSsO3gNw7jJ39Xd6cIm85TPuYB7rdPPQl6Di0XxmWOMuW5ckd0v3eLIXCaVP
E1nH11R79H5EgC0iXZ4ljRU197XvArNXUJANDKBR9PkDjJLHGisIAFA=
-----END PRIVATE KEY-----`;

const ICA_ISSUER_TEST_X5C = 'MIICQzCCAcqgAwIBAgIUDO7JwdnoN/7sPtXSsYvu3/lsJ/owCgYIKoZIzj0EAwIwWTELMAkGA1UEBhMCRVMxDTALBgNVBAoMBEFjbWUxEzARBgNVBAMMCkNvbnRyb2xsZXIxJjAkBgkqhkiG9w0BCQEWF2l0LWRpcmVjdG9yQGV4YW1wbGUub3JnMB4XDTI2MDMwNzE1NDk1MloXDTM2MDMwNDE1NDk1MlowWTELMAkGA1UEBhMCRVMxDTALBgNVBAoMBEFjbWUxEzARBgNVBAMMCkNvbnRyb2xsZXIxJjAkBgkqhkiG9w0BCQEWF2l0LWRpcmVjdG9yQGV4YW1wbGUub3JnMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuuya3GaE323xjWErDt4DcO4yd/V3enCJvOUz7mAe63Tz0Jeg4tF8ZljjLluXJHdL93iyFwmlTxNZx9dUe/R+RIAtIl2eJY0VNfe17wKzV1CQDQygUfT5A4ySxxorCABQo1MwUTAdBgNVHQ4EFgQUoqHCRVOg4IkdCG+1D24CTJjECVMwHwYDVR0jBBgwFoAUoqHCRVOg4IkdCG+1D24CTJjECVMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNnADBkAjB3vq5C6TgDU/WwV9bsJG+svSuu6d93YQco4z7tMrpzfgZP6emsFyg23lFeY5GzoC4CMA7jgC4UXi2k4UAB6eBePQJVXRS8c2MlwOjiIa+MLDqcvyZcbRaZLBT3JHz09RTRIQ==';
const TEST_RESOURCE_TYPE_CONTRACT = 'contract' as const;
const TEST_CREATE_DID_REQUEST_TYPE =
  'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1' as const;
const TEST_ANIMAL_CARE_SECTOR = 'animal-care' as const;
const TEST_RAW_LOOKUP_REQUEST_ID = 'req-did-create-raw-taxid-lookup' as const;
const TEST_RAW_LOOKUP_RECORD_ID = 'org-record-raw-taxid-lookup' as const;
const TEST_RAW_LOOKUP_THREAD_ID = 'thid-verify-org-raw-taxid-lookup' as const;
const TEST_RAW_LOOKUP_CREDENTIAL_ID = 'urn:vc:org:raw-taxid-lookup' as const;
const TEST_RAW_LOOKUP_ORG_PUBLIC_KEY_JWK = Object.freeze({
  kty: 'EC',
  crv: 'P-384',
  x: 'rawtaxid-org-x',
  y: 'rawtaxid-org-y',
});
const TEST_RAW_LOOKUP_CONTROLLER_PUBLIC_KEY_JWK = Object.freeze({
  kty: 'EC',
  crv: 'P-384',
  x: 'rawtaxid-controller-x',
  y: 'rawtaxid-controller-y',
});
const TEST_RAW_LOOKUP_CONTROLLER_SAME_AS = 'urn:multibase:zControllerHash' as const;
const TEST_PROVIDER_TAX_ID_RAW = EXAMPLE_PROVIDER_TAX_ID.replace(/^VATES-/, '');
const TEST_PROVIDER_ORGANIZATION_DID = buildOrganizationDidFromTaxId(
  TEST_ANIMAL_CARE_SECTOR,
  EXAMPLE_PROVIDER_TAX_ID,
  'globaldatacare.es',
);

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

test('parseCreateDidDocumentSubmission prefers thid, then id, then jti', async () => {
  const reqWithId = buildDidcommRequest({
    id: 'msg-create-did-001',
    jti: 'req-create-did-001',
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
  const parsedWithId = await parseCreateDidDocumentSubmission(reqWithId);
  assert.equal(parsedWithId.thid, 'msg-create-did-001');

  const reqWithJti = buildDidcommRequest({
    jti: 'req-create-did-002',
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
  const parsedWithJti = await parseCreateDidDocumentSubmission(reqWithJti);
  assert.equal(parsedWithJti.thid, 'req-create-did-002');
});

test('parseCreateDidDocumentSubmission accepts optional jwks for controller and organization', async () => {
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
              jwks: {
                keys: [
                  {
                    kid: 'org-didcomm-enc-001',
                    kty: 'EC',
                    crv: 'P-384',
                    x: 'org-enc-x',
                    y: 'org-enc-y',
                    use: 'enc',
                    purposes: ['didcomm-enc'],
                  },
                ],
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
              jwks: {
                keys: [
                  {
                    kid: 'controller-didcomm-sign-001',
                    kty: 'EC',
                    crv: 'P-384',
                    x: 'controller-sign-x',
                    y: 'controller-sign-y',
                    use: 'sig',
                    purposes: ['didcomm-sign'],
                  },
                ],
              },
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const parsed = await parseCreateDidDocumentSubmission(req);
  assert.equal(parsed.items[0]?.organization.jwks?.keys[0]?.kid, 'org-didcomm-enc-001');
  assert.deepEqual(parsed.items[0]?.organization.jwks?.keys[0]?.purposes, ['didcomm-enc']);
  assert.equal(parsed.items[0]?.controller.jwks?.keys[0]?.kid, 'controller-didcomm-sign-001');
  assert.deepEqual(parsed.items[0]?.controller.jwks?.keys[0]?.purposes, ['didcomm-sign']);
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

test('parsePollingThreadId accepts thid, falls back to id, then jti', async () => {
  const thidReq = buildDidcommRequest(
    { thid: 'thid-create-did-001' },
    '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response',
  );
  const parsedFromThid = await parsePollingThreadId(
    thidReq,
    new URL('http://localhost/ica/cds-ES/v1/animal-care/entity/did/document/_create-response'),
  );
  assert.equal(parsedFromThid, 'thid-create-did-001');

  const idReq = buildDidcommRequest(
    { id: 'msg-create-did-001' },
    '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response',
  );
  const parsedFromId = await parsePollingThreadId(
    idReq,
    new URL('http://localhost/ica/cds-ES/v1/animal-care/entity/did/document/_create-response'),
  );
  assert.equal(parsedFromId, 'msg-create-did-001');

  const jtiReq = buildDidcommRequest(
    { jti: 'req-create-did-001' },
    '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response',
  );
  const parsedFromJti = await parsePollingThreadId(
    jtiReq,
    new URL('http://localhost/ica/cds-ES/v1/animal-care/entity/did/document/_create-response'),
  );
  assert.equal(parsedFromJti, 'req-create-did-001');
});

test('CreateDidDocument managers build derived did:web document asynchronously', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  try {
    const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
    assert.ok(parsedRoute);
    assert.equal(parsedRoute?.ok, true);
    if (!parsedRoute || !parsedRoute.ok) return;

    const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
    resetVerificationCollectionsMemAdapterStateForTests();

    try {
      const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
      assert.ok(parsedRoute);
      assert.equal(parsedRoute?.ok, true);
      if (!parsedRoute || !parsedRoute.ok) return;

      const store2 = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
      const collectionsService2 = new VerificationCollectionsService();
      await collectionsService2.storeIssuedCredentials([
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
      const requestManager = new CreateDidDocumentRequestManager(store2, collectionsService2);
      const responseManager = new CreateDidDocumentResponseManager(store2);

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
                  jwks: {
                    keys: [
                      {
                        kid: 'org-didcomm-sign-001',
                        kty: 'EC',
                        crv: 'P-384',
                        x: 'orgsignx',
                        y: 'orgsigny',
                        use: 'sig',
                        purposes: ['didcomm-sign'],
                      },
                      {
                        kid: 'org-didcomm-enc-001',
                        kty: 'EC',
                        crv: 'P-384',
                        x: 'orgencx',
                        y: 'orgency',
                        use: 'enc',
                        purposes: ['didcomm-enc'],
                      },
                    ],
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
      },
      '/ica/cds-ES/v1/animal-care/entity/did/document/_create'
    );
      const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
      writeOutput('create-manager-submit', { submitOutcome });
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
      writeOutput('create-manager-poll', { outcome });
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
      assert.equal(resource?.didDocument?.verificationMethod?.length, 3);
      assert.ok(resource?.didDocument?.authentication?.includes('did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678#org-didcomm-sign-001'));
      assert.ok(resource?.didDocument?.keyAgreement?.includes('did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678#org-didcomm-enc-001'));
      assert.equal(resource?.didDocument?.alsoKnownAs, undefined);

      const didBindings = await collectionsService2.listDidBindings();
      const didDocuments = await collectionsService2.listDidDocuments();
      writeOutput('create-manager-bindings', { didBindings, didDocuments });
      assert.equal(didBindings.length, 1);
      assert.equal(didBindings[0]?.status, 'confirmed');
      assert.equal(didBindings[0]?.taxId, 'VATES-A12345678');
      assert.equal(didDocuments.length, 1);
      assert.equal(didDocuments[0]?.status, 'confirmed');
      assert.equal(didDocuments[0]?.did, 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678');
    } finally {
      resetVerificationCollectionsMemAdapterStateForTests();
    }
    assert.equal(parsedRoute?.ok, true);
    if (!parsedRoute || !parsedRoute.ok) return;

    const store3 = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
    const collectionsService3 = new VerificationCollectionsService();
    await collectionsService3.storeIssuedCredentials([
      {
        id: 'org-record-key-001',
        tenantId: parsedRoute.context.tenantId,
        jurisdiction: parsedRoute.context.jurisdiction,
        sector: parsedRoute.context.sector,
        resourceType: 'contract',
        thid: 'thid-verify-org-key-001',
        credentialType: 'Organization-verification-v1.0',
        credentialId: 'urn:vc:org:key:001',
        subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
        issuerId: 'did:web:localhost%3A3310',
        publicKeyJwk: {
          kty: 'EC',
          crv: 'P-384',
          x: 'stored-org-x',
          y: 'stored-org-y',
          alg: 'ES384',
          kid: 'stored-org-es384-001',
        },
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
      {
        id: 'person-record-key-001',
        tenantId: parsedRoute.context.tenantId,
        jurisdiction: parsedRoute.context.jurisdiction,
        sector: parsedRoute.context.sector,
        resourceType: 'contract',
        thid: 'thid-verify-person-key-001',
        credentialType: 'LegalRepresentative-verification-v1.0',
        credentialId: 'urn:vc:person:key:001',
        subjectId: 'urn:person:identifier:IDCES-99999999R',
        issuerId: 'did:web:localhost%3A3310',
        publicKeyJwk: {
          kty: 'EC',
          crv: 'P-384',
          x: 'stored-controller-x',
          y: 'stored-controller-y',
          alg: 'ES384',
          kid: 'stored-controller-es384-001',
        },
        credential: {
          credentialSubject: {
            '@type': 'Person',
            id: 'urn:person:identifier:IDCES-99999999R',
            sameAs: 'urn:multibase:zControllerHash',
            memberOf: {
              '@type': 'Organization',
              taxID: 'VATES-A12345678',
            },
          },
        },
        createdAt: '2026-03-12T00:00:00.000Z',
        updatedAt: '2026-03-12T00:00:00.000Z',
      },
    ]);
    await collectionsService3.storeDidBindings([
      {
        id: 'ica::es::animal-care::VATES-A12345678',
        tenantId: parsedRoute.context.tenantId,
        jurisdiction: parsedRoute.context.jurisdiction,
        sector: parsedRoute.context.sector,
        resourceType: 'contract',
        thid: 'thid-verify-bindings-key-001',
        taxId: 'VATES-A12345678',
        did: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
        controllerSameAs: 'urn:multibase:zControllerHash',
        controllerPublicKeyJwk: {
          kty: 'EC',
          crv: 'P-384',
          x: 'stored-controller-x',
          y: 'stored-controller-y',
          alg: 'ES384',
          kid: 'stored-controller-es384-001',
        },
        organizationPublicKeyJwk: {
          kty: 'EC',
          crv: 'P-384',
          x: 'stored-org-x',
          y: 'stored-org-y',
          alg: 'ES384',
          kid: 'stored-org-es384-001',
        },
        organizationKeySource: 'attachment',
        status: 'draft',
        createdAt: '2026-03-12T00:00:00.000Z',
        updatedAt: '2026-03-12T00:00:00.000Z',
      },
    ]);
    const requestManager2 = new CreateDidDocumentRequestManager(store3, collectionsService3);
    const responseManager2 = new CreateDidDocumentResponseManager(store3);

    const submitReq = buildDidcommRequest({
      jti: 'req-did-create-stored-keys-001',
      thid: 'thid-did-create-stored-keys-001',
      type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
      body: {
        data: [
          {
            resource: {
              organization: {
                identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
              },
              controller: {
                sameAs: 'urn:multibase:zControllerHash',
              },
            },
          },
        ],
      },
    }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

    const submitOutcome = await requestManager2.submit(parsedRoute.context, submitReq);
    assert.equal(submitOutcome.type, 'accepted');
    await new Promise((resolve) => setImmediate(resolve));

    const pollRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create-response');
    assert.ok(pollRoute);
    assert.equal(pollRoute?.ok, true);
    if (!pollRoute || !pollRoute.ok) return;

    const pollReq = buildDidcommRequest({}, '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-did-create-stored-keys-001');
    const outcome = await responseManager2.poll(
      pollRoute.context,
      pollReq,
      new URL('http://localhost/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-did-create-stored-keys-001'),
    );
    assert.equal(outcome.type, 'succeeded');
    if (outcome.type !== 'succeeded') return;
    const payload = outcome.payload as Record<string, any>;
    const methodJwk = payload.body?.data?.[0]?.resource?.didDocument?.verificationMethod?.[0]?.publicKeyJwk;
    assert.equal(methodJwk?.kid, 'stored-org-es384-001');
    assert.equal(methodJwk?.x, 'stored-org-x');
    assert.match(payload.body?.data?.[0]?.resource?.didDocument?.controller || '', /^did:key:z/);
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

test('CreateDidDocument prefers the canonical taxID embedded in organization.identifier over a raw request taxID', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
  const collectionsService = new VerificationCollectionsService();
  await collectionsService.storeIssuedCredentials([
    {
      id: TEST_RAW_LOOKUP_RECORD_ID,
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: TEST_RESOURCE_TYPE_CONTRACT,
      thid: TEST_RAW_LOOKUP_THREAD_ID,
      credentialType: EXAMPLE_VERIFY_RESPONSE_ORG_ENTRY_TYPE,
      credentialId: TEST_RAW_LOOKUP_CREDENTIAL_ID,
      subjectId: TEST_PROVIDER_ORGANIZATION_DID,
      issuerId: EXAMPLE_DEFAULT_ICA_DID,
      credential: {
        credentialSubject: {
          '@type': 'Organization',
          id: TEST_PROVIDER_ORGANIZATION_DID,
          taxID: EXAMPLE_PROVIDER_TAX_ID,
          legalName: EXAMPLE_PROVIDER_LEGAL_NAME,
        },
      },
      createdAt: EXAMPLE_VERIFY_RESPONSE_DATE,
      updatedAt: EXAMPLE_VERIFY_RESPONSE_DATE,
    },
  ]);
  const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);

  const submitReq = buildDidcommRequest({
    jti: TEST_RAW_LOOKUP_REQUEST_ID,
    type: TEST_CREATE_DID_REQUEST_TYPE,
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: TEST_PROVIDER_ORGANIZATION_DID,
              taxID: TEST_PROVIDER_TAX_ID_RAW,
              publicKeyJwk: TEST_RAW_LOOKUP_ORG_PUBLIC_KEY_JWK,
            },
            controller: {
              sameAs: TEST_RAW_LOOKUP_CONTROLLER_SAME_AS,
              publicKeyJwk: TEST_RAW_LOOKUP_CONTROLLER_PUBLIC_KEY_JWK,
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
  assert.equal(submitOutcome.type, 'accepted');

  await new Promise((resolve) => setImmediate(resolve));
  const job = store.get(TEST_RAW_LOOKUP_REQUEST_ID);
  assert.equal(job?.status, 'succeeded');
  assert.equal(job?.result?.items?.[0]?.did, TEST_PROVIDER_ORGANIZATION_DID);

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

test('CreateDidDocument rejects controller.publicKeyJwk override when _verify already stored a different controller binding', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
  const collectionsService = new VerificationCollectionsService();
  await collectionsService.storeIssuedCredentials([
    {
      id: 'org-record-006',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-org-006',
      credentialType: 'Organization-verification-v1.0',
      credentialId: 'urn:vc:org:006',
      subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-E00000000',
      issuerId: 'did:web:localhost%3A3310',
      credential: {
        credentialSubject: {
          '@type': 'Organization',
          id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-E00000000',
          taxID: 'VATES-E00000000',
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
    {
      id: 'person-record-006',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-person-006',
      credentialType: 'Person-verification-v1.0',
      credentialId: 'urn:vc:person:006',
      subjectId: 'urn:person:identifier:88888888R',
      issuerId: 'did:web:localhost%3A3310',
      publicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'stored-controller-x',
        y: 'stored-controller-y',
        alg: 'ES384',
        kid: 'stored-controller-kid',
      },
      credential: {
        credentialSubject: {
          '@type': 'Person',
          sameAs: 'urn:multibase:zStoredControllerHash',
          memberOf: {
            '@type': 'Organization',
            taxID: 'VATES-E00000000',
          },
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  await collectionsService.storeDidBindings([
    {
      id: 'ica::es::animal-care::VATES-E00000000',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-bindings-006',
      taxId: 'VATES-E00000000',
      did: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-E00000000',
      controllerSameAs: 'urn:multibase:zStoredControllerHash',
      controllerPublicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'stored-controller-x',
        y: 'stored-controller-y',
        alg: 'ES384',
        kid: 'stored-controller-kid',
      },
      organizationPublicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'org-x',
        y: 'org-y',
        alg: 'ES384',
        kid: 'stored-org-kid',
      },
      organizationKeySource: 'attachment',
      status: 'draft',
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);

  const submitReq = buildDidcommRequest({
    jti: 'req-did-create-006',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-E00000000',
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'org-x',
                y: 'org-y',
              },
            },
            controller: {
              publicKeyJwk: {
                kty: 'EC',
                crv: 'P-384',
                x: 'different-controller-x',
                y: 'different-controller-y',
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
  const job = store.get('req-did-create-006');
  assert.equal(job?.status, 'failed');
  assert.match(job?.error || '', /controller\.publicKeyJwk must match the controller binding stored during _verify/i);

  resetVerificationCollectionsMemAdapterStateForTests();
});

test('CreateDidDocument reuses ICA-generated organization key from _verify when organization.publicKeyJwk is omitted', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
  const collectionsService = new VerificationCollectionsService();
  await collectionsService.storeIssuedCredentials([
    {
      id: 'org-record-007',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-org-007',
      credentialType: 'Organization-verification-v1.0',
      credentialId: 'urn:vc:org:007',
      subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-F00000000',
      issuerId: 'did:web:localhost%3A3310',
      publicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'generated-org-x',
        y: 'generated-org-y',
        alg: 'ES384',
        kid: 'generated-org-kid',
      },
      keySource: 'generated',
      credential: {
        credentialSubject: {
          '@type': 'Organization',
          id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-F00000000',
          taxID: 'VATES-F00000000',
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
    {
      id: 'person-record-007',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-person-007',
      credentialType: 'LegalRepresentative-verification-v1.0',
      credentialId: 'urn:vc:person:007',
      subjectId: 'urn:person:identifier:77777777R',
      issuerId: 'did:web:localhost%3A3310',
      publicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'stored-controller-x',
        y: 'stored-controller-y',
        alg: 'ES384',
        kid: 'stored-controller-kid',
      },
      credential: {
        credentialSubject: {
          '@type': 'Person',
          sameAs: 'urn:multibase:zStoredControllerHash',
          memberOf: {
            '@type': 'Organization',
            taxID: 'VATES-F00000000',
          },
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  await collectionsService.storeDidBindings([
    {
      id: 'ica::es::animal-care::VATES-F00000000',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-bindings-007',
      taxId: 'VATES-F00000000',
      did: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-F00000000',
      controllerSameAs: 'urn:multibase:zStoredControllerHash',
      controllerPublicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'stored-controller-x',
        y: 'stored-controller-y',
        alg: 'ES384',
        kid: 'stored-controller-kid',
      },
      organizationPublicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'generated-org-x',
        y: 'generated-org-y',
        alg: 'ES384',
        kid: 'generated-org-kid',
      },
      organizationKeySource: 'generated',
      status: 'draft',
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);

  const submitReq = buildDidcommRequest({
    jti: 'req-did-create-007',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-F00000000',
            },
            controller: {
              sameAs: 'urn:multibase:zStoredControllerHash',
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
  assert.equal(submitOutcome.type, 'accepted');

  await new Promise((resolve) => setImmediate(resolve));
  const job = store.get('req-did-create-007');
  assert.equal(job?.status, 'succeeded');

  resetVerificationCollectionsMemAdapterStateForTests();
});

test('CreateDidDocument accepts explicit organization.publicKeyJwk override when it differs from key stored during _verify', async () => {
  resetVerificationCollectionsMemAdapterStateForTests();

  const parsedRoute = parseCreateDidDocumentRoute('/ica/cds-ES/v1/animal-care/entity/did/document/_create');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const generatedOrganizationPublicKeyJwk = {
    kty: 'EC',
    crv: 'P-384',
    x: 'generated-org-confirm-x',
    y: 'generated-org-confirm-y',
    alg: 'ES384',
    kid: 'generated-org-confirm-kid',
  };
  const overrideOrganizationPublicKeyJwk = {
    kty: 'EC',
    crv: 'P-384',
    x: 'override-org-confirm-x',
    y: 'override-org-confirm-y',
    alg: 'ES384',
    kid: 'override-org-confirm-kid',
  };

  const store = new InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>(60);
  const collectionsService = new VerificationCollectionsService();
  await collectionsService.storeIssuedCredentials([
    {
      id: 'org-record-008',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-org-008',
      credentialType: 'Organization-verification-v1.0',
      credentialId: 'urn:vc:org:008',
      subjectId: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-G00000000',
      issuerId: 'did:web:localhost%3A3310',
      publicKeyJwk: generatedOrganizationPublicKeyJwk,
      keySource: 'generated',
      credential: {
        credentialSubject: {
          '@type': 'Organization',
          id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-G00000000',
          taxID: 'VATES-G00000000',
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
    {
      id: 'person-record-008',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-person-008',
      credentialType: 'LegalRepresentative-verification-v1.0',
      credentialId: 'urn:vc:person:008',
      subjectId: 'urn:person:identifier:66666666R',
      issuerId: 'did:web:localhost%3A3310',
      publicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'stored-controller-x',
        y: 'stored-controller-y',
        alg: 'ES384',
        kid: 'stored-controller-kid',
      },
      credential: {
        credentialSubject: {
          '@type': 'Person',
          sameAs: 'urn:multibase:zStoredControllerHash',
          memberOf: {
            '@type': 'Organization',
            taxID: 'VATES-G00000000',
          },
        },
      },
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  await collectionsService.storeDidBindings([
    {
      id: 'ica::es::animal-care::VATES-G00000000',
      tenantId: parsedRoute.context.tenantId,
      jurisdiction: parsedRoute.context.jurisdiction,
      sector: parsedRoute.context.sector,
      resourceType: 'contract',
      thid: 'thid-verify-bindings-008',
      taxId: 'VATES-G00000000',
      did: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-G00000000',
      controllerSameAs: 'urn:multibase:zStoredControllerHash',
      controllerPublicKeyJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: 'stored-controller-x',
        y: 'stored-controller-y',
        alg: 'ES384',
        kid: 'stored-controller-kid',
      },
      organizationPublicKeyJwk: generatedOrganizationPublicKeyJwk,
      organizationKeySource: 'generated',
      status: 'draft',
      createdAt: '2026-03-12T00:00:00.000Z',
      updatedAt: '2026-03-12T00:00:00.000Z',
    },
  ]);
  const requestManager = new CreateDidDocumentRequestManager(store, collectionsService);

  const submitReq = buildDidcommRequest({
    jti: 'req-did-create-008',
    thid: 'thid-did-create-008',
    type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
    body: {
      data: [
        {
          resource: {
            organization: {
              identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-G00000000',
              publicKeyJwk: overrideOrganizationPublicKeyJwk,
            },
            controller: {
              sameAs: 'urn:multibase:zStoredControllerHash',
            },
          },
        },
      ],
    },
  }, '/ica/cds-ES/v1/animal-care/entity/did/document/_create');

  const submitOutcome = await requestManager.submit(parsedRoute.context, submitReq);
  assert.equal(submitOutcome.type, 'accepted');

  await new Promise((resolve) => setImmediate(resolve));
  const job = store.get('thid-did-create-008');
  assert.equal(job?.status, 'succeeded');
  const updatedBindings = await collectionsService.listDidBindings();
  const updated = updatedBindings.find((entry) => entry.taxId === 'VATES-G00000000');
  assert.equal((updated?.organizationPublicKeyJwk as Record<string, unknown>)?.kid, 'override-org-confirm-kid');

  resetVerificationCollectionsMemAdapterStateForTests();
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

test('buildOrganizationDidDocument attaches deterministic x5c chain in self-CA staging mode', (t) => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
  } catch {
    t.skip('OpenSSL is required for self-CA DID document tests.');
    return;
  }

  const envBackup = {
    ICA_CREATE_DID_SELF_CA_STAGING: process.env.ICA_CREATE_DID_SELF_CA_STAGING,
    ICA_CREATE_DID_SELF_CA_PASSPHRASE: process.env.ICA_CREATE_DID_SELF_CA_PASSPHRASE,
    ICA_CREATE_DID_SELF_CA_DOMAIN: process.env.ICA_CREATE_DID_SELF_CA_DOMAIN,
    ICA_CREATE_DID_SELF_CA_NOT_BEFORE: process.env.ICA_CREATE_DID_SELF_CA_NOT_BEFORE,
  };
  t.after(() => {
    for (const [key, value] of Object.entries(envBackup)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    resetOrganizationSelfCaCacheForTests();
  });

  process.env.ICA_CREATE_DID_SELF_CA_STAGING = 'true';
  process.env.ICA_CREATE_DID_SELF_CA_PASSPHRASE = 'test-passphrase';
  process.env.ICA_CREATE_DID_SELF_CA_DOMAIN = 'ca.staging.example.org';
  process.env.ICA_CREATE_DID_SELF_CA_NOT_BEFORE = '20240101000000Z';

  const organizationPublicKeyJwk = deriveDeterministicEcPrivateKeyPem('org-self-ca-seed', 'P-384').publicJwk;
  const controllerPublicKeyJwk = deriveDeterministicEcPrivateKeyPem('controller-self-ca-seed', 'P-384').publicJwk;
  const input = {
    did: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
    controller: {
      sameAs: 'urn:multibase:zControllerHash',
      publicKeyJwk: controllerPublicKeyJwk,
    },
    organization: {
      identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-A12345678',
      taxID: 'VATES-A12345678',
      legalName: 'Acme Org',
      publicKeyJwk: organizationPublicKeyJwk,
    },
  } as const;

  const first = buildOrganizationDidDocument(input);
  resetOrganizationSelfCaCacheForTests();
  const second = buildOrganizationDidDocument(input);

  const firstJwk = readPrimaryVerificationMethodJwk(first);
  const secondJwk = readPrimaryVerificationMethodJwk(second);
  assert.deepEqual(firstJwk.x5c, secondJwk.x5c);
  assert.equal(Array.isArray(firstJwk.x5c), true);
  assert.equal((firstJwk.x5c as string[]).length, 3);
});

test('buildOrganizationDidDocument attaches x5c chain from active ICA signing key when self-CA is disabled', (t) => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
  } catch {
    t.skip('OpenSSL is required for ICA-issued DID document tests.');
    return;
  }

  const envBackup = {
    ICA_CREATE_DID_SELF_CA_STAGING: process.env.ICA_CREATE_DID_SELF_CA_STAGING,
    ICA_CREATE_DID_SELF_CA_NOT_BEFORE: process.env.ICA_CREATE_DID_SELF_CA_NOT_BEFORE,
  };
  t.after(() => {
    for (const [key, value] of Object.entries(envBackup)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    resetActiveSigningKeysStateForTests();
    resetOrganizationSelfCaCacheForTests();
  });

  delete process.env.ICA_CREATE_DID_SELF_CA_STAGING;
  process.env.ICA_CREATE_DID_SELF_CA_NOT_BEFORE = '20240101000000Z';
  resetActiveSigningKeysStateForTests();
  activateSigningKey({
    kid: 'ica-issuer-es384-001',
    alg: 'ES384',
    privateKeyPem: ICA_ISSUER_TEST_PRIVATE_KEY_PEM,
    x5c: [ICA_ISSUER_TEST_X5C],
  });

  const organizationPublicKeyJwk = deriveDeterministicEcPrivateKeyPem('org-ica-leaf-seed', 'P-384').publicJwk;
  const controllerPublicKeyJwk = deriveDeterministicEcPrivateKeyPem('controller-ica-leaf-seed', 'P-384').publicJwk;
  const input = {
    did: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
    controller: {
      sameAs: 'urn:multibase:zControllerHash',
      publicKeyJwk: controllerPublicKeyJwk,
    },
    organization: {
      identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
      taxID: 'VATES-B00000000',
      legalName: 'Acme Org',
      publicKeyJwk: organizationPublicKeyJwk,
    },
  } as const;

  const first = buildOrganizationDidDocument(input);
  const second = buildOrganizationDidDocument(input);
  const firstJwk = readPrimaryVerificationMethodJwk(first);
  const secondJwk = readPrimaryVerificationMethodJwk(second);
  assert.deepEqual(firstJwk.x5c, secondJwk.x5c);
  assert.equal(Array.isArray(firstJwk.x5c), true);
  assert.equal((firstJwk.x5c as string[]).length, 2);
  assert.equal((firstJwk.x5c as string[])[1], ICA_ISSUER_TEST_X5C);
});
