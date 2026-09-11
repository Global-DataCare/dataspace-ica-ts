// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import test from 'node:test';
import { toJwkThumbprintSha256Urn } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import { deriveDeterministicEcPrivateKeyPem } from '../src/api/tools/deterministic-key-material.ts';
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import {
  VerificationCollectionsService,
  resetVerificationCollectionsMemStateForTests,
} from '../src/api/tools/verification-collections-storage.ts';
import type { VerifyBundleResponse, VerifyRouteContext } from '../src/api/types.ts';
import type { JsonObject } from '../src/api/tools/verification-collections-storage.ts';

const ROUTE: VerifyRouteContext = {
  tenantId: 'ica',
  jurisdiction: 'ES',
  sector: 'animal-care',
  section: 'test',
  format: 'pdf',
  resourceType: 'contract',
  action: '_verify',
};
const ORGANIZATION_TAX_ID = 'VATES-TSTORG0000';
const ORGANIZATION_DID = `did:web:member.example:animal-care:organization:taxid:${ORGANIZATION_TAX_ID}`;
const CONTROLLER_SAME_AS = 'urn:multibase:zCanonicalControllerIdentity';
const OLD_CONTROLLER_KEY = deriveDeterministicEcPrivateKeyPem('controller-rebind-old', 'P-384').publicJwk;
const NEW_CONTROLLER_KEY = deriveDeterministicEcPrivateKeyPem('controller-rebind-new', 'P-384').publicJwk;

function createCollectionsService(allowControllerRebindOnReverify = false): VerificationCollectionsService {
  return new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica-controller-rebind',
    allowControllerRebindOnReverify,
  });
}

function buildVerificationBundle(controllerPublicKeyJwk: JsonObject): VerifyBundleResponse {
  return {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 2,
    data: [
      {
        type: 'Organization-verification-v1.0',
        resource: {
          id: 'urn:uuid:00000000-0000-4000-8000-000000000001',
          type: ['VerifiableCredential', 'OrganizationCredential'],
          issuer: 'did:web:ica.example',
          credentialSubject: {
            '@type': 'Organization',
            id: ORGANIZATION_DID,
            taxID: ORGANIZATION_TAX_ID,
          },
        },
        response: {
          status: '200',
          outcome: { resourceType: 'OperationOutcome', issue: [] },
        },
      },
      {
        type: 'ServiceController-verification-v1.0',
        publicKeyJwk: controllerPublicKeyJwk,
        resource: {
          id: 'urn:uuid:00000000-0000-4000-8000-000000000002',
          type: ['VerifiableCredential', 'ServiceControllerCredential'],
          issuer: 'did:web:ica.example',
          credentialSubject: {
            owner: {
              '@type': 'Person',
              sameAs: CONTROLLER_SAME_AS,
            },
            provider: {
              '@type': 'Organization',
              taxID: ORGANIZATION_TAX_ID,
            },
          },
        },
        response: {
          status: '200',
          outcome: { resourceType: 'OperationOutcome', issue: [] },
        },
      },
    ],
  };
}

async function seedActiveBinding(service: VerificationCollectionsService): Promise<void> {
  await service.storeDidBindings([
    {
      id: `ica::es::animal-care::${ORGANIZATION_TAX_ID}`,
      tenantId: ROUTE.tenantId,
      jurisdiction: ROUTE.jurisdiction,
      sector: ROUTE.sector,
      resourceType: ROUTE.resourceType,
      thid: 'thid-original-verification',
      taxId: ORGANIZATION_TAX_ID,
      did: ORGANIZATION_DID,
      controllerSameAs: CONTROLLER_SAME_AS,
      controllerPublicKeyJwk: OLD_CONTROLLER_KEY,
      status: 'confirmed',
      createdAt: '2026-09-01T00:00:00.000Z',
      updatedAt: '2026-09-01T00:00:00.000Z',
      confirmedAt: '2026-09-01T00:00:00.000Z',
    },
  ]);
}

test('active controller binding cannot be replaced by reverify unless the deployment opts in', async () => {
  resetVerificationCollectionsMemStateForTests();
  const service = createCollectionsService();
  await seedActiveBinding(service);

  await assert.rejects(
    service.persistFromVerificationBundle(
      ROUTE,
      'thid-controller-rebind-denied',
      buildVerificationBundle(NEW_CONTROLLER_KEY),
    ),
    /ICA_ALLOW_CONTROLLER_REBIND_ON_REVERIFY=true/,
  );

  const bindings = await service.listDidBindings();
  assert.deepEqual(bindings[0]?.controllerPublicKeyJwk, OLD_CONTROLLER_KEY);
  assert.equal(bindings[0]?.status, 'confirmed');
});

test('opted-in reverify replaces only the controller key and records the superseded thumbprint', async () => {
  resetVerificationCollectionsMemStateForTests();
  const service = createCollectionsService(true);
  await seedActiveBinding(service);

  await service.persistFromVerificationBundle(
    ROUTE,
    'thid-controller-rebind-allowed',
    buildVerificationBundle(NEW_CONTROLLER_KEY),
  );

  const bindings = await service.listDidBindings();
  assert.deepEqual(bindings[0]?.controllerPublicKeyJwk, NEW_CONTROLLER_KEY);
  assert.equal(bindings[0]?.status, 'draft');
  assert.equal(
    bindings[0]?.previousControllerKeyThumbprint,
    toJwkThumbprintSha256Urn(OLD_CONTROLLER_KEY),
  );
  assert.match(bindings[0]?.controllerKeyReboundAt || '', /^\d{4}-\d{2}-\d{2}T/);
});

test('re-enrollment after successful removal accepts a new controller key without the opt-in', async () => {
  resetVerificationCollectionsMemStateForTests();
  const service = createCollectionsService();
  await seedActiveBinding(service);
  const [binding] = await service.listDidBindings();
  assert.ok(binding);
  await service.storeDidBindings([{
    ...binding,
    status: 'removed',
    removedAt: '2026-09-02T00:00:00.000Z',
    updatedAt: '2026-09-02T00:00:00.000Z',
  }]);

  await service.persistFromVerificationBundle(
    ROUTE,
    'thid-controller-reenrollment',
    buildVerificationBundle(NEW_CONTROLLER_KEY),
  );

  const rebound = (await service.listDidBindings())[0];
  assert.deepEqual(rebound?.controllerPublicKeyJwk, NEW_CONTROLLER_KEY);
  assert.equal(rebound?.status, 'draft');
});

test('the opt-in never turns a controller identity change into key rotation', async () => {
  resetVerificationCollectionsMemStateForTests();
  const service = createCollectionsService(true);
  await seedActiveBinding(service);
  const bundle = buildVerificationBundle(NEW_CONTROLLER_KEY);
  const controllerResource = bundle.data[1]?.resource as {
    credentialSubject?: {
      owner?: { sameAs?: string };
    };
  };
  const controllerSubject = controllerResource.credentialSubject as {
    owner?: { sameAs?: string };
  };
  if (controllerSubject.owner) {
    controllerSubject.owner.sameAs = 'urn:multibase:zDifferentControllerIdentity';
  }

  await assert.rejects(
    service.persistFromVerificationBundle(
      ROUTE,
      'thid-controller-identity-change-denied',
      bundle,
    ),
    /cannot replace controller identity/,
  );
});

test('OpenAPI publishes the default-deny reverify controller-key policy', () => {
  const spec = buildIcaVerifyOpenApiSpec();
  const operation = spec.paths[
    '/ica/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify-response'
  ]?.post;
  assert.match(
    operation?.description || '',
    /ICA_ALLOW_CONTROLLER_REBIND_ON_REVERIFY=true.*disabled by default/s,
  );
});
