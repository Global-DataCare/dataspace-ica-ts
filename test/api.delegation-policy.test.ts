import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import { parseDelegationPolicyRoute } from '../src/api/path.ts';
import { DelegationPolicyUpsertRequestManager } from '../src/api/managers/delegation-policy-upsert-request-manager.ts';
import { DelegationPolicyUpsertResponseManager } from '../src/api/managers/delegation-policy-upsert-response-manager.ts';
import type {
  DelegationPolicyRouteContext,
  DelegationPolicyUpsertResult,
} from '../src/api/types.ts';

test('DelegationPolicy upsert managers accept valid ODRL policy and return polling payload', async () => {
  const parsed = parseDelegationPolicyRoute('/acme/cds-ES/v1/animal-care/network/policies/delegations/_upsert');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const store = new InMemoryEntityJobStore<DelegationPolicyRouteContext, DelegationPolicyUpsertResult>(60);
  const requestManager = new DelegationPolicyUpsertRequestManager(store);
  const responseManager = new DelegationPolicyUpsertResponseManager(store);

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-delegation-policy-upsert-001',
    thid: 'thid-delegation-policy-upsert-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/policies/delegations/upsert-request/v1',
    body: {
      data: [
        {
          resource: {
            '@context': [
              'http://www.w3.org/ns/odrl.jsonld',
              {
                ovc: 'https://w3id.org/gaia-x/ovc/1/',
                sdo: 'https://schema.org/',
              },
            ],
            profile: 'https://w3id.org/gaia-x/ovc/1/',
            uid: 'urn:policy:ica:es:delegate:1120:zEmailHash:official-registry:v1',
            type: 'Set',
            assignee: {
              '@id': 'did:web:ica.example.org:ica:cds-ES:v1:onehealth:delegate:1120:zEmailHash',
            },
            permission: [
              {
                target: 'urn:ica:organization:*:evidence:official-registry',
                action: { '@id': 'odrl:write' },
                'ovc:constraint': [
                  {
                    'ovc:leftOperand': '$.credentialSubject.id',
                    'odrl:operator': 'odrl:eq',
                    'odrl:rightOperand':
                      'did:web:ica.example.org:ica:cds-ES:v1:onehealth:delegate:1120:zEmailHash',
                  },
                  {
                    'ovc:leftOperand': '$.credentialSubject.hasOccupation.identifier',
                    'odrl:operator': 'odrl:eq',
                    'odrl:rightOperand': 'urn:ilo:ilostat:isco-08:1120',
                  },
                ],
              },
            ],
          },
        },
      ],
    },
  }));

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/policies/delegations/_upsert';
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
    '/acme/cds-ES/v1/animal-care/network/policies/delegations/_upsert-response',
  );

  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/policies/delegations/_upsert-response?thid=thid-delegation-policy-upsert-001',
  );
  const pollOutcome = await responseManager.poll(parsed.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');
  if (pollOutcome.type !== 'succeeded') return;

  const body = (pollOutcome.payload as any)?.body;
  assert.equal(body?.data?.[0]?.resource?.policyType, 'delegations');
  assert.equal(
    body?.data?.[0]?.resource?.content?.[0]?.roleIdentifier,
    'urn:ilo:ilostat:isco-08:1120',
  );
});

test('DelegationPolicy upsert managers reject policy without role constraint', async () => {
  const parsed = parseDelegationPolicyRoute('/acme/cds-ES/v1/animal-care/network/policies/delegations/_upsert');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const store = new InMemoryEntityJobStore<DelegationPolicyRouteContext, DelegationPolicyUpsertResult>(60);
  const requestManager = new DelegationPolicyUpsertRequestManager(store);

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-delegation-policy-upsert-invalid-001',
    thid: 'thid-delegation-policy-upsert-invalid-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/policies/delegations/upsert-request/v1',
    body: {
      data: [
        {
          resource: {
            '@context': ['http://www.w3.org/ns/odrl.jsonld'],
            permission: [
              {
                action: { '@id': 'odrl:write' },
                assignee: {
                  '@id': 'did:web:ica.example.org:ica:cds-ES:v1:onehealth:delegate:1120:zEmailHash',
                },
                'ovc:constraint': [
                  {
                    'ovc:leftOperand': '$.credentialSubject.id',
                    'odrl:operator': 'odrl:eq',
                    'odrl:rightOperand':
                      'did:web:ica.example.org:ica:cds-ES:v1:onehealth:delegate:1120:zEmailHash',
                  },
                ],
              },
            ],
          },
        },
      ],
    },
  }));

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/policies/delegations/_upsert';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsed.context, req);
  assert.equal(submitOutcome.type, 'error');
  if (submitOutcome.type !== 'error') return;
  assert.equal(submitOutcome.statusCode, 400);
  assert.match(submitOutcome.message, /hasOccupation\.identifier/i);
});
