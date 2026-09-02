/**
 * Flow contract - one-time governed host activation without a bootstrap DID file:
 * 1. The ICA operator creates a time-bounded activation for one exact approved host profile.
 * 2. Only the raw activation code leaves the ICA process; persistence keeps its SHA-256 hash.
 * 3. The host submits that code together with its public JWK and signed authorization request.
 * 4. ICA consumes the activation atomically before accepting the request.
 * 5. Reuse, expiry or any change to domain, network, legal identity or controller fails closed.
 * Authorization invariant: thid correlates the async request but never acts as its bearer secret.
 * Persistence invariant: the raw activation code is never persisted.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  HostActivationService,
  resetHostActivationMemStateForTests,
} from '../src/api/host-activation.ts';

const approvedHost = {
  jurisdiction: 'ES',
  sector: 'onehealth-research',
  legalName: 'Example Hosting Provider',
  addressCountry: 'ES',
  taxId: 'VAT-EXAMPLE-001',
  controllerEmail: 'controller@provider.example',
  serviceUrl: 'https://host.provider.example',
};

test.afterEach(() => resetHostActivationMemStateForTests());

test('creates and consumes one activation without persisting its raw code', async () => {
  const now = new Date('2026-09-02T12:00:00.000Z');
  const service = new HostActivationService({ provider: 'mem' }, () => now);

  const created = await service.create({
    domain: 'host.provider.example',
    networkKind: 'network',
    expiresInSeconds: 72 * 60 * 60,
    createdBy: 'ica-operator',
    approval: approvedHost,
  });

  assert.match(created.activationCode, /^ica_host_/);
  assert.equal(JSON.stringify(created.record).includes(created.activationCode), false);
  assert.equal(created.record.domain, 'host.provider.example');
  assert.equal(created.record.networkKind, 'network');

  const consumed = await service.consume({
    activationCode: created.activationCode,
    domain: 'host.provider.example',
    networkKind: 'network',
    thid: 'host-request-001',
    approval: approvedHost,
  });
  assert.equal(consumed.status, 'consumed');
  assert.equal(consumed.consumedByThid, 'host-request-001');

  await assert.rejects(
    service.consume({
      activationCode: created.activationCode,
      domain: 'host.provider.example',
      networkKind: 'network',
      thid: 'host-request-replay',
      approval: approvedHost,
    }),
    /invalid, expired, already consumed or does not match/i,
  );
});

test('rejects a valid code for another domain or network and preserves it for its approved scope', async () => {
  const service = new HostActivationService({ provider: 'mem' });
  const created = await service.create({
    domain: 'host.provider.example',
    networkKind: 'network',
    expiresInSeconds: 3600,
    createdBy: 'ica-operator',
    approval: approvedHost,
  });

  await assert.rejects(
    service.consume({
      activationCode: created.activationCode,
      domain: 'other.example',
      networkKind: 'network',
      thid: 'wrong-domain',
      approval: { ...approvedHost, serviceUrl: 'https://other.example' },
    }),
    /invalid, expired, already consumed or does not match/i,
  );
  await assert.rejects(
    service.consume({
      activationCode: created.activationCode,
      domain: 'host.provider.example',
      networkKind: 'test-network',
      thid: 'wrong-network',
      approval: approvedHost,
    }),
    /invalid, expired, already consumed or does not match/i,
  );
  await assert.rejects(
    service.consume({
      activationCode: created.activationCode,
      domain: 'host.provider.example',
      networkKind: 'network',
      thid: 'wrong-controller',
      approval: { ...approvedHost, controllerEmail: 'another-controller@provider.example' },
    }),
    /approved host data/i,
  );

  const consumed = await service.consume({
    activationCode: created.activationCode,
    domain: 'host.provider.example',
    networkKind: 'network',
    thid: 'approved-scope',
    approval: approvedHost,
  });
  assert.equal(consumed.status, 'consumed');
});

test('rejects an expired activation', async () => {
  let now = new Date('2026-09-02T12:00:00.000Z');
  const service = new HostActivationService({ provider: 'mem' }, () => now);
  const created = await service.create({
    domain: 'host.provider.example',
    networkKind: 'network',
    expiresInSeconds: 60,
    createdBy: 'ica-operator',
    approval: approvedHost,
  });
  now = new Date('2026-09-02T12:01:01.000Z');

  await assert.rejects(
    service.consume({
      activationCode: created.activationCode,
      domain: 'host.provider.example',
      networkKind: 'network',
      thid: 'expired-request',
      approval: approvedHost,
    }),
    /invalid, expired, already consumed or does not match/i,
  );
});
