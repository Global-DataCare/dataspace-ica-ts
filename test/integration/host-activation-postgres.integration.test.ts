/**
 * Flow contract - persisted host activation across independent ICA processes:
 * 1. An operator process creates one activation in PostgreSQL.
 * 2. A separate verifier process consumes it for the approved domain/network.
 * 3. A third process cannot replay the same activation.
 * Authorization invariant: only the exact domain, network and approved host profile can consume it.
 * Persistence invariant: PostgreSQL stores the hash and state, never the raw code.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { HostActivationService } from '../../src/api/host-activation.ts';

const postgresUrl = String(process.env.POSTGRES_MIGRATION_TEST_URL || '').trim();

test('persists and atomically consumes one host activation in PostgreSQL', {
  skip: postgresUrl ? false : 'POSTGRES_MIGRATION_TEST_URL is required',
}, async () => {
  const collectionPrefix = `activation_test_${process.pid}`;
  const config = { provider: 'postgres' as const, postgresUrl, collectionPrefix };
  const created = await new HostActivationService(config).create({
    domain: 'host.audit.example',
    networkKind: 'local-network',
    expiresInSeconds: 3600,
    createdBy: 'local-audit-operator',
    approval: {
      jurisdiction: 'ES',
      sector: 'onehealth-research',
      legalName: 'Example Hosting Provider',
      addressCountry: 'ES',
      taxId: 'VAT-EXAMPLE-001',
      controllerEmail: 'controller@host.audit.example',
      serviceUrl: 'https://host.audit.example',
    },
  });
  assert.equal(JSON.stringify(created.record).includes(created.activationCode), false);

  const consumed = await new HostActivationService(config).consume({
    activationCode: created.activationCode,
    domain: 'host.audit.example',
    networkKind: 'local-network',
    thid: 'local-audit-host-request',
    approval: created.record.approval,
  });
  assert.equal(consumed.status, 'consumed');

  await assert.rejects(
    new HostActivationService(config).consume({
      activationCode: created.activationCode,
      domain: 'host.audit.example',
      networkKind: 'local-network',
      thid: 'local-audit-host-replay',
      approval: created.record.approval,
    }),
    /already consumed/i,
  );
});
