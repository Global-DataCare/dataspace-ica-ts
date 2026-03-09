import assert from 'node:assert/strict';
import test from 'node:test';
import { DataspaceSyncService } from '../src/api/tools/dataspace-sync.ts';
import type {
  EvidenceRecord,
  IssuedCredentialRecord,
} from '../src/api/tools/verification-collections-storage.ts';

test('DataspaceSyncService marks origin dataspace and attempts sync to configured target', async () => {
  const previousFetch = globalThis.fetch;
  const warned: string[] = [];
  const observedSyncPayloads: Record<string, unknown>[] = [];
  const previousWarn = console.warn;
  console.warn = (message?: unknown, ...rest: unknown[]) => {
    warned.push([String(message || ''), ...rest.map((entry) => String(entry))].join(' '));
  };

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;
    if (url.includes('/dummy-sync')) {
      if (typeof init?.body === 'string') {
        observedSyncPayloads.push(JSON.parse(init.body) as Record<string, unknown>);
      }
      return new Response('upstream unavailable', { status: 503, statusText: 'Service Unavailable' });
    }
    return previousFetch(input, init);
  }) as typeof fetch;

  try {
    const service = new DataspaceSyncService({
      strict: false,
      timeoutMs: 3000,
      targets: [
        {
          did: 'did:web:id.delta-dao.com',
          endpointUrl: 'https://adapter.example.org/dummy-sync',
        },
      ],
    });

    const record: IssuedCredentialRecord = {
      id: 'urn:uuid:issued-001',
      tenantId: 'ica',
      jurisdiction: 'ES',
      sector: 'animal-care',
      resourceType: 'member-onboarding',
      thid: 'thid-001',
      credentialType: 'member-onboarding',
      credentialId: 'urn:uuid:vc-001',
      subjectId: 'did:web:member.example.org',
      issuerId: 'did:web:id.delta-dao.com',
      originDataspaceDid: 'did:web:id.delta-dao.com',
      credential: {
        id: 'urn:uuid:vc-001',
        credentialSubject: { id: 'did:web:member.example.org' },
      },
      dataspacePublications: service.buildInitialPublications('did:web:id.delta-dao.com'),
      createdAt: '2026-03-08T00:00:00.000Z',
      updatedAt: '2026-03-08T00:00:00.000Z',
    };

    const synced = await service.syncIssuedCredentialRecord(record, { event: 'issued', status: 'active' });
    const publications = synced.dataspacePublications || [];
    assert.equal(publications.length, 1);
    assert.equal(publications[0]?.did, 'did:web:id.delta-dao.com');
    assert.equal(publications[0]?.status, 'origin');
    assert.ok(synced.contentHashSha3_384);

    const externalRecord: IssuedCredentialRecord = {
      ...record,
      id: 'urn:uuid:issued-002',
      credentialId: 'urn:uuid:vc-002',
      originDataspaceDid: 'did:web:external.example.org',
      dataspacePublications: service.buildInitialPublications('did:web:external.example.org'),
    };
    const syncedExternal = await service.syncIssuedCredentialRecord(externalRecord, { event: 'issued', status: 'active' });
    const externalPublications = syncedExternal.dataspacePublications || [];
    assert.equal(externalPublications.length, 2);
    const deltaDaoEntry = externalPublications.find((entry) => entry.did === 'did:web:id.delta-dao.com');
    const originEntry = externalPublications.find((entry) => entry.did === 'did:web:external.example.org');
    assert.equal(originEntry?.status, 'origin');
    assert.equal(deltaDaoEntry?.status, 'failed');
    assert.ok(deltaDaoEntry?.lastAttemptAt);
    assert.equal(warned.some((entry) => entry.includes('dataspace=did:web:id.delta-dao.com')), true);
    const metadataPayload = observedSyncPayloads.find((entry) => entry.kind === 'credential');
    assert.ok(metadataPayload);
    assert.equal(metadataPayload?.['@type'], 'DataspacePublicationMetadata');
    assert.equal(metadataPayload?.resourceType, undefined);
  } finally {
    globalThis.fetch = previousFetch;
    console.warn = previousWarn;
  }
});

test('DataspaceSyncService syncEvidenceRecord computes hash and keeps origin marker', async () => {
  const service = new DataspaceSyncService({
    strict: false,
    targets: [],
  });
  const record: EvidenceRecord = {
    id: 'urn:uuid:evidence-001',
    issuedCredentialRecordId: 'urn:uuid:issued-001',
    tenantId: 'ica',
    jurisdiction: 'ES',
    sector: 'animal-care',
    resourceType: 'official-registry',
    thid: 'thid-evidence-001',
    evidenceType: 'official-registry',
    evidence: {
      type: 'electronic_record',
      record: {
        type: 'vc+jwt',
      },
    },
    originDataspaceDid: 'did:web:id.delta-dao.com',
    dataspacePublications: service.buildInitialPublications('did:web:id.delta-dao.com'),
    createdAt: '2026-03-08T00:00:00.000Z',
    updatedAt: '2026-03-08T00:00:00.000Z',
  };

  const synced = await service.syncEvidenceRecord(record, { event: 'added', status: 'active' });
  assert.ok(synced.contentHashSha3_384);
  assert.equal(synced.dataspacePublications?.[0]?.status, 'origin');
});
