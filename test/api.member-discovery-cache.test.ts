import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isMemberDiscoveryUrlAllowed,
  MemberDiscoveryCache,
  parseMemberDiscoveryAllowedHosts,
  type DiscoveryJsonFetcher,
} from '../src/api/tools/member-discovery-cache.ts';
import type { IssuedCredentialRecord } from '../src/api/tools/verification-collections/types.ts';

const did = 'did:web:member.example';
const didUrl = 'https://member.example/.well-known/did.json';
const participantUrl = 'https://member.example/.well-known/legal-participant.vc.json';
const catalogUrl = 'https://member.example/dcat3/catalog';

function credential(type: string, id: string): IssuedCredentialRecord {
  return {
    id,
    tenantId: 'ica',
    jurisdiction: 'ES',
    sector: 'health-care',
    resourceType: 'contract',
    thid: 'thread-1',
    credentialType: type,
    credentialId: id,
    subjectId: did,
    issuerId: 'did:web:ica.example',
    credential: {
      id,
      type: ['VerifiableCredential', type],
      credentialSubject: { id: did, taxID: 'VATES-B00000000' },
    },
    createdAt: '2026-07-21T00:00:00.000Z',
    updatedAt: '2026-07-21T00:00:00.000Z',
  };
}

test('member discovery host allowlist accepts IPs, DNS names and origins but rejects URL paths and credentials', () => {
  const allowed = parseMemberDiscoveryAllowedHosts('192.0.2.10, member.example, https://catalog.example:8443');
  assert.deepEqual([...allowed].sort(), ['192.0.2.10', 'catalog.example', 'member.example']);
  assert.equal(isMemberDiscoveryUrlAllowed('http://192.0.2.10/.well-known/did.json', allowed), true);
  assert.equal(isMemberDiscoveryUrlAllowed('https://member.example/.well-known/did.json', allowed), true);
  assert.equal(isMemberDiscoveryUrlAllowed('https://unlisted.example/.well-known/did.json', allowed), false);
  assert.throws(() => parseMemberDiscoveryAllowedHosts('https://member.example/path'), /Use an IP, DNS name, or HTTP\(S\) origin/);
  assert.throws(() => parseMemberDiscoveryAllowedHosts('https://user:secret@member.example'), /Use an IP, DNS name, or HTTP\(S\) origin/);
});

test('MemberDiscoveryCache returns documents, current VCs and exact Gaia-X VC-JWT attachments, then reuses cache', async () => {
  let calls = 0;
  const fetcher: DiscoveryJsonFetcher = async (url) => {
    calls += 1;
    if (url === didUrl) return { document: { id: did, service: [
      { id: '#legal-participant', type: 'LegalPersonCredential', serviceEndpoint: participantUrl },
      { id: '#catalog', type: 'CatalogService', serviceEndpoint: catalogUrl },
    ] } };
    if (url === participantUrl) return { document: { proof: { type: 'EnvelopedVerifiableCredential', id: 'data:application/vc+jwt,participant.jwt.sig' } } };
    if (url === catalogUrl) return { document: { '@type': 'dcat:Catalog' } };
    throw new Error('optional artifact unavailable');
  };
  const cache = new MemberDiscoveryCache(fetcher, 300);
  const input = {
    dataset: { datasetId: 'member', publisherDid: did, title: 'Member', accessUrl: didUrl, jurisdiction: 'ES', sector: 'health-care' },
    issuedCredentials: [credential('LegalRepresentativeCredential', 'urn:person'), credential('OrganizationCredential', 'urn:organization')],
    didDocuments: [],
    now: new Date('2026-07-21T10:00:00.000Z'),
  };

  const first = await cache.resolve(input);
  const callsAfterFirst = calls;
  const second = await cache.resolve({ ...input, now: new Date('2026-07-21T10:01:00.000Z') });

  assert.equal(first.vc[0]?.id, 'urn:organization');
  assert.equal(first.did.document.id, did);
  assert.equal(first.dcat?.document['@type'], 'dcat:Catalog');
  assert.equal(first.attachments[0]?.role, 'gaia-x-participant-vc-jwt');
  assert.equal(first.attachments[0]?.data.json.jwt, 'participant.jwt.sig');
  assert.deepEqual(second, first);
  assert.equal(calls, callsAfterFirst);
});
