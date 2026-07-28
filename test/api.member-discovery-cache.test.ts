// Flow contract: ICA member autodiscovery keeps three credential/evidence
// layers independent. `data[].vc[]` contains ICA-issued schema.org VC JSON;
// member-level `data[].attachments[]` contains exact signed Gaia-X VC-JWTs
// whose decoded subjects use required `gx:` semantics; and
// `credential.evidence[].attachments` remains audit evidence. These tests
// protect participant-first ordering, cache reuse, the host allowlist, and
// fail-closed rejection of a schema.org OrganizationCredential merely encoded
// as JWT and mislabeled as a Gaia-X participant attachment.

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

function vcJwt(credentialSubject: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'ES384', typ: 'vc+jwt' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: did,
    sub: String(credentialSubject.id || did),
    vc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'LegalPerson'],
      credentialSubject,
    },
  })).toString('base64url');
  return `${header}.${payload}.signature`;
}

const participantJwt = vcJwt({
  id: did,
  type: 'gx:LegalPerson',
  'gx:legalName': 'Synthetic Member',
  'gx:legalRegistrationNumber': { id: 'https://notary.example/registration/synthetic-member' },
  'gx:headquarterAddress': { 'gx:countryCode': 'ES' },
  'gx:legalAddress': { 'gx:countryCode': 'ES' },
});

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
    if (url === participantUrl) return { document: { proof: { type: 'EnvelopedVerifiableCredential', id: `data:application/vc+jwt,${participantJwt}` } } };
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
  assert.equal(first.attachments[0]?.data.json.jwt, participantJwt);
  assert.deepEqual(second, first);
  assert.equal(calls, callsAfterFirst);
});

test('MemberDiscoveryCache rejects a schema.org OrganizationCredential mislabeled as Gaia-X participant JWT', async () => {
  const schemaOrgJwt = vcJwt({
    id: did,
    '@type': 'Organization',
    legalName: 'Synthetic Member',
    taxID: 'VATES-B00000000',
  });
  const fetcher: DiscoveryJsonFetcher = async (url) => {
    if (url === didUrl) return { document: { id: did, service: [
      { id: '#legal-participant', type: 'LegalPersonCredential', serviceEndpoint: participantUrl },
    ] } };
    if (url === participantUrl) return {
      document: {
        proof: {
          type: 'EnvelopedVerifiableCredential',
          id: `data:application/vc+jwt,${schemaOrgJwt}`,
        },
      },
    };
    throw new Error('artifact unavailable');
  };

  const cache = new MemberDiscoveryCache(fetcher, 300);
  await assert.rejects(
    cache.resolve({
      dataset: {
        datasetId: 'member',
        publisherDid: did,
        title: 'Member',
        accessUrl: didUrl,
        jurisdiction: 'ES',
        sector: 'health-care',
      },
      issuedCredentials: [credential('OrganizationCredential', 'urn:organization')],
      didDocuments: [],
    }),
    /credentialSubject.type must be gx:LegalPerson/,
  );
});
