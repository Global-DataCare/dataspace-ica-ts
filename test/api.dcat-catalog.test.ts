import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildDcatCatalog,
  buildDcatDiscoveryCatalog,
  buildProviderDatasetsFromIssuedCredentials,
  filterProviderDatasets,
  findProviderDatasetById,
} from '../src/api/tools/dcat-catalog.ts';
import { multibase58MultihashSha3_256 } from '../src/api/tools/multihash.ts';
import type { IssuedCredentialRecord } from '../src/api/tools/verification-collections/types.ts';

function buildIssuedRecord(input: {
  id: string;
  subjectDid: string;
  title: string;
  taxId?: string;
  tenantId?: string;
  jurisdiction?: string;
  sector?: string;
}): IssuedCredentialRecord {
  return {
    id: input.id,
    tenantId: input.tenantId || 'ica',
    jurisdiction: input.jurisdiction || 'ES',
    sector: input.sector || 'animal-care',
    resourceType: '202603081200',
    thid: 'thid-dcat-001',
    credentialType: 'OrganizationCredential',
    credentialId: input.id,
    subjectId: input.subjectDid,
    issuerId: 'did:web:ica.example.org',
    credential: {
      id: input.id,
      type: ['VerifiableCredential', 'OrganizationCredential'],
      credentialSubject: {
        id: input.subjectDid,
        legalName: input.title,
        taxID: input.taxId || 'VATES-A12345678',
        category: input.sector || 'animal-care',
        addressCountry: input.jurisdiction || 'ES',
      },
    },
    createdAt: '2026-03-08T00:00:00.000Z',
    updatedAt: '2026-03-08T00:00:00.000Z',
  };
}

test('buildProviderDatasetsFromIssuedCredentials builds deduplicated datasets for route scope', () => {
  const records: IssuedCredentialRecord[] = [
    buildIssuedRecord({
      id: 'urn:uuid:record-001',
      subjectDid: 'did:web:member-a.example.org',
      title: 'Member A',
    }),
    buildIssuedRecord({
      id: 'urn:uuid:record-002',
      subjectDid: 'did:web:member-a.example.org',
      title: 'Member A Duplicate',
    }),
    buildIssuedRecord({
      id: 'urn:uuid:record-003',
      subjectDid: 'did:web:member-b.example.org',
      title: 'Member B',
      sector: 'health-care',
    }),
  ];

  const datasets = buildProviderDatasetsFromIssuedCredentials(records, {
    tenantId: 'ica',
    jurisdiction: 'ES',
    sector: 'animal-care',
  });
  assert.equal(datasets.length, 1);
  assert.equal(datasets[0]?.publisherDid, 'did:web:member-a.example.org');
  assert.equal(datasets[0]?.datasetId, encodeURIComponent(multibase58MultihashSha3_256('VATES-A12345678')));
  assert.equal(datasets[0]?.accessUrl, 'https://member-a.example.org/.well-known/did.json');
});

test('buildProviderDatasetsFromIssuedCredentials ignores ICA internal membership DIDs and non-did:web identifiers', () => {
  const records: IssuedCredentialRecord[] = [
    buildIssuedRecord({
      id: 'urn:uuid:record-internal-001',
      subjectDid: 'did:web:ica.example.org:ica:cds-ES:v1:onehealth:organization:dataprovider:zInternalHash',
      title: 'Internal Membership Only',
      sector: 'onehealth',
    }),
    buildIssuedRecord({
      id: 'urn:uuid:record-urn-001',
      subjectDid: 'urn:organization:taxid:VATES-B12345678',
      title: 'URN only',
      sector: 'onehealth',
    }),
    buildIssuedRecord({
      id: 'urn:uuid:record-real-001',
      subjectDid: 'did:web:member-real.example.org',
      title: 'Member Real',
      taxId: 'VATES-C12345678',
      sector: 'onehealth',
    }),
  ];

  const datasets = buildProviderDatasetsFromIssuedCredentials(records, {
    tenantId: 'ica',
    jurisdiction: 'ES',
    sector: 'onehealth',
  });

  assert.equal(datasets.length, 1);
  assert.equal(datasets[0]?.publisherDid, 'did:web:member-real.example.org');
  assert.equal(datasets[0]?.datasetId, encodeURIComponent(multibase58MultihashSha3_256('VATES-C12345678')));
});

test('buildDcatCatalog builds dcat:Catalog with dcat:dataset entries', () => {
  const datasetId = encodeURIComponent(multibase58MultihashSha3_256('VATES-A12345678'));
  const datasets = [
    {
      datasetId,
      publisherDid: 'did:web:member-a.example.org',
      title: 'Member A',
      sector: 'animal-care',
      jurisdiction: 'ES',
      accessUrl: 'https://member-a.example.org/.well-known/did.json',
    },
  ];
  const catalog = buildDcatCatalog('https://ica.example.org/ica/cds-ES/v1/animal-care/dcat3/catalog', datasets) as Record<string, unknown>;
  assert.equal(catalog['@type'], 'dcat:Catalog');
  const entries = Array.isArray(catalog['dcat:dataset']) ? catalog['dcat:dataset'] as Array<Record<string, unknown>> : [];
  assert.equal(entries.length, 1);
  assert.equal(entries[0]?.['@type'], 'dcat:Dataset');
  assert.equal(entries[0]?.['dcterms:identifier'], datasetId);
});

test('buildDcatDiscoveryCatalog builds dcat:Catalog with dcat:service entries', () => {
  const catalog = buildDcatDiscoveryCatalog('https://ica.example.org/.well-known/dcat3/catalog', [
    {
      id: 'did:web:ica.example.org#dsp-catalog-service',
      type: 'CatalogService',
      serviceEndpoint: '/.well-known/dcat3/catalog',
    },
    {
      id: 'did:web:ica.example.org#dsp-data-service',
      type: 'DataService',
      serviceEndpoint: 'https://ica.example.org/.well-known/dspace-version',
    },
  ]) as Record<string, unknown>;

  assert.equal(catalog['@type'], 'dcat:Catalog');
  assert.equal(Array.isArray(catalog['dcat:dataset']), true);
  assert.equal((catalog['dcat:dataset'] as Array<unknown>).length, 0);
  const services = Array.isArray(catalog['dcat:service']) ? catalog['dcat:service'] as Array<Record<string, unknown>> : [];
  assert.equal(services.length, 2);
  assert.equal(services[0]?.['@type'], 'dcat:DataService');
  assert.equal(services[0]?.['dcat:endpointURL'], 'https://ica.example.org/.well-known/dcat3/catalog');
  assert.equal(services[1]?.['dcat:endpointURL'], 'https://ica.example.org/.well-known/dspace-version');
});

test('filterProviderDatasets and findProviderDatasetById work with filters and encoded id', () => {
  const datasetAId = encodeURIComponent(multibase58MultihashSha3_256('VATES-A12345678'));
  const datasetBId = encodeURIComponent(multibase58MultihashSha3_256('VATES-B12345678'));
  const datasets = [
    {
      datasetId: datasetAId,
      publisherDid: 'did:web:member-a.example.org',
      title: 'Member A',
      sector: 'animal-care',
      jurisdiction: 'ES',
      accessUrl: 'https://member-a.example.org/.well-known/did.json',
    },
    {
      datasetId: datasetBId,
      publisherDid: 'did:web:member-b.example.org',
      title: 'Member B',
      sector: 'health-care',
      jurisdiction: 'ES',
      accessUrl: 'https://member-b.example.org/.well-known/did.json',
    },
  ];

  const filtered = filterProviderDatasets(datasets, { sector: 'animal-care', jurisdiction: 'ES' });
  assert.equal(filtered.length, 1);
  const found = findProviderDatasetById(datasets, datasetBId);
  assert.equal(found?.publisherDid, 'did:web:member-b.example.org');
});
