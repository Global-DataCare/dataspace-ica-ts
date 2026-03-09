import type { ProviderDataset } from './dcat-catalog.ts';

type JsonObject = Record<string, unknown>;

function buildDatasetDdoEntry(catalogBaseUrl: string, dataset: ProviderDataset): JsonObject {
  return {
    id: `${catalogBaseUrl}/ddo/datasets/${dataset.datasetId}`,
    type: 'OrganizationDataOffering',
    datasetId: dataset.datasetId,
    title: dataset.title,
    participantDid: dataset.publisherDid,
    accessUrl: dataset.accessUrl,
    sector: dataset.sector || undefined,
    jurisdiction: dataset.jurisdiction || undefined,
  };
}

export function buildCatalogDdo(
  catalogBaseUrl: string,
  datasets: ProviderDataset[],
): JsonObject {
  return {
    profile: 'urn:ica:ddo:catalog:v1',
    id: `${catalogBaseUrl}/ddo`,
    type: 'DataCatalogDDO',
    catalogUrl: catalogBaseUrl,
    generatedAt: new Date().toISOString(),
    datasetCount: datasets.length,
    datasetList: datasets.map((dataset) => buildDatasetDdoEntry(catalogBaseUrl, dataset)),
  };
}

