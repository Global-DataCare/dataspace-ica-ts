export type HealthDcatAccessLevel = 'public' | 'restricted' | 'non-public';

export type HealthDcatContext = {
  dcat: 'https://www.w3.org/ns/dcat#';
  dcterms: 'http://purl.org/dc/terms/';
  odrl: 'http://www.w3.org/ns/odrl/2/';
  dcatap: 'http://data.europa.eu/r5r/';
  healthdcatap: 'http://healthdataportal.eu/ns/health#';
  foaf: 'http://xmlns.com/foaf/0.1/';
  vcard: 'http://www.w3.org/2006/vcard/ns#';
};

export type HealthDcatContactPoint = {
  '@type': 'vcard:Kind';
  'vcard:hasEmail'?: { '@id': string };
  'vcard:hasURL'?: { '@id': string };
};

export type HealthDcatAgent = {
  '@id': string;
  '@type': 'foaf:Agent';
  'foaf:name': string;
  'dcat:contactPoint': HealthDcatContactPoint;
};

export type HealthDcatDistribution = {
  '@id': string;
  '@type': 'dcat:Distribution';
  'dcat:accessURL': Array<{ '@id': string }>;
  'dcatap:applicableLegislation': Array<{ '@id': string }>;
};

export type HealthDcatDataset = {
  '@id': string;
  '@type': 'dcat:Dataset';
  'dcterms:identifier': string[];
  'dcterms:title': Array<{ '@value': string; '@language': string }>;
  'dcterms:description': Array<{ '@value': string; '@language': string }>;
  'dcterms:accessRights': { '@id': string };
  'dcatap:applicableLegislation': Array<{ '@id': string }>;
  'dcat:theme': Array<{ '@id': string }>;
  'healthdcatap:healthCategory': Array<{ '@id': string }>;
  'healthdcatap:hdab': HealthDcatAgent;
  'dcat:distribution': HealthDcatDistribution[];
};

export type HealthDcatCatalogDocument = {
  '@context': HealthDcatContext;
  '@id': string;
  '@type': 'dcat:Catalog';
  'dcterms:title': Array<{ '@value': string; '@language': string }>;
  'dcterms:description': Array<{ '@value': string; '@language': string }>;
  'dcatap:applicableLegislation': Array<{ '@id': string }>;
  'dcat:dataset': HealthDcatDataset[];
};

export type HealthDcatRelease7ExampleInput = {
  catalogId: string;
  catalogTitle: string;
  catalogDescription: string;
  datasetId: string;
  datasetIdentifier: string;
  datasetTitle: string;
  datasetDescription: string;
  datasetAccessRightsUri: string;
  datasetThemeUri: string;
  healthCategoryUri: string;
  hdabId: string;
  hdabName: string;
  hdabContactEmail?: string;
  hdabContactUrl?: string;
  distributionId: string;
  distributionAccessUrl: string;
  language?: string;
  applicableLegislationUri?: string;
};

export const HEALTHDCAT_RELEASE_7_URL =
  'https://healthdataeu.pages.code.europa.eu/healthdcat-ap/releases/release-7/' as const;

export const EHDS_LEGISLATION_URI =
  'http://data.europa.eu/eli/reg/2025/327/oj' as const;

export const DCAT_HEALTH_THEME_URI =
  'http://publications.europa.eu/resource/authority/data-theme/HEAL' as const;

/**
 * Builds a parameterized HealthDCAT-AP Release 7 JSON-LD example suitable for
 * tests and docs. Callers provide all deployment-specific and vocabulary-
 * specific identifiers so the example can be reused without embedding local
 * tenant URIs or placeholder values in the implementation.
 */
export function buildHealthDcatRelease7Example(
  input: HealthDcatRelease7ExampleInput,
): HealthDcatCatalogDocument {
  const language = input.language || 'en';
  const applicableLegislationUri = input.applicableLegislationUri || EHDS_LEGISLATION_URI;
  const contactPoint: HealthDcatContactPoint = {
    '@type': 'vcard:Kind',
  };

  if (input.hdabContactEmail) {
    contactPoint['vcard:hasEmail'] = { '@id': input.hdabContactEmail };
  }
  if (input.hdabContactUrl) {
    contactPoint['vcard:hasURL'] = { '@id': input.hdabContactUrl };
  }

  return {
    '@context': {
      dcat: 'https://www.w3.org/ns/dcat#',
      dcterms: 'http://purl.org/dc/terms/',
      odrl: 'http://www.w3.org/ns/odrl/2/',
      dcatap: 'http://data.europa.eu/r5r/',
      healthdcatap: 'http://healthdataportal.eu/ns/health#',
      foaf: 'http://xmlns.com/foaf/0.1/',
      vcard: 'http://www.w3.org/2006/vcard/ns#',
    },
    '@id': input.catalogId,
    '@type': 'dcat:Catalog',
    'dcterms:title': [
      { '@value': input.catalogTitle, '@language': language },
    ],
    'dcterms:description': [
      { '@value': input.catalogDescription, '@language': language },
    ],
    'dcatap:applicableLegislation': [
      { '@id': applicableLegislationUri },
    ],
    'dcat:dataset': [
      {
        '@id': input.datasetId,
        '@type': 'dcat:Dataset',
        'dcterms:identifier': [input.datasetIdentifier],
        'dcterms:title': [
          { '@value': input.datasetTitle, '@language': language },
        ],
        'dcterms:description': [
          { '@value': input.datasetDescription, '@language': language },
        ],
        'dcterms:accessRights': {
          '@id': input.datasetAccessRightsUri,
        },
        'dcatap:applicableLegislation': [
          { '@id': applicableLegislationUri },
        ],
        'dcat:theme': [
          { '@id': input.datasetThemeUri },
        ],
        'healthdcatap:healthCategory': [
          { '@id': input.healthCategoryUri },
        ],
        'healthdcatap:hdab': {
          '@id': input.hdabId,
          '@type': 'foaf:Agent',
          'foaf:name': input.hdabName,
          'dcat:contactPoint': contactPoint,
        },
        'dcat:distribution': [
          {
            '@id': input.distributionId,
            '@type': 'dcat:Distribution',
            'dcat:accessURL': [
              { '@id': input.distributionAccessUrl },
            ],
            'dcatap:applicableLegislation': [
              { '@id': applicableLegislationUri },
            ],
          },
        ],
      },
    ],
  };
}
