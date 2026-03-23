import { readFileSync } from 'node:fs';
import {
  getConfiguredSupportedJurisdictionIds,
} from './supported-jurisdictions.ts';
import {
  getConfiguredSupportedSectorIds,
  hasWildcardSupportedSector,
  getSupportedSectorCodings,
  getSupportedSectorsLanguage,
} from './supported-sectors.ts';
import { DIDCOMM_BUNDLE_TYPE } from './tools/didcomm-message.ts';

const OPERATION_OUTCOME_SCHEMA = {
  type: 'object',
  required: ['resourceType', 'issue'],
  properties: {
    resourceType: { type: 'string', enum: ['OperationOutcome'] },
    issue: {
      type: 'array',
      items: {
        type: 'object',
        required: ['severity', 'code', 'diagnostics'],
        properties: {
          severity: { type: 'string', enum: ['information', 'warning', 'error', 'fatal'] },
          code: { type: 'string' },
          diagnostics: { type: 'string' },
        },
      },
    },
  },
} as const;

const REVOCATION_DEBUG_CHECK_SCHEMA = {
  type: 'object',
  required: ['phase', 'status'],
  properties: {
    url: { type: 'string' },
    phase: { type: 'string', enum: ['discovery', 'download', 'verify'] },
    status: {
      type: 'string',
      enum: ['no_urls', 'ok', 'http_error', 'timeout', 'download_error', 'parse_error', 'revoked', 'verify_error'],
    },
    httpStatus: { type: 'integer' },
    message: { type: 'string' },
  },
} as const;

const REVOCATION_DEBUG_SCHEMA = {
  type: 'object',
  required: ['finalStatus', 'checks'],
  properties: {
    finalStatus: { type: 'string', enum: ['good', 'revoked', 'unknown'] },
    checks: {
      type: 'array',
      items: REVOCATION_DEBUG_CHECK_SCHEMA,
    },
  },
} as const;

const VERIFY_RESULT_SCHEMA = {
  type: 'object',
  required: [
    'ok',
    'verifiedAt',
    'templateUrl',
    'templateMatch',
    'signatureValid',
    'chainValid',
    'revocationStatus',
    'digest',
    'signerCertificateSerialNumber',
    'signerSubject',
    'signerIssuer',
    'hashes',
    'notes',
  ],
  properties: {
    ok: { type: 'boolean' },
    verifiedAt: { type: 'string' },
    templateUrl: { type: 'string' },
    templateMatch: { type: 'boolean' },
    signatureValid: { type: 'boolean' },
    chainValid: { type: 'boolean' },
    revocationStatus: { type: 'string', enum: ['good', 'revoked', 'unknown'] },
    digest: {
      type: 'object',
      required: ['alg', 'signedPdfHex', 'unsignedPdfHex', 'templateHex'],
      properties: {
        alg: { type: 'string' },
        signedPdfHex: { type: 'string' },
        unsignedPdfHex: { type: 'string' },
        templateHex: { type: 'string' },
      },
    },
    signerCertificateSerialNumber: { type: 'string' },
    signerSubject: { type: 'string' },
    signerIssuer: { type: 'string' },
    hashes: {
      type: 'object',
      required: ['signedPdfSha256Hex', 'unsignedPdfSha256Hex', 'templateSha256Hex'],
      properties: {
        signedPdfSha256Hex: { type: 'string' },
        unsignedPdfSha256Hex: { type: 'string' },
        templateSha256Hex: { type: 'string' },
      },
    },
    notes: {
      type: 'array',
      items: { type: 'string' },
    },
    annexFormFields: {
      type: 'object',
      additionalProperties: { type: 'string' },
      description: 'Optional extracted Terms annex form fields (AcroForm) from the signed PDF.',
    },
    revocationDebug: REVOCATION_DEBUG_SCHEMA,
    auditDocument: {
      type: 'object',
      required: ['provider', 'objectId', 'objectKey', 'attachmentUrl', 'contentType', 'sizeBytes', 'storedAt'],
      properties: {
        provider: { type: 'string', enum: ['filesystem', 'gcs'] },
        objectId: { type: 'string' },
        objectKey: { type: 'string' },
        bucket: { type: 'string' },
        attachmentUrl: { type: 'string' },
        contentType: { type: 'string' },
        sizeBytes: { type: 'integer' },
        storedAt: { type: 'string' },
      },
    },
  },
} as const;

const VERIFY_BUNDLE_BODY_SCHEMA = {
  type: 'object',
  required: ['resourceType', 'type', 'total', 'data'],
  properties: {
    resourceType: { type: 'string', enum: ['Bundle'] },
    type: { type: 'string', enum: ['batch-response'] },
    total: { type: 'integer' },
    issues: OPERATION_OUTCOME_SCHEMA,
    data: {
      type: 'array',
      items: {
        type: 'object',
        required: ['type', 'resource', 'response'],
        properties: {
          type: { type: 'string' },
          resource: { type: 'object', additionalProperties: true },
          response: {
            type: 'object',
            required: ['status', 'outcome'],
            properties: {
              status: { type: 'string' },
              outcome: OPERATION_OUTCOME_SCHEMA,
            },
          },
        },
      },
    },
  },
} as const;

const DIDCOMM_VERIFY_RESPONSE_SCHEMA = {
  type: 'object',
  required: ['jti', 'iss', 'aud', 'thid', 'type', 'body'],
  properties: {
    jti: { type: 'string' },
    iss: { type: 'string' },
    aud: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string', enum: ['application/bundle-api+json'] },
    attachments: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'media_type', 'data'],
        properties: {
          id: { type: 'string' },
          format: { type: 'string', enum: ['vc+jwt'] },
          media_type: { type: 'string', enum: ['application/vc+jwt'] },
          filename: { type: 'string' },
          data: {
            type: 'object',
            properties: {
              json: {
                type: 'object',
                properties: {
                  format: { type: 'string', enum: ['vc+jwt'] },
                  jwt: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
    body: VERIFY_BUNDLE_BODY_SCHEMA,
  },
} as const;

const ERROR_BUNDLE_BODY_SCHEMA = {
  type: 'object',
  required: ['resourceType', 'type', 'total', 'data', 'issues'],
  properties: {
    resourceType: { type: 'string', enum: ['Bundle'] },
    type: { type: 'string', enum: ['batch-response'] },
    total: { type: 'integer', enum: [0] },
    data: {
      type: 'array',
      maxItems: 0,
      items: { type: 'object', additionalProperties: true },
      example: [],
    },
    issues: OPERATION_OUTCOME_SCHEMA,
  },
  example: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 0,
    data: [],
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'error',
          code: 'invalid',
          diagnostics: 'Invalid request.',
        },
      ],
    },
  },
} as const;

const DIDCOMM_ERROR_RESPONSE_SCHEMA = {
  type: 'object',
  required: ['jti', 'iss', 'aud', 'thid', 'type', 'body'],
  properties: {
    jti: { type: 'string' },
    iss: { type: 'string' },
    aud: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string', enum: ['application/bundle-api+json'] },
    body: ERROR_BUNDLE_BODY_SCHEMA,
  },
} as const;

const DCAT_CATALOG_REQUEST_SCHEMA = {
  type: 'object',
  properties: {
    filters: {
      type: 'object',
      properties: {
        sector: { type: 'string' },
        jurisdiction: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
} as const;

const DCAT_DATASET_SCHEMA = {
  type: 'object',
  required: [
    '@id',
    '@type',
    'dcterms:title',
    'dcterms:identifier',
    'dcterms:publisher',
    'dcat:distribution',
    'odrl:hasPolicy',
  ],
  properties: {
    '@id': { type: 'string' },
    '@type': { type: 'string', enum: ['dcat:Dataset'] },
    'dcterms:title': { type: 'string' },
    'dcterms:identifier': { type: 'string' },
    'dcterms:publisher': {
      type: 'object',
      required: ['@id'],
      properties: {
        '@id': { type: 'string' },
      },
      additionalProperties: false,
    },
    'dcat:theme': { type: 'string' },
    'dcterms:spatial': { type: 'string' },
    'dcat:distribution': {
      type: 'array',
      items: {
        type: 'object',
        required: ['@type', 'dcat:accessURL'],
        properties: {
          '@type': { type: 'string', enum: ['dcat:Distribution'] },
          'dcat:accessURL': { type: 'string' },
        },
        additionalProperties: false,
      },
    },
    'odrl:hasPolicy': {
      type: 'object',
      required: ['@type'],
      properties: {
        '@type': { type: 'string', enum: ['odrl:Set'] },
      },
      additionalProperties: true,
    },
  },
  additionalProperties: false,
} as const;

const DCAT_CATALOG_SCHEMA = {
  type: 'object',
  required: ['@context', '@id', '@type', 'dcat:dataset'],
  properties: {
    '@context': {
      type: 'object',
      required: ['dcat', 'dcterms', 'odrl'],
      properties: {
        dcat: { type: 'string' },
        dcterms: { type: 'string' },
        odrl: { type: 'string' },
      },
      additionalProperties: false,
    },
    '@id': { type: 'string' },
    '@type': { type: 'string', enum: ['dcat:Catalog'] },
    'dcat:dataset': {
      type: 'array',
      items: DCAT_DATASET_SCHEMA,
    },
  },
  additionalProperties: false,
} as const;

const DCAT_CATALOG_REQUEST_EXAMPLE = {
  filters: {
    sector: 'onehealth',
    jurisdiction: 'ES',
  },
} as const;

const DCAT_DATASET_EXAMPLE = {
  '@id': 'https://ica.example.org/ica/cds-ES/v1/onehealth/dcat3/catalog/datasets/z3MpnvTtN9h7K4N5XGtrPJxRQJ4mknpXhD2A9N4rb1n3Q',
  '@type': 'dcat:Dataset',
  'dcterms:title': 'Clinica Veterinaria Norte dataset',
  'dcterms:identifier': 'z3MpnvTtN9h7K4N5XGtrPJxRQJ4mknpXhD2A9N4rb1n3Q',
  'dcterms:publisher': {
    '@id': 'did:web:member.example.org',
  },
  'dcat:theme': 'onehealth',
  'dcterms:spatial': 'ES',
  'dcat:distribution': [
    {
      '@type': 'dcat:Distribution',
      'dcat:accessURL':
        'https://member.example.org/.well-known/did.json',
    },
  ],
  'odrl:hasPolicy': {
    '@type': 'odrl:Set',
  },
} as const;

const DCAT_CATALOG_EXAMPLE = {
  '@context': {
    dcat: 'https://www.w3.org/ns/dcat#',
    dcterms: 'http://purl.org/dc/terms/',
    odrl: 'http://www.w3.org/ns/odrl/2/',
  },
  '@id': 'https://ica.example.org/ica/cds-ES/v1/onehealth/dcat3/catalog',
  '@type': 'dcat:Catalog',
  'dcat:dataset': [DCAT_DATASET_EXAMPLE],
} as const;

const DDO_DATASET_ENTRY_SCHEMA = {
  type: 'object',
  required: ['id', 'type', 'datasetId', 'title', 'participantDid', 'accessUrl'],
  properties: {
    id: { type: 'string' },
    type: { type: 'string', enum: ['OrganizationDataOffering'] },
    datasetId: { type: 'string' },
    title: { type: 'string' },
    participantDid: { type: 'string' },
    accessUrl: { type: 'string' },
    sector: { type: 'string' },
    jurisdiction: { type: 'string' },
  },
} as const;

const DDO_CATALOG_SCHEMA = {
  type: 'object',
  required: ['profile', 'id', 'type', 'catalogUrl', 'generatedAt', 'datasetCount', 'datasetList'],
  properties: {
    profile: { type: 'string', enum: ['urn:ica:ddo:catalog:v1'] },
    id: { type: 'string' },
    type: { type: 'string', enum: ['DataCatalogDDO'] },
    catalogUrl: { type: 'string' },
    generatedAt: { type: 'string' },
    datasetCount: { type: 'integer' },
    datasetList: {
      type: 'array',
      items: DDO_DATASET_ENTRY_SCHEMA,
    },
  },
} as const;

const DDO_CATALOG_REQUEST_SCHEMA = {
  type: 'object',
  properties: {
    filters: {
      type: 'object',
      properties: {
        sector: { type: 'string' },
        jurisdiction: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
} as const;

const DDO_CATALOG_REQUEST_EXAMPLE = {
  filters: {
    sector: 'onehealth',
    jurisdiction: 'ES',
  },
} as const;

const DDO_CATALOG_EXAMPLE = {
  profile: 'urn:ica:ddo:catalog:v1',
  id: 'https://ica.example.org/ica/cds-ES/v1/onehealth/dcat3/catalog/ddo',
  type: 'DataCatalogDDO',
  catalogUrl: 'https://ica.example.org/ica/cds-ES/v1/onehealth/dcat3/catalog',
  generatedAt: '2026-03-09T10:12:45.000Z',
  datasetCount: 1,
  datasetList: [
    {
      id: 'https://ica.example.org/ica/cds-ES/v1/onehealth/dcat3/catalog/ddo/datasets/z3MpnvTtN9h7K4N5XGtrPJxRQJ4mknpXhD2A9N4rb1n3Q',
      type: 'OrganizationDataOffering',
      datasetId: 'z3MpnvTtN9h7K4N5XGtrPJxRQJ4mknpXhD2A9N4rb1n3Q',
      title: 'Clinica Veterinaria Norte dataset',
      participantDid: 'did:web:member.example.org',
      accessUrl: 'https://member.example.org/.well-known/did.json',
      sector: 'onehealth',
      jurisdiction: 'ES',
    },
  ],
} as const;

const ACTIVATE_KEY_SCHEMA = {
  type: 'object',
  required: ['alg', 'privateKeyPem'],
  properties: {
    kid: { type: 'string' },
    alg: { type: 'string', enum: ['ES384', 'ES256K', 'RS256', 'PS256', 'EdDSA'] },
    privateKeyPem: { type: 'string' },
    x5c: { type: 'array', items: { type: 'string' } },
    certificateChainPem: { type: 'array', items: { type: 'string' } },
  },
  anyOf: [
    { required: ['x5c'] },
    { required: ['certificateChainPem'] },
  ],
} as const;

const ACTIVATE_KEY_DATA_ITEM_SCHEMA = {
  type: 'object',
  properties: {
    key: ACTIVATE_KEY_SCHEMA,
    kid: { type: 'string' },
    alg: { type: 'string', enum: ['ES384', 'ES256K', 'RS256', 'PS256', 'EdDSA'] },
    privateKeyPem: { type: 'string' },
    x5c: { type: 'array', items: { type: 'string' } },
    certificateChainPem: { type: 'array', items: { type: 'string' } },
  },
  oneOf: [
    { required: ['key'] },
    {
      required: ['alg', 'privateKeyPem'],
      anyOf: [
        { required: ['x5c'] },
        { required: ['certificateChainPem'] },
      ],
    },
  ],
} as const;

const CONTROLLER_FHIR_SIGNATURE_SCHEMA = {
  type: 'object',
  required: ['who', 'data'],
  properties: {
    type: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: true,
      },
      description: 'FHIR Signature.type coding (optional).',
    },
    when: { type: 'string', description: 'FHIR Signature.when timestamp (optional).' },
    who: {
      type: 'object',
      required: ['reference'],
      properties: {
        reference: {
          type: 'string',
          description: 'FHIR Reference to controller verification method, e.g. did:web:...#kid.',
        },
      },
      additionalProperties: true,
      description: 'FHIR Signature.who reference.',
    },
    sigFormat: { type: 'string', description: 'e.g., application/jose' },
    targetFormat: { type: 'string' },
    data: {
      type: 'string',
      description:
        'Detached compact JWS (`<protected>..<signature>`) or base64-encoded detached compact JWS. Signature is verified over canonical request body excluding signature and, for body.resourceType="Bundle", excluding root id/meta.',
    },
    kid: { type: 'string', description: 'Optional controller kid hint.' },
    alg: { type: 'string', enum: ['ES384', 'ES256K', 'RS256', 'PS256', 'EdDSA'] },
  },
  additionalProperties: true,
} as const;

const ACTIVATE_REQUEST_BODY_SCHEMA = {
  type: 'object',
  description:
    'Provide keys in body.data[] (even for a single key). Use body.signature (FHIR Signature) for controller authorization.',
  required: ['data', 'signature'],
  properties: {
    data: {
      type: 'array',
      minItems: 1,
      items: ACTIVATE_KEY_DATA_ITEM_SCHEMA,
    },
    signature: CONTROLLER_FHIR_SIGNATURE_SCHEMA,
  },
} as const;

const ACTIVATE_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: ACTIVATE_REQUEST_BODY_SCHEMA,
  },
} as const;

const ROTATE_REQUEST_BODY_SCHEMA = {
  type: 'object',
  description: 'Controller-signed authorization for key rotation using body.signature (FHIR Signature).',
  required: ['signature'],
  properties: {
    signature: CONTROLLER_FHIR_SIGNATURE_SCHEMA,
  },
  additionalProperties: true,
} as const;

const ROTATE_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: ROTATE_REQUEST_BODY_SCHEMA,
  },
  additionalProperties: true,
} as const;

const OIDC4IDA_CHECK_DETAILS_ITEM_SCHEMA = {
  type: 'object',
  required: ['check_method'],
  properties: {
    check_method: { type: 'string' },
    organization: { type: 'string' },
    txn: { type: 'string' },
    time: { type: 'string' },
  },
  additionalProperties: true,
} as const;

const OIDC4IDA_ATTACHMENT_DIGEST_SCHEMA = {
  type: 'object',
  required: ['alg', 'value'],
  properties: {
    alg: { type: 'string' },
    value: { type: 'string' },
  },
  additionalProperties: true,
} as const;

const OIDC4IDA_EXTERNAL_ATTACHMENT_SCHEMA = {
  type: 'object',
  required: ['digest'],
  properties: {
    digest: OIDC4IDA_ATTACHMENT_DIGEST_SCHEMA,
    url: { type: 'string' },
  },
  additionalProperties: true,
} as const;

const OIDC4IDA_EVIDENCE_DOCUMENT_SCHEMA = {
  type: 'object',
  required: ['type', 'method', 'verifier'],
  properties: {
    type: { type: 'string', enum: ['document'] },
    method: { type: 'string' },
    time: { type: 'string' },
    verifier: {
      type: 'object',
      required: ['organization'],
      properties: {
        organization: { type: 'string' },
        txn: { type: 'string' },
      },
      additionalProperties: true,
    },
    check_details: {
      type: 'array',
      items: OIDC4IDA_CHECK_DETAILS_ITEM_SCHEMA,
    },
    attachments: OIDC4IDA_EXTERNAL_ATTACHMENT_SCHEMA,
    document_details: { type: 'object', additionalProperties: true },
  },
  additionalProperties: true,
} as const;

const OIDC4IDA_EVIDENCE_ELECTRONIC_RECORD_SCHEMA = {
  type: 'object',
  required: ['type'],
  properties: {
    type: { type: 'string', enum: ['electronic_record'] },
    time: { type: 'string' },
    verifier: {
      type: 'object',
      properties: {
        organization: { type: 'string' },
        txn: { type: 'string' },
      },
      additionalProperties: true,
    },
    check_details: {
      type: 'array',
      items: OIDC4IDA_CHECK_DETAILS_ITEM_SCHEMA,
    },
    record: { type: 'object', additionalProperties: true },
    attachments: {
      type: 'array',
      items: OIDC4IDA_EXTERNAL_ATTACHMENT_SCHEMA,
    },
  },
  anyOf: [
    { required: ['record'] },
    { required: ['attachments'] },
  ],
  additionalProperties: true,
} as const;

const OIDC4IDA_EVIDENCE_ELECTRONIC_SIGNATURE_SCHEMA = {
  type: 'object',
  required: ['type', 'signature_type', 'issuer', 'serial_number', 'created_at'],
  properties: {
    type: { type: 'string', enum: ['electronic_signature'] },
    signature_type: { type: 'string' },
    issuer: { type: 'string' },
    serial_number: { type: 'string' },
    created_at: { type: 'string' },
    attachments: {
      type: 'array',
      items: {
        type: 'object',
        required: ['content_type', 'content'],
        properties: {
          content_type: { type: 'string' },
          content: { type: 'string' },
        },
        additionalProperties: true,
      },
    },
  },
  additionalProperties: true,
} as const;

const OIDC4IDA_EVIDENCE_SCHEMA = {
  description: 'OIDC4IDA evidence object.',
  oneOf: [
    OIDC4IDA_EVIDENCE_DOCUMENT_SCHEMA,
    OIDC4IDA_EVIDENCE_ELECTRONIC_RECORD_SCHEMA,
    OIDC4IDA_EVIDENCE_ELECTRONIC_SIGNATURE_SCHEMA,
  ],
} as const;

const OIDC4IDA_VERIFIED_CLAIMS_RESOURCE_SCHEMA = {
  type: 'object',
  required: ['verified_claims'],
  properties: {
    verified_claims: {
      type: 'object',
      required: ['verification'],
      properties: {
        verification: {
          type: 'object',
          required: ['evidence'],
          properties: {
            trust_framework: {
              oneOf: [
                { type: 'string' },
                { type: 'null' },
              ],
            },
            time: {
              oneOf: [
                { type: 'string' },
                { type: 'null' },
              ],
            },
            evidence: {
              type: 'array',
              minItems: 1,
              items: OIDC4IDA_EVIDENCE_SCHEMA,
            },
          },
          additionalProperties: true,
        },
        claims: {
          type: 'object',
          additionalProperties: true,
          description: 'Additional claims proven by evidence (e.g. healthcare/certification registry identifiers).',
        },
      },
      additionalProperties: true,
    },
  },
  additionalProperties: true,
} as const;

const ADD_EVIDENCE_RESOURCE_SCHEMA = {
  description: 'Either plain OIDC4IDA evidence object or resource wrapper with verified_claims.',
  oneOf: [
    OIDC4IDA_EVIDENCE_SCHEMA,
    OIDC4IDA_VERIFIED_CLAIMS_RESOURCE_SCHEMA,
  ],
} as const;

const ADD_EVIDENCE_DATA_ITEM_SCHEMA = {
  type: 'object',
  properties: {
    issuedCredentialRecordId: { type: 'string' },
    operatorDid: { type: 'string' },
    evidence: OIDC4IDA_EVIDENCE_SCHEMA,
    resource: ADD_EVIDENCE_RESOURCE_SCHEMA,
  },
  oneOf: [
    { required: ['evidence'] },
    { required: ['resource'] },
  ],
  additionalProperties: false,
} as const;

const ADD_EVIDENCE_REQUEST_BODY_SCHEMA = {
  type: 'object',
  description:
    'Canonical form: body.data[] (batch, one or many). Also supports DIDComm attachments with vc+jwt payload for issuer-list based evidence ingestion.',
  properties: {
    issuedCredentialRecordId: { type: 'string' },
    operatorDid: { type: 'string' },
    evidence: ADD_EVIDENCE_RESOURCE_SCHEMA,
    data: {
      type: 'array',
      minItems: 1,
      items: ADD_EVIDENCE_DATA_ITEM_SCHEMA,
    },
  },
} as const;

const VC_JWT_DIDCOMM_ATTACHMENT_SCHEMA = {
  type: 'object',
  required: ['id', 'media_type', 'data'],
  properties: {
    id: { type: 'string' },
    format: { type: 'string', enum: ['vc+jwt'] },
    media_type: { type: 'string', enum: ['application/vc+jwt'] },
    filename: { type: 'string' },
    data: {
      type: 'object',
      properties: {
        json: {
          type: 'object',
          properties: {
            format: { type: 'string', enum: ['vc+jwt'] },
            jwt: { type: 'string' },
          },
          required: ['jwt'],
        },
        jwt: { type: 'string' },
        base64: { type: 'string' },
      },
      anyOf: [
        { required: ['json'] },
        { required: ['jwt'] },
        { required: ['base64'] },
      ],
    },
  },
} as const;

const ADD_EVIDENCE_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: ADD_EVIDENCE_REQUEST_BODY_SCHEMA,
    attachments: {
      type: 'array',
      items: VC_JWT_DIDCOMM_ATTACHMENT_SCHEMA,
    },
  },
} as const;

const ODRL_DELEGATION_POLICY_RESOURCE_SCHEMA = {
  type: 'object',
  description:
    'ODRL delegation policy (Gaia-X OVC style constraints) used by ICA controller to delegate evidence operations.',
  required: ['@context', 'permission'],
  properties: {
    '@context': {
      type: 'array',
      minItems: 1,
      items: {
        oneOf: [
          { type: 'string' },
          { type: 'object', additionalProperties: true },
        ],
      },
    },
    profile: { type: 'string' },
    uid: { type: 'string' },
    id: { type: 'string' },
    type: {
      oneOf: [
        { type: 'string' },
        { type: 'array', items: { type: 'string' } },
      ],
    },
    assigner: {
      oneOf: [
        { type: 'string' },
        {
          type: 'object',
          properties: {
            '@id': { type: 'string' },
            id: { type: 'string' },
          },
          additionalProperties: true,
        },
      ],
    },
    assignee: {
      oneOf: [
        { type: 'string' },
        {
          type: 'object',
          properties: {
            '@id': { type: 'string' },
            id: { type: 'string' },
          },
          additionalProperties: true,
        },
      ],
    },
    permission: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        required: ['action'],
        properties: {
          target: { type: 'string' },
          action: {
            oneOf: [
              { type: 'string' },
              {
                type: 'object',
                properties: {
                  '@id': { type: 'string' },
                },
                additionalProperties: true,
              },
              { type: 'array', items: { type: 'object', additionalProperties: true } },
            ],
          },
          assigner: {
            oneOf: [
              { type: 'string' },
              { type: 'object', additionalProperties: true },
            ],
          },
          assignee: {
            oneOf: [
              { type: 'string' },
              { type: 'object', additionalProperties: true },
            ],
          },
          constraint: {
            type: 'array',
            items: { type: 'object', additionalProperties: true },
          },
          'ovc:constraint': {
            type: 'array',
            items: { type: 'object', additionalProperties: true },
          },
        },
        additionalProperties: true,
      },
    },
  },
  additionalProperties: true,
} as const;

const POLICY_UPSERT_DATA_ITEM_SCHEMA = {
  type: 'object',
  required: ['resource'],
  properties: {
    resource: ODRL_DELEGATION_POLICY_RESOURCE_SCHEMA,
  },
  additionalProperties: false,
} as const;

const POLICY_UPSERT_REQUEST_BODY_SCHEMA = {
  type: 'object',
  description: 'Canonical form: body.data[] (batch, one or many).',
  properties: {
    data: {
      type: 'array',
      minItems: 1,
      items: POLICY_UPSERT_DATA_ITEM_SCHEMA,
    },
  },
  required: ['data'],
} as const;

const POLICY_UPSERT_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: POLICY_UPSERT_REQUEST_BODY_SCHEMA,
  },
} as const;

const SCHEMA_ORG_CREDENTIAL_SCHEMA = {
  type: 'object',
  required: ['credentialSubject'],
  properties: {
    id: { type: 'string' },
    type: {
      oneOf: [
        { type: 'string' },
        { type: 'array', items: { type: 'string' } },
      ],
    },
    issuer: {
      oneOf: [
        { type: 'string' },
        {
          type: 'object',
          properties: {
            id: { type: 'string' },
          },
          additionalProperties: true,
        },
      ],
    },
    credentialSubject: {
      description: 'schema.org subject. Must include @type Person or Organization.',
      oneOf: [
        {
          type: 'object',
          required: ['@type'],
          properties: {
            id: { type: 'string' },
            '@type': {
              oneOf: [
                {
                  type: 'string',
                  enum: [
                    'Person',
                    'Organization',
                    'https://schema.org/Person',
                    'https://schema.org/Organization',
                    'schema:Person',
                    'schema:Organization',
                  ],
                },
                {
                  type: 'array',
                  items: {
                    type: 'string',
                    enum: [
                      'Person',
                      'Organization',
                      'https://schema.org/Person',
                      'https://schema.org/Organization',
                      'schema:Person',
                      'schema:Organization',
                    ],
                  },
                },
              ],
            },
            name: { type: 'string' },
            legalName: { type: 'string' },
            taxID: { type: 'string' },
            identifier: { type: 'string' },
            memberOf: { type: 'object', additionalProperties: true },
            affiliation: { type: 'object', additionalProperties: true },
          },
          additionalProperties: true,
        },
        {
          type: 'array',
          minItems: 1,
          items: {
            type: 'object',
            required: ['@type'],
            properties: {
              id: { type: 'string' },
              '@type': {
                oneOf: [
                  {
                    type: 'string',
                    enum: [
                      'Person',
                      'Organization',
                      'https://schema.org/Person',
                      'https://schema.org/Organization',
                      'schema:Person',
                      'schema:Organization',
                    ],
                  },
                  {
                    type: 'array',
                    items: {
                      type: 'string',
                      enum: [
                        'Person',
                        'Organization',
                        'https://schema.org/Person',
                        'https://schema.org/Organization',
                        'schema:Person',
                        'schema:Organization',
                      ],
                    },
                  },
                ],
              },
              name: { type: 'string' },
              legalName: { type: 'string' },
              taxID: { type: 'string' },
              identifier: { type: 'string' },
              memberOf: { type: 'object', additionalProperties: true },
              affiliation: { type: 'object', additionalProperties: true },
            },
            additionalProperties: true,
          },
        },
      ],
    },
  },
  additionalProperties: true,
} as const;

const ISSUE_CREDENTIAL_DATA_ITEM_SCHEMA = {
  type: 'object',
  properties: {
    resource: SCHEMA_ORG_CREDENTIAL_SCHEMA,
    credential: SCHEMA_ORG_CREDENTIAL_SCHEMA,
    evidence: {
      type: 'array',
      items: { type: 'object', additionalProperties: true },
    },
  },
  oneOf: [
    { required: ['resource'] },
    { required: ['credential'] },
  ],
  additionalProperties: true,
} as const;

const ISSUE_CREDENTIAL_REQUEST_BODY_SCHEMA = {
  type: 'object',
  required: ['data'],
  properties: {
    data: {
      type: 'array',
      minItems: 1,
      items: ISSUE_CREDENTIAL_DATA_ITEM_SCHEMA,
    },
  },
} as const;

const CREDENTIAL_LOOKUP_DATA_ITEM_SCHEMA = {
  type: 'object',
  properties: {
    issuedCredentialRecordId: { type: 'string' },
    credentialId: { type: 'string' },
    subjectId: { type: 'string' },
    credentialStatusId: { type: 'string' },
    resource: {
      type: 'object',
      additionalProperties: true,
      description:
        'Optional lookup container. Resolver can use resource.id, resource.credentialStatus.id, and resource.credentialSubject.id.',
    },
  },
  anyOf: [
    { required: ['issuedCredentialRecordId'] },
    { required: ['credentialId'] },
    { required: ['subjectId'] },
    { required: ['credentialStatusId'] },
    { required: ['resource'] },
  ],
  additionalProperties: true,
} as const;

const ISSUE_CREDENTIAL_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: ISSUE_CREDENTIAL_REQUEST_BODY_SCHEMA,
  },
} as const;

const CREDENTIAL_STATUS_REQUEST_BODY_SCHEMA = {
  type: 'object',
  required: ['data'],
  properties: {
    data: {
      type: 'array',
      minItems: 1,
      items: CREDENTIAL_LOOKUP_DATA_ITEM_SCHEMA,
    },
  },
} as const;

const CREDENTIAL_STATUS_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: CREDENTIAL_STATUS_REQUEST_BODY_SCHEMA,
  },
} as const;

const CREDENTIAL_REVOKE_REQUEST_BODY_SCHEMA = {
  type: 'object',
  required: ['data'],
  properties: {
    data: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        properties: {
          issuedCredentialRecordId: { type: 'string' },
          credentialId: { type: 'string' },
          subjectId: { type: 'string' },
          credentialStatusId: { type: 'string' },
          reason: { type: 'string' },
          revokedBy: { type: 'string' },
          resource: { type: 'object', additionalProperties: true },
        },
        anyOf: [
          { required: ['issuedCredentialRecordId'] },
          { required: ['credentialId'] },
          { required: ['subjectId'] },
          { required: ['credentialStatusId'] },
          { required: ['resource'] },
        ],
        additionalProperties: true,
      },
    },
  },
} as const;

const CREDENTIAL_REVOKE_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: CREDENTIAL_REVOKE_REQUEST_BODY_SCHEMA,
  },
} as const;

const CREDENTIAL_SEARCH_REQUEST_BODY_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string', description: 'Generic identifier filter (mapped by credentialType hint).' },
    text: { type: 'string', description: 'Free-text search (e.g., legal name/address fragment).' },
    email: { type: 'string' },
    taxId: { type: 'string' },
    taxIdHash: {
      type: 'string',
      description: 'multibase58(multihash(SHA3-256(taxId)))',
    },
    legalName: { type: 'string' },
    subjectId: { type: 'string' },
    issuerId: { type: 'string' },
    credentialId: { type: 'string' },
    thid: { type: 'string' },
    jti: { type: 'string' },
  },
  anyOf: [
    { required: ['id'] },
    { required: ['text'] },
    { required: ['email'] },
    { required: ['taxId'] },
    { required: ['taxIdHash'] },
    { required: ['legalName'] },
    { required: ['subjectId'] },
    { required: ['issuerId'] },
    { required: ['credentialId'] },
  ],
} as const;

const SPACES_TARGET_SCHEMA = {
  type: 'object',
  description:
    'Spaces target descriptor. Use "@type" (JSON-LD) or "resourceType" (plain JSON). '
    + 'Field "type" is not supported for target entries; this does not affect DIDComm/FHIR Bundle body.type.',
  properties: {
    '@type': {
      type: 'string',
      example: 'RuntimePlatform',
      description: 'JSON-LD type (preferred when the payload is JSON-LD). Allowed: RuntimePlatform or SoftwareApplication.',
    },
    resourceType: {
      type: 'string',
      example: 'RuntimePlatform',
      description: 'Non JSON-LD type alias. Allowed: RuntimePlatform or SoftwareApplication.',
    },
    name: { type: 'string', example: 'Pontus-X' },
    did: { type: 'string', example: 'did:web:pontusx.example.org' },
    id: { type: 'string', example: 'did:web:pontusx.example.org', description: 'Alias of did.' },
    identifier: { type: 'string', example: 'did:web:pontusx.example.org', description: 'Alias of did (RuntimePlatform style).' },
    endpointUrl: { type: 'string', example: 'https://adapter.example.org/dummy-sync' },
    url: { type: 'string', example: 'https://adapter.example.org/dummy-sync', description: 'Alias of endpointUrl (RuntimePlatform style).' },
    apiKey: { type: 'string', writeOnly: true, description: 'Write-only inline API key (never returned by _list/_replace responses).' },
    license: { type: 'string', writeOnly: true, description: 'Alias of apiKey (RuntimePlatform style). Write-only.' },
    resource: { type: 'object', additionalProperties: true },
  },
  anyOf: [
    { required: ['did'] },
    { required: ['id'] },
    { required: ['identifier'] },
  ],
  additionalProperties: true,
} as const;

const SPACES_LIST_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: { type: 'object', additionalProperties: true },
  },
} as const;

const SPACES_REPLACE_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: {
      type: 'object',
      required: ['data'],
      properties: {
        data: {
          type: 'array',
          minItems: 1,
          items: SPACES_TARGET_SCHEMA,
        },
      },
    },
  },
} as const;

const VERIFY_RESPONSE_SUCCESS_EXAMPLE = {
  jti: 'urn:uuid:verify-resp-001',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'verify-terms-001',
  type: 'application/bundle-api+json',
  attachments: [
    {
      id: 'vc-jwt-1',
      format: 'vc+jwt',
      media_type: 'application/vc+jwt',
      filename: 'Organization-verification-v1.0-1.jwt',
      data: {
        json: {
          format: 'vc+jwt',
          jwt: '<vc-jwt-organization>',
        },
      },
    },
    {
      id: 'vc-jwt-2',
      format: 'vc+jwt',
      media_type: 'application/vc+jwt',
      filename: 'LegalRepresentative-verification-v1.0-2.jwt',
      data: {
        json: {
          format: 'vc+jwt',
          jwt: '<vc-jwt-legal-representative>',
        },
      },
    },
  ],
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 2,
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'information',
          code: 'informational',
          diagnostics: 'Verification completed.',
        },
      ],
    },
    data: [
      {
        type: 'Organization-verification-v1.0',
        response: {
          status: '200',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'information',
                code: 'informational',
                diagnostics: 'Organization credential extracted from verified document.',
              },
            ],
          },
        },
        resource: {
          id: 'urn:uuid:org-vc-001',
          '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
          type: ['VerifiableCredential', 'OrganizationCredential'],
          issuer: 'did:web:localhost%3A3310',
          validFrom: '2026-03-12T21:12:26.646Z',
          meta: {
            versionId: 'zPdfVersionHash001',
          },
          credentialSubject: {
            id: 'did:web:globaldatacare.es:onehealth:organization:taxid:VATES-B00000000',
            '@type': 'Organization',
            legalName: 'Example Data Provider SL',
            taxID: 'VATES-B00000000',
            sameAs: 'did:web:provider.example.org',
            url: 'provider.example.org',
            alternateName: 'example-provider',
            additionalType:
              'sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider',
            address: {
              '@type': 'PostalAddress',
              addressCountry: 'ES',
            },
          },
          evidence: [
            {
              type: 'electronic_signature',
              signature_type: 'pades',
              issuer: 'C=ES\nO=FNMT-RCM\nOU=CERES\nCN=AC Representación',
              serial_number: '20A438B97CF06452688B9E2C7967662A',
              created_at: '2026-03-12T21:12:26.646Z',
              attachments: [
                {
                  content_type: 'application/json',
                  content:
                    'data:application/json;base64,eyJwcm9maWxlIjoib2lkYzRpZGEtZXZpZGVuY2UtdjEiLCJ2ZXJpZmljYXRpb25SZXN1bHQiOiJ2YWxpZCIsIi4uLiI6InRydW5jYXRlZCJ9',
                },
              ],
            },
            {
              type: 'document',
              method: 'eid',
              time: '2026-03-12T21:12:26.646Z',
              verifier: {
                organization: 'did:web:localhost%3A3310',
              },
              check_details: [
                {
                  check_method: 'vdig',
                  organization: 'did:web:localhost%3A3310',
                  time: '2026-03-12T21:12:26.646Z',
                },
                {
                  check_method: 'vcrypt',
                  organization: 'did:web:localhost%3A3310',
                  time: '2026-03-12T21:12:26.646Z',
                },
              ],
              attachments: {
                digest: {
                  alg: 'sha3-384',
                  value: 'aafUF1Ne7Zrmg/y1f6jprx4f/n0OiOo9i4j5AXXN4ZotOFsahUHYdr+nZOnESHqH',
                },
                url: 'urn:uuid:audit-object-001',
              },
              document_details: {
                type: 'terms-and-conditions',
                document_number: 'contract',
                serial_number: '20A438B97CF06452688B9E2C7967662A',
                issuer: {
                  id: 'did:web:localhost%3A3310',
                  type: 'TrustServiceProvider',
                  country_code: 'ES',
                  jurisdiction: 'ES',
                },
              },
            },
          ],
          proof: {
            type: 'JsonWebSignature2020',
            created: '2026-03-12T21:12:57.534Z',
            proofPurpose: 'assertionMethod',
            verificationMethod: 'did:web:localhost%3A3310#verification-key-001',
            jws: '<detached-jws-organization-truncated>',
          },
        },
      },
      {
        type: 'LegalRepresentative-verification-v1.0',
        response: {
          status: '200',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'information',
                code: 'informational',
                diagnostics: 'Legal representative credential extracted from verified document.',
              },
            ],
          },
        },
        resource: {
          id: 'urn:uuid:person-vc-001',
          '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
          type: ['VerifiableCredential', 'PersonCredential', 'LegalRepresentativeCredential'],
          issuer: 'did:web:localhost%3A3310',
          validFrom: '2026-03-12T21:12:26.646Z',
          meta: {
            versionId: 'zPdfVersionHash001',
          },
          credentialSubject: {
            id: 'urn:person:identifier:IDCES-99999999R',
            '@type': 'Person',
            name: 'Alex Example',
            hasOccupation: {
              '@type': 'Occupation',
              name: 'LegalRepresentative',
              identifier: 'urn:ilo:ilostat:isco-08:1120',
            },
            memberOf: {
              '@type': 'Organization',
              legalName: 'Example Data Provider SL',
              taxID: 'VATES-B00000000',
            },
            givenName: 'Alex',
            familyName: 'Example',
            identifier: 'IDCES-99999999R',
            nationality: 'ES',
            sameAs: 'urn:multibase:zControllerHash',
            alternateName: 'controller-es384-001',
            additionalType: 'ES384',
          },
          evidence: [
            {
              type: 'electronic_signature',
              signature_type: 'pades',
              issuer: 'C=ES\nO=FNMT-RCM\nOU=CERES\nCN=AC Representación',
              serial_number: '20A438B97CF06452688B9E2C7967662A',
              created_at: '2026-03-12T21:12:26.646Z',
              attachments: [
                {
                  content_type: 'application/json',
                  content:
                    'data:application/json;base64,eyJwcm9maWxlIjoib2lkYzRpZGEtZXZpZGVuY2UtdjEiLCJ2ZXJpZmljYXRpb25SZXN1bHQiOiJ2YWxpZCIsIi4uLiI6InRydW5jYXRlZCJ9',
                },
              ],
            },
            {
              type: 'document',
              method: 'eid',
              time: '2026-03-12T21:12:26.646Z',
              verifier: {
                organization: 'did:web:localhost%3A3310',
              },
              check_details: [
                {
                  check_method: 'vdig',
                  organization: 'did:web:localhost%3A3310',
                  time: '2026-03-12T21:12:26.646Z',
                },
                {
                  check_method: 'vcrypt',
                  organization: 'did:web:localhost%3A3310',
                  time: '2026-03-12T21:12:26.646Z',
                },
              ],
              attachments: {
                digest: {
                  alg: 'sha3-384',
                  value: 'aafUF1Ne7Zrmg/y1f6jprx4f/n0OiOo9i4j5AXXN4ZotOFsahUHYdr+nZOnESHqH',
                },
                url: 'urn:uuid:audit-object-001',
              },
              document_details: {
                type: 'terms-and-conditions',
                document_number: 'contract',
                serial_number: '20A438B97CF06452688B9E2C7967662A',
                issuer: {
                  id: 'did:web:localhost%3A3310',
                  type: 'TrustServiceProvider',
                  country_code: 'ES',
                  jurisdiction: 'ES',
                },
              },
            },
          ],
          proof: {
            type: 'JsonWebSignature2020',
            created: '2026-03-12T21:12:57.535Z',
            proofPurpose: 'assertionMethod',
            verificationMethod: 'did:web:localhost%3A3310#verification-key-001',
            jws: '<detached-jws-person-truncated>',
          },
        },
      },
    ],
  },
} as const;

const VERIFY_RESPONSE_FAILED_EXAMPLE = {
  jti: 'urn:uuid:verify-resp-002',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'verify-terms-002',
  type: 'application/bundle-api+json',
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 1,
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'error',
          code: 'exception',
          diagnostics: 'Revocation check did not pass (status=unknown).',
        },
      ],
    },
    data: [
      {
        type: 'TermsVerification-v1.0',
        resource: {
          id: 'urn:uuid:verify-fail-001',
          type: 'terms-verification-v1.0',
          thid: 'verify-terms-002',
          tenantId: 'ica',
          jurisdiction: 'ES',
          sector: 'animal-care',
          section: 'terms',
          format: 'pdf',
          resourceType: '202603051133',
          status: 'failed',
          createdAt: '2026-03-06T12:01:00.000Z',
          updatedAt: '2026-03-06T12:01:03.000Z',
          audit: {
            txId: '',
            txTime: '',
          },
          content: [
            {
              error: 'Revocation check did not pass (status=unknown).',
            },
          ],
        },
        response: {
          status: '500',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'error',
                code: 'exception',
                diagnostics: 'Revocation check did not pass (status=unknown).',
              },
            ],
          },
        },
      },
    ],
  },
} as const;

const ACTIVATE_RESPONSE_SUCCESS_EXAMPLE = {
  jti: 'urn:uuid:activate-resp-001',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'activate-signing-001',
  type: 'application/bundle-api+json',
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 1,
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'information',
          code: 'informational',
          diagnostics: 'Signing key activation completed.',
        },
      ],
    },
    data: [
      {
        type: 'SigningKeyActivation-v1.0',
        response: {
          status: '200',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'information',
                code: 'informational',
                diagnostics: 'Signing key activation completed.',
              },
            ],
          },
        },
        resource: {
          id: 'urn:uuid:activate-resource-001',
          type: 'signing-key-activation-v1.0',
          thid: 'activate-signing-001',
          tenantId: 'ica',
          jurisdiction: 'ES',
          sector: 'animal-care',
          status: 'activated',
          createdAt: '2026-03-06T12:02:00.000Z',
          updatedAt: '2026-03-06T12:02:03.000Z',
          issuerDid: 'did:web:localhost%3A3310',
          content: [
            {
              kid: 'ica-es384-20260305',
              alg: 'ES384',
              activatedAt: '2026-03-06T12:02:03.000Z',
              assertionMethod: 'did:web:localhost%3A3310#ica-es384-20260305',
              chainLength: 1,
            },
          ],
        },
      },
    ],
  },
} as const;

const ADD_EVIDENCE_RESPONSE_SUCCESS_EXAMPLE = {
  jti: 'urn:uuid:add-evidence-resp-001',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'evidence-add-001',
  type: 'application/bundle-api+json',
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 1,
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'information',
          code: 'informational',
          diagnostics: 'Evidence record(s) stored: 2.',
        },
      ],
    },
    data: [
      {
        type: 'NetworkEvidenceAdd-v1.0',
        response: {
          status: '200',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'information',
                code: 'informational',
                diagnostics: 'Evidence record(s) stored: 2.',
              },
            ],
          },
        },
        resource: {
          id: 'urn:uuid:add-evidence-resource-001',
          type: 'network-evidence-add-v1.0',
          thid: 'evidence-add-001',
          tenantId: 'ica',
          jurisdiction: 'ES',
          sector: 'animal-care',
          evidenceType: 'official-registry',
          status: 'stored',
          createdAt: '2026-03-06T12:03:00.000Z',
          updatedAt: '2026-03-06T12:03:02.000Z',
          content: [
            {
              evidenceRecordId: 'urn:uuid:evidence-record-001',
              evidenceType: 'official-registry',
              issuedCredentialRecordId: 'urn:uuid:issued-record-001',
              linkedToCredential: true,
              storedAt: '2026-03-06T12:03:02.000Z',
              operatorDid: 'did:web:localhost%3A3310#employee-01',
            },
            {
              evidenceRecordId: 'urn:uuid:evidence-record-002',
              evidenceType: 'official-registry',
              issuedCredentialRecordId: 'urn:uuid:issued-record-001',
              linkedToCredential: true,
              storedAt: '2026-03-06T12:03:02.000Z',
              operatorDid: 'did:web:localhost%3A3310#employee-02',
            },
          ],
        },
      },
    ],
  },
} as const;

const DELEGATION_POLICY_UPSERT_RESPONSE_SUCCESS_EXAMPLE = {
  jti: 'urn:uuid:delegation-policy-upsert-resp-001',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'delegation-policy-upsert-001',
  type: 'application/bundle-api+json',
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 1,
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'information',
          code: 'informational',
          diagnostics: 'Delegation policy record(s) upserted: 1.',
        },
      ],
    },
    data: [
      {
        type: 'DelegationPolicyUpsert-v1.0',
        response: {
          status: '200',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'information',
                code: 'informational',
                diagnostics: 'Delegation policy record(s) upserted: 1.',
              },
            ],
          },
        },
        resource: {
          id: 'urn:uuid:delegation-policy-upsert-resource-001',
          type: 'delegation-policy-upsert-v1.0',
          thid: 'delegation-policy-upsert-001',
          tenantId: 'ica',
          jurisdiction: 'ES',
          sector: 'animal-care',
          policyType: 'delegations',
          status: 'upserted',
          createdAt: '2026-03-06T12:03:00.000Z',
          updatedAt: '2026-03-06T12:03:02.000Z',
          content: [
            {
              policyId: 'urn:policy:ica:es:delegate:1120:zEmailHash:official-registry:v1',
              assigneeDid: 'did:web:ica.example.org:ica:cds-ES:v1:onehealth:delegate:1120:zEmailHash',
              roleIdentifier: 'urn:ilo:ilostat:isco-08:1120',
              upsertedAt: '2026-03-06T12:03:02.000Z',
            },
          ],
        },
      },
    ],
  },
} as const;

const ISSUE_CREDENTIAL_RESPONSE_SUCCESS_EXAMPLE = {
  jti: 'urn:uuid:issue-resp-001',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'credential-issue-001',
  type: 'application/bundle-api+json',
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 1,
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'information',
          code: 'informational',
          diagnostics: 'Credential record(s) stored: 1.',
        },
      ],
    },
    data: [
      {
        type: 'NetworkCredentialIssue-v1.0',
        response: {
          status: '200',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'information',
                code: 'informational',
                diagnostics: 'Credential record(s) stored: 1.',
              },
            ],
          },
        },
        resource: {
          id: 'urn:uuid:issue-resource-001',
          type: 'network-credential-issue-v1.0',
          thid: 'credential-issue-001',
          tenantId: 'ica',
          jurisdiction: 'ES',
          sector: 'animal-care',
          credentialType: 'member-onboarding',
          status: 'stored',
          createdAt: '2026-03-06T12:04:00.000Z',
          updatedAt: '2026-03-06T12:04:02.000Z',
          content: [
            {
              issuedCredentialRecordId: 'urn:uuid:issued-record-001',
              credentialId: 'urn:uuid:vc-member-001',
              credentialType: 'member-onboarding',
              evidenceRecordIds: ['urn:uuid:evidence-record-001'],
              storedAt: '2026-03-06T12:04:02.000Z',
            },
          ],
        },
      },
    ],
  },
} as const;

const CREDENTIAL_STATUS_RESPONSE_SUCCESS_EXAMPLE = {
  jti: 'urn:uuid:status-resp-001',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'credential-status-001',
  type: 'application/bundle-api+json',
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 1,
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'information',
          code: 'informational',
          diagnostics: 'Credential status resolved for 1 item(s).',
        },
      ],
    },
    data: [
      {
        type: 'NetworkCredentialStatus-v1.0',
        response: {
          status: '200',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'information',
                code: 'informational',
                diagnostics: 'Credential status resolved for 1 item(s).',
              },
            ],
          },
        },
        resource: {
          id: 'urn:uuid:status-resource-001',
          type: 'network-credential-status-v1.0',
          thid: 'credential-status-001',
          tenantId: 'ica',
          jurisdiction: 'ES',
          sector: 'animal-care',
          credentialType: 'member-onboarding',
          status: 'resolved',
          createdAt: '2026-03-06T12:05:00.000Z',
          updatedAt: '2026-03-06T12:05:02.000Z',
          content: [
            {
              status: 'good',
              checkedAt: '2026-03-06T12:05:02.000Z',
              issuedCredentialRecordId: 'urn:uuid:issued-record-001',
              credentialId: 'urn:uuid:vc-member-001',
            },
          ],
        },
      },
    ],
  },
} as const;

const CREDENTIAL_REVOKE_RESPONSE_SUCCESS_EXAMPLE = {
  jti: 'urn:uuid:revoke-resp-001',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'credential-revoke-001',
  type: 'application/bundle-api+json',
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 1,
    issues: {
      resourceType: 'OperationOutcome',
      issue: [
        {
          severity: 'information',
          code: 'informational',
          diagnostics: 'Credential status set to revoked for 1 item(s).',
        },
      ],
    },
    data: [
      {
        type: 'NetworkCredentialRevoke-v1.0',
        response: {
          status: '200',
          outcome: {
            resourceType: 'OperationOutcome',
            issue: [
              {
                severity: 'information',
                code: 'informational',
                diagnostics: 'Credential status set to revoked for 1 item(s).',
              },
            ],
          },
        },
        resource: {
          id: 'urn:uuid:revoke-resource-001',
          type: 'network-credential-revoke-v1.0',
          thid: 'credential-revoke-001',
          tenantId: 'ica',
          jurisdiction: 'ES',
          sector: 'animal-care',
          credentialType: 'member-onboarding',
          status: 'revoked',
          createdAt: '2026-03-06T12:06:00.000Z',
          updatedAt: '2026-03-06T12:06:02.000Z',
          content: [
            {
              status: 'revoked',
              revokedAt: '2026-03-06T12:06:02.000Z',
              issuedCredentialRecordId: 'urn:uuid:issued-record-001',
              credentialId: 'urn:uuid:vc-member-001',
              subjectId: 'mailto:member@example.org',
              reason: 'membership-terminated',
              revokedBy: 'did:web:localhost%3A3310#employee-02',
            },
          ],
        },
      },
    ],
  },
} as const;

function resolveOpenApiInfoVersion(): string {
  const fromEnv = (process.env.npm_package_version || '').trim();
  if (fromEnv) return fromEnv;
  try {
    const raw = readFileSync(new URL('../../package.json', import.meta.url), 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const fromPackage = typeof parsed.version === 'string' ? parsed.version.trim() : '';
    if (fromPackage) return fromPackage;
  } catch {
    // Fallback used when package metadata cannot be resolved.
  }
  return '0.0.0';
}

function resolveOpenApiSectorExample(
  supportedSectorIds: readonly string[],
  wildcardEnabled: boolean,
): string {
  const fromEnv = (process.env.ICA_OPENAPI_SECTOR_EXAMPLE || '').trim().toLowerCase();
  if (fromEnv) return fromEnv;

  const dataspaceTitle = (process.env.DATASPACE_TITLE || '').trim().toLowerCase();
  if (dataspaceTitle === 'procuredata') return 'retail';
  if (dataspaceTitle === 'global-datacare') return 'health-care';

  if (!wildcardEnabled) {
    return supportedSectorIds[0] || 'health-care';
  }
  return 'retail';
}

function resolveOpenApiTitle(): string {
  const dataspaceTitle = (process.env.DATASPACE_TITLE || '').trim();
  if (dataspaceTitle) {
    return `${dataspaceTitle} ICA Verification API`;
  }
  return 'DataSpace ICA Verification API';
}

const OPENAPI_DIDCOMM_EXAMPLE_PREFIX = 'https://globaldatacare.es/didcomm/';

function normalizeOpenApiDidcommTypeExamples<T>(value: T): T {
  if (!value || typeof value !== 'object') return value;
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    if (Array.isArray(current)) {
      for (const item of current) {
        stack.push(item);
      }
      continue;
    }

    const record = current as Record<string, unknown>;
    if (
      typeof record.type === 'string'
      && record.type.startsWith(OPENAPI_DIDCOMM_EXAMPLE_PREFIX)
    ) {
      record.type = DIDCOMM_BUNDLE_TYPE;
    }

    for (const nested of Object.values(record)) {
      stack.push(nested);
    }
  }
  return value;
}

const OPENAPI_INFO_VERSION = resolveOpenApiInfoVersion();

export function buildIcaVerifyOpenApiSpec(
  options: {
    serverUrl?: string;
  } = {},
) {
  const configuredServerUrl = (options.serverUrl || process.env.ICA_OPENAPI_SERVER_URL || '').trim();
  const serverUrl = configuredServerUrl || 'http://localhost:3310';
  const supportedJurisdictionIds = getConfiguredSupportedJurisdictionIds();
  const supportedJurisdictionSchema = {
    type: 'string',
    enum: supportedJurisdictionIds,
    example: supportedJurisdictionIds[0] || 'ES',
  } as const;
  const supportedSectorIds = getConfiguredSupportedSectorIds();
  const wildcardSupportedSector = hasWildcardSupportedSector();
  const supportedSectorExample = resolveOpenApiSectorExample(supportedSectorIds, wildcardSupportedSector);
  const supportedSectorSchema = wildcardSupportedSector
    ? {
        type: 'string',
        example: supportedSectorExample,
      } as const
    : {
        type: 'string',
        enum: supportedSectorIds,
        example: supportedSectorExample,
      } as const;
  const supportedSectorCodings = getSupportedSectorCodings();
  const supportedSectorsLanguage = getSupportedSectorsLanguage();
  const spec = {
    openapi: '3.1.0',
    info: {
      title: resolveOpenApiTitle(),
      version: OPENAPI_INFO_VERSION,
      description:
        'Asynchronous API for verifying FNMT-signed PDF terms, persisting network evidence/credentials, upserting ICA delegation policies (ODRL), checking credential status, revoking credentials, and activating ICA cryptographic keys before production issuance, plus synchronous DCAT v3 catalog discovery. Current deployment is monotenant and uses alternateName "ica".',
    },
    servers: [{ url: serverUrl }],
    tags: [
      {
        name: 'discovery',
        description: 'Service metadata and DID document endpoints.',
      },
      {
        name: 'terms/pdf',
        description: 'FNMT PDF verification flow (_verify / _verify-response).',
      },
      {
        name: 'entity/did/document',
        description: 'Asynchronous organization did:web document creation and polling.',
      },
      {
        name: 'entity/keys/credentials',
        description: 'ICA credential-signing key lifecycle (_activate / _rotate).',
      },
      {
        name: 'entity/keys/communications',
        description: 'Communication key lifecycle (currently rotate stubs).',
      },
      {
        name: 'network/evidence',
        description: 'Evidence ingestion and polling (_add / _add-response).',
      },
      {
        name: 'network/policies',
        description: 'ICA delegation policy upsert and polling (_upsert / _upsert-response).',
      },
      {
        name: 'network/credentials',
        description:
          'Credential lifecycle over network records: issue, status, revoke and search with async polling (_issue, _status, _revoke, _search + *_response).',
      },
      {
        name: 'network/spaces',
        description:
          'Sector-scoped spaces targets for metadata sync adapters (list/replace).',
      },
      {
        name: 'catalog/dcat3',
        description: 'DCAT v3 synchronous catalog discovery for ICA member organizations.',
      },
    ],
    paths: {
      '/.well-known/ica-configuration': {
        get: {
          tags: ['discovery'],
          summary: 'Get ICA public configuration',
          description:
            'Returns public discovery configuration for this ICA deployment, including the jurisdictions and sectors currently supported by the ICA. Values are resolved from ICA_SUPPORTED_JURISDICTIONS and ICA_SUPPORTED_SECTORS or fall back to the built-in defaults.',
          responses: {
            '200': {
              description: 'Public ICA discovery configuration.',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['language', 'jurisdictions', 'sectors'],
                    properties: {
                      language: { type: 'string', example: supportedSectorsLanguage },
                      jurisdictions: {
                        type: 'array',
                        items: supportedJurisdictionSchema,
                      },
                      sectors: {
                        type: 'array',
                        items: {
                          type: 'object',
                          required: ['code', 'display'],
                          properties: {
                            code: supportedSectorSchema,
                            display: { type: 'string' },
                          },
                        },
                      },
                    },
                  },
                  examples: {
                    icaConfiguration: {
                      value: {
                        language: supportedSectorsLanguage,
                        jurisdictions: supportedJurisdictionIds,
                        sectors: supportedSectorCodings,
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/.well-known/did.json': {
        get: {
          tags: ['discovery'],
          summary: 'Get ICA DID document',
          responses: {
            '200': {
              description: 'DID document.',
              content: {
                'application/did+ld+json': {
                  schema: { type: 'object', additionalProperties: true },
                  examples: {
                    icaDid: {
                      summary: 'ICA DID document with protocol endpoints',
                      value: {
                        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
                        id: 'did:web:localhost%3A3310',
                        controller:
                          'did:web:localhost%3A3310:ica:cds-ES:v1:management:controller:1120:zW1asF7QVMofcbd3hXTJncqMojdpQiRWBBdfkfGJQuEah9g',
                        service: [
                          {
                            id: 'did:web:localhost%3A3310#verify-terms',
                            type: 'DataSpaceIcaVerifyService',
                            serviceEndpoint: '/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify',
                          },
                          {
                            id: 'did:web:localhost%3A3310#dsp-catalog-service',
                            type: 'CatalogService',
                            serviceEndpoint: '/ica/cds-{jurisdiction}/v1/onehealth/dcat3/catalog/request',
                          },
                          {
                            id: 'did:web:localhost%3A3310#dsp-data-service',
                            type: 'DataService',
                            serviceEndpoint: 'https://localhost:3310/.well-known/dspace-version',
                          },
                        ],
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/did.json': {
        get: {
          tags: ['discovery'],
          summary: 'Get ICA DID document (alias)',
          responses: {
            '200': {
              description: 'DID document.',
              content: {
                'application/did+ld+json': {
                  schema: { type: 'object', additionalProperties: true },
                  examples: {
                    icaDidAlias: {
                      summary: 'Same response as /.well-known/did.json',
                      value: {
                        id: 'did:web:localhost%3A3310',
                        service: [
                          {
                            id: 'did:web:localhost%3A3310#verify-terms',
                            type: 'DataSpaceIcaVerifyService',
                            serviceEndpoint: '/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify',
                          },
                        ],
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/.well-known/dspace-version': {
        get: {
          tags: ['discovery'],
          summary: 'Get data space protocol version document',
          responses: {
            '200': {
              description: 'Version and discovery links.',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    additionalProperties: true,
                  },
                  examples: {
                    versionDoc: {
                      value: {
                        version: '1',
                        did: '/.well-known/did.json',
                        openapi: '/openapi.json',
                        icaConfiguration: '/.well-known/ica-configuration',
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/{membertype}/{role}/{idHash}/did.json': {
        get: {
          tags: ['discovery'],
          summary: 'Get controller/member DID document',
          description:
            'Returns the controller DID document when ICA_SELF_CONTROLLER_* DID settings match this route.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'management' },
              description: 'Controller/member namespace (for ICA controller use `management`).',
            },
            {
              name: 'membertype',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'controller' },
              description: 'Membership section (e.g. `controller`, `delegate`, `organization`).',
            },
            {
              name: 'role',
              in: 'path',
              required: true,
              schema: { type: 'string', example: '1120' },
            },
            {
              name: 'idHash',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'zQmExampleControllerHash' },
              description:
                'Deterministic member identifier hash: multibase58(multihash(SHA3-256(id))). For controller bootstrap, id is typically normalized email.',
            },
          ],
          responses: {
            '200': {
              description: 'Controller DID document.',
              content: {
                'application/did+ld+json': {
                  schema: { type: 'object', additionalProperties: true },
                  examples: {
                    controllerDid: {
                      summary: 'Controller DID document',
                      value: {
                        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
                        id: 'did:web:localhost%3A3310:ica:cds-ES:v1:management:controller:1120:zW1asF7QVMofcbd3hXTJncqMojdpQiRWBBdfkfGJQuEah9g',
                        verificationMethod: [
                          {
                            id: 'did:web:localhost%3A3310:ica:cds-ES:v1:management:controller:1120:zW1asF7QVMofcbd3hXTJncqMojdpQiRWBBdfkfGJQuEah9g#ica-controller-es384-001',
                            type: 'JsonWebKey2020',
                            controller:
                              'did:web:localhost%3A3310:ica:cds-ES:v1:management:controller:1120:zW1asF7QVMofcbd3hXTJncqMojdpQiRWBBdfkfGJQuEah9g',
                          },
                        ],
                      },
                    },
                  },
                },
              },
            },
            '404': {
              description: 'Controller DID document is not configured for the requested route.',
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/did/document/_create': {
        post: {
          tags: ['entity/did/document'],
          summary: 'Create organization did:web document asynchronously',
          description:
            'Starts async creation of an organization `did:web` document.\n\n'
            + 'Private keys are never created or retained by the infrastructure operator, except when ICA-generated bootstrap is explicitly used; in that case the private key is returned once and must be stored by the organization.\n\n'
            + '**Key inputs**\n'
            + '- `organization.publicKeyJwk`: primary organization credential-signing key used in `verificationMethod`\n'
            + '- `controller.publicKeyJwk`: different key used to derive the top-level `controller` as `did:key:...`\n'
            + '- optional `organization.jwks` / `controller.jwks`: extra public keys for `vc-sign`, `didcomm-sign`, `didcomm-enc`, etc.\n\n'
            + '**V2 bootstrap**\n'
            + '- controller key may already be stored from `_verify` via `meta.jws.protected.jwk`\n'
            + '- organization key may already be stored from `_verify` via an `application/jwk+json` attachment or an ICA-generated ES384 bootstrap key\n'
            + '- for v1 compatibility, `_create` still accepts explicit `controller.publicKeyJwk` and `organization.publicKeyJwk` when no stored binding/bootstrap key exists yet\n'
            + '- if a controller binding already exists, any explicit `controller.publicKeyJwk` sent to `_create` must match the stored binding and cannot override it\n'
            + '- if an organization key already exists from `_verify`, any explicit `organization.publicKeyJwk` sent to `_create` must match the stored key and cannot override it\n'
            + '- if the organization key was ICA-generated during `_verify` (`keySource=generated`), `_create` requires `organization.publicKeyJwk` to be sent again as explicit confirmation\n\n'
            + '**SDK v2**\n'
            + '- `setControllerMessageSigningPublicKey()` helps `_verify` bind the controller key\n'
            + '- `setOrgCredentialSigningPublicKey()` sends the organization credential key attachment during `_verify`\n'
            + '- `createOrgDidDocument()` and `createOrgDidDocumentFromVcs()` can then call this endpoint reusing the stored keys\n\n'
            + '**Input modes**\n'
            + '- Minimal explicit mode: send `organization.identifier` plus `organization.publicKeyJwk`; the identifier must match a stored organization VC `credentialSubject.id`\n'
            + '- Minimal derived mode: send `organization.url`, `organization.taxID`, and optionally `organization.publicKeyJwk`\n'
            + '  Backend derives `did:web:<organization.url>:<sector>:organization:taxid:<VATES-NIF>` and it must match the stored organization VC `credentialSubject.id` for the same `organization.taxID`\n\n'
            + '**Controller check**\n'
            + '- optional runtime flag `ICA_CREATE_DID_REQUIRE_CONTROLLER_SAMEAS_MATCH=true` enforces that `controller.sameAs` matches the stored Person credential `credentialSubject.sameAs` for the same organization\n\n'
            + '**Polling**\n'
            + '- poll `_create-response` with the same `thid`\n'
            + '- or use `pollCreateOrgDidDocumentResponse()` from the SDK',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                schema: {
                  type: 'object',
                  additionalProperties: true,
                },
                examples: {
                  createDidDocumentRequest: {
                    summary: 'Create one organization did:web document',
                    value: {
                      jti: 'req-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
                      body: {
                        data: [
                          {
                            resource: {
                              organization: {
                                identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
                                publicKeyJwk: {
                                  kty: 'EC',
                                  crv: 'P-384',
                                  x: '<org-x-coordinate>',
                                  y: '<org-y-coordinate>',
                                },
                                jwks: {
                                  keys: [
                                    {
                                      kid: 'org-didcomm-enc-p384-001',
                                      kty: 'EC',
                                      crv: 'P-384',
                                      x: '<org-didcomm-enc-x-coordinate>',
                                      y: '<org-didcomm-enc-y-coordinate>',
                                      use: 'enc',
                                      alg: 'ECDH-ES+A256KW',
                                      purposes: ['didcomm-enc'],
                                    },
                                  ],
                                },
                              },
                              controller: {
                                sameAs: 'urn:multibase:zControllerHash',
                                publicKeyJwk: {
                                  kty: 'EC',
                                  crv: 'P-384',
                                  x: '<controller-x-coordinate>',
                                  y: '<controller-y-coordinate>',
                                },
                                jwks: {
                                  keys: [
                                    {
                                      kid: 'controller-didcomm-sign-p384-001',
                                      kty: 'EC',
                                      crv: 'P-384',
                                      x: '<controller-didcomm-sign-x-coordinate>',
                                      y: '<controller-didcomm-sign-y-coordinate>',
                                      use: 'sig',
                                      alg: 'ES384',
                                      purposes: ['didcomm-sign'],
                                    },
                                  ],
                                },
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                  createDidDocumentRequestDerivedFromUrl: {
                    summary: 'Create one organization did:web document deriving identifier from organization.url',
                    value: {
                      jti: 'req-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
                      body: {
                        data: [
                          {
                            resource: {
                              organization: {
                                url: 'globaldatacare.es',
                                taxID: 'VATES-B00000000',
                                publicKeyJwk: {
                                  kty: 'EC',
                                  crv: 'P-384',
                                  x: '<org-x-coordinate>',
                                  y: '<org-y-coordinate>',
                                },
                                jwks: {
                                  keys: [
                                    {
                                      kid: 'org-didcomm-enc-p384-001',
                                      kty: 'EC',
                                      crv: 'P-384',
                                      x: '<org-didcomm-enc-x-coordinate>',
                                      y: '<org-didcomm-enc-y-coordinate>',
                                      use: 'enc',
                                      alg: 'ECDH-ES+A256KW',
                                      purposes: ['didcomm-enc'],
                                    },
                                  ],
                                },
                              },
                              controller: {
                                sameAs: 'urn:multibase:zControllerHash',
                                publicKeyJwk: {
                                  kty: 'EC',
                                  crv: 'P-384',
                                  x: '<controller-x-coordinate>',
                                  y: '<controller-y-coordinate>',
                                },
                                jwks: {
                                  keys: [
                                    {
                                      kid: 'controller-didcomm-sign-p384-001',
                                      kty: 'EC',
                                      crv: 'P-384',
                                      x: '<controller-didcomm-sign-x-coordinate>',
                                      y: '<controller-didcomm-sign-y-coordinate>',
                                      use: 'sig',
                                      alg: 'ES384',
                                      purposes: ['didcomm-sign'],
                                    },
                                  ],
                                },
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                  createDidDocumentRequestUsingStoredVerifyKeys: {
                    summary: 'V2 create using keys already stored by _verify',
                    value: {
                      jti: 'req-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/entity/did/document/create-request/v1',
                      body: {
                        data: [
                          {
                            resource: {
                              organization: {
                                url: 'globaldatacare.es',
                                taxID: 'VATES-B00000000',
                              },
                              controller: {
                                sameAs: 'urn:multibase:zControllerHash',
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                },
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _create-response endpoint. If `thid` was omitted in the request, read the generated one from `Location`.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint URL including the generated `thid` query parameter, for example `/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-create-did-001`.',
                  example:
                    '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-create-did-001',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '415': {
              description: 'Unsupported content type.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/did/document/_create-response': {
        post: {
          tags: ['entity/did/document'],
          summary: 'Poll organization did:web document creation result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Create DID document thread id. Can also be sent in body as thid.',
            },
          ],
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    thid: { type: 'string' },
                  },
                },
                examples: {
                  pollByBodyThid: {
                    summary: 'Poll using body thid',
                    value: {
                      thid: 'thid-create-did-001',
                    },
                  },
                },
              },
            },
          },
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same `_create-response` polling URL including `?thid=...` so Swagger can keep using the generated thread id.',
                  example:
                    '/ica/cds-ES/v1/animal-care/entity/did/document/_create-response?thid=thid-create-did-001',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'DID document creation completed.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                  examples: {
                    createDidDocumentCompleted: {
                      summary: 'Organization did:web document created',
                      value: {
                        jti: 'urn:uuid:create-did-response-001',
                        iss: 'did:web:localhost%3A3310',
                        aud: 'did:web:localhost%3A3310',
                        thid: 'thid-create-did-001',
                        type: 'application/bundle-api+json',
                        body: {
                          resourceType: 'Bundle',
                          type: 'batch-response',
                          total: 1,
                          issues: {
                            resourceType: 'OperationOutcome',
                            issue: [
                              {
                                severity: 'information',
                                code: 'informational',
                                diagnostics: 'DID document(s) created: 1.',
                              },
                            ],
                          },
                          data: [
                            {
                              type: 'EntityDidDocumentCreate-v1.0',
                              response: {
                                status: '200',
                                outcome: {
                                  resourceType: 'OperationOutcome',
                                  issue: [
                                    {
                                      severity: 'information',
                                      code: 'informational',
                                      diagnostics: 'DID document(s) created: 1.',
                                    },
                                  ],
                                },
                              },
                              resource: {
                                didDocument: {
                                  '@context': [
                                    'https://www.w3.org/ns/did/v1',
                                    'https://w3id.org/security/suites/jws-2020/v1',
                                  ],
                                  id: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
                                  controller: 'did:key:z<controller-public-key-multibase>',
                                  verificationMethod: [
                                    {
                                      id:
                                        'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000#<jwk-rfc7638-thumbprint>',
                                      type: 'JsonWebKey2020',
                                      controller:
                                        'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
                                      publicKeyJwk: {
                                        kty: 'EC',
                                        crv: 'P-384',
                                        x: '<org-x-coordinate>',
                                        y: '<org-y-coordinate>',
                                        kid: '<jwk-rfc7638-thumbprint>',
                                        alg: 'ES384',
                                        use: 'sig',
                                      },
                                    },
                                    {
                                      id:
                                        'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000#org-didcomm-sign-p384-001',
                                      type: 'JsonWebKey2020',
                                      controller:
                                        'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
                                      publicKeyJwk: {
                                        kid: 'org-didcomm-sign-p384-001',
                                        kty: 'EC',
                                        crv: 'P-384',
                                        x: '<org-didcomm-sign-x-coordinate>',
                                        y: '<org-didcomm-sign-y-coordinate>',
                                        use: 'sig',
                                        alg: 'ES384',
                                        purposes: ['didcomm-sign'],
                                      },
                                    },
                                    {
                                      id:
                                        'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000#org-didcomm-enc-p384-001',
                                      type: 'JsonWebKey2020',
                                      controller:
                                        'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
                                      publicKeyJwk: {
                                        kid: 'org-didcomm-enc-p384-001',
                                        kty: 'EC',
                                        crv: 'P-384',
                                        x: '<org-didcomm-enc-x-coordinate>',
                                        y: '<org-didcomm-enc-y-coordinate>',
                                        use: 'enc',
                                        alg: 'ECDH-ES+A256KW',
                                        purposes: ['didcomm-enc'],
                                      },
                                    },
                                  ],
                                  assertionMethod: [
                                    'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000#<jwk-rfc7638-thumbprint>',
                                  ],
                                  authentication: [
                                    'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000#<jwk-rfc7638-thumbprint>',
                                    'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000#org-didcomm-sign-p384-001',
                                  ],
                                  keyAgreement: [
                                    'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000#org-didcomm-enc-p384-001',
                                  ],
                                },
                                meta: {
                                  createdAt: '2026-03-12T21:12:26.646Z',
                                },
                              },
                            },
                          ],
                        },
                      },
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'DID document create job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/request': {
        post: {
          tags: ['catalog/dcat3'],
          summary: 'Request ICA DCAT v3 catalog',
          description:
            'Returns a `dcat:Catalog` with ICA member organization datasets. Optional JSON body supports filters (`sector`, `jurisdiction`). Response format is DCAT JSON-LD (not DIDComm envelope/body.data[]). The publisher DID is the organization real `did:web`; ICA internal membership aliases are not used as primary publisher.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: DCAT_CATALOG_REQUEST_SCHEMA,
                examples: {
                  allMembers: {
                    summary: 'Catalog without filters',
                    value: {},
                  },
                  onehealthEs: {
                    summary: 'Catalog filtered by onehealth sector/jurisdiction',
                    value: DCAT_CATALOG_REQUEST_EXAMPLE,
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'DCAT v3 catalog.',
              content: {
                'application/ld+json': {
                  schema: DCAT_CATALOG_SCHEMA,
                  examples: {
                    dcatCatalog: {
                      summary: 'DCAT catalog response',
                      value: DCAT_CATALOG_EXAMPLE,
                    },
                  },
                },
                'application/json': {
                  schema: DCAT_CATALOG_SCHEMA,
                  examples: {
                    dcatCatalog: {
                      summary: 'DCAT catalog response',
                      value: DCAT_CATALOG_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/json': {
                  schema: { type: 'object', properties: { error: { type: 'string' } } },
                },
              },
            },
            '415': {
              description: 'Unsupported content type.',
              content: {
                'application/json': {
                  schema: { type: 'object', properties: { error: { type: 'string' } } },
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/datasets/{id}': {
        get: {
          tags: ['catalog/dcat3'],
          summary: 'Read one dataset from ICA DCAT v3 catalog',
          description:
            'Returns one `dcat:Dataset` entry in DCAT JSON-LD (not DIDComm envelope/body.data[]). The returned `dcterms:publisher.@id` is the organization real `did:web`.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'zQmTaxIdMultihash' },
              description: 'Dataset id: multibase58(multihash(SHA3-256(taxId))).',
            },
          ],
          responses: {
            '200': {
              description: 'DCAT dataset.',
              content: {
                'application/ld+json': {
                  schema: DCAT_DATASET_SCHEMA,
                  examples: {
                    dcatDataset: {
                      summary: 'Single dataset from catalog',
                      value: DCAT_DATASET_EXAMPLE,
                    },
                  },
                },
                'application/json': {
                  schema: DCAT_DATASET_SCHEMA,
                  examples: {
                    dcatDataset: {
                      summary: 'Single dataset from catalog',
                      value: DCAT_DATASET_EXAMPLE,
                    },
                  },
                },
              },
            },
            '404': {
              description: 'Dataset not found.',
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/ddo/request': {
        post: {
          tags: ['catalog/dcat3'],
          summary: 'Request ICA DDO catalog (parallel format)',
          description:
            'Returns an ICA DDO catalog profile (`urn:ica:ddo:catalog:v1`) in parallel to DCAT endpoints. This does not replace DCAT nor metadata sync formats.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: DDO_CATALOG_REQUEST_SCHEMA,
                examples: {
                  bySectorAndJurisdiction: {
                    summary: 'Filter by sector and jurisdiction',
                    value: DDO_CATALOG_REQUEST_EXAMPLE,
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'DDO catalog profile.',
              content: {
                'application/json': {
                  schema: DDO_CATALOG_SCHEMA,
                  examples: {
                    catalogDdo: {
                      summary: 'ICA DDO catalog response',
                      value: DDO_CATALOG_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/json': {
                  schema: { type: 'object', properties: { error: { type: 'string' } } },
                },
              },
            },
            '415': {
              description: 'Unsupported content type.',
              content: {
                'application/json': {
                  schema: { type: 'object', properties: { error: { type: 'string' } } },
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/dcat3/catalog/ddo/datasets/{id}': {
        get: {
          tags: ['catalog/dcat3'],
          summary: 'Read one dataset from ICA DDO catalog (parallel format)',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'zQmTaxIdMultihash' },
              description: 'Dataset id: multibase58(multihash(SHA3-256(taxId))).',
            },
          ],
          responses: {
            '200': {
              description: 'DDO dataset profile entry.',
              content: {
                'application/json': {
                  schema: DDO_DATASET_ENTRY_SCHEMA,
                  examples: {
                    datasetEntry: {
                      summary: 'Single dataset DDO entry',
                      value: DDO_CATALOG_EXAMPLE.datasetList[0],
                    },
                  },
                },
              },
            },
            '404': {
              description: 'Dataset not found.',
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate': {
        post: {
          tags: ['entity/keys/credentials'],
          summary: 'Activate ICA signing key',
          description:
            'Starts async activation/import of one or more signing keys and returns polling location. Supports controller authorization via body.signature (FHIR Signature with detached compact JWS over canonical body) and validates CA x509 credential chain (x5c/certificateChainPem) per key. For a runnable deterministic test payload use npm run api:example:activate.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  activateMultipleKeys: {
                    summary: 'Activate multiple keys in one request',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
                      body: {
                        signature: {
                          sigFormat: 'application/jose',
                          who: {
                            reference: 'did:web:ica.example.com#ica-es384-20260305',
                          },
                          data: '<detached-compact-jws-or-base64>',
                        },
                        data: [
                          {
                            key: {
                              kid: 'ica-es384-20260305',
                              alg: 'ES384',
                              privateKeyPem: '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----',
                              certificateChainPem: [
                                '-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----',
                              ],
                            },
                          },
                          {
                            key: {
                              kid: 'ica-es256k-20260305',
                              alg: 'ES256K',
                              privateKeyPem: '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----',
                              certificateChainPem: [
                                '-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----',
                              ],
                            },
                          },
                        ],
                      },
                    },
                  },
                  activateEs384: {
                    summary: 'Activate single ES384 key via body.data[]',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
                      body: {
                        signature: {
                          sigFormat: 'application/jose',
                          who: {
                            reference: 'did:web:ica.example.com#ica-es384-20260305',
                          },
                          data: '<detached-compact-jws-or-base64>',
                        },
                        data: [
                          {
                            key: {
                              kid: 'ica-es384-20260305',
                              alg: 'ES384',
                              privateKeyPem: '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----',
                              certificateChainPem: [
                                '-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----',
                                '-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----',
                              ],
                            },
                          },
                        ],
                      },
                    },
                  },
                },
                schema: ACTIVATE_DIDCOMM_REQUEST_SCHEMA,
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _activate-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint path ending in _activate-response (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add': {
        post: {
          tags: ['network/evidence'],
          summary: 'Add verified evidence record',
          description:
            'Starts async persistence of evidence records (`address`, `official-registry`, `qualification`, etc.) and returns polling location. Canonical input is body.data[]; optionally accepts DIDComm `attachments[]` with vc+jwt entries that are verified against configured vc issuer list (DID/JWKS) before persistence.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'evidenceType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'official-registry' },
              description: 'Evidence classifier for collection storage.',
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  addOfficialRegistryEvidence: {
                    summary: 'Add single evidence using resource.verified_claims + claims',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
                      body: {
                        data: [
                          {
                            issuedCredentialRecordId: 'urn:uuid:issued-record-001',
                            operatorDid: 'did:web:localhost%3A3310#employee-01',
                            resource: {
                              verified_claims: {
                                verification: {
                                  trust_framework: null,
                                  time: '2026-03-06T10:00:00.000Z',
                                  evidence: [
                                    {
                                      type: 'electronic_record',
                                      time: '2026-03-06T10:00:00.000Z',
                                      verifier: {
                                        organization: 'did:web:localhost%3A3310',
                                      },
                                      record: {
                                        type: 'official-registry',
                                        source: {
                                          id: 'did:web:mercantile-registry.example.org',
                                          type: 'PublicRegistry',
                                          country_code: 'ES',
                                          jurisdiction: 'ES',
                                        },
                                        created_at: '2026-03-06T10:00:00.000Z',
                                      },
                                      attachments: [
                                        {
                                          digest: {
                                            alg: 'sha3-384',
                                            value: '<base64>',
                                          },
                                          url: 'urn:uuid:evidence-doc-001',
                                        },
                                      ],
                                      check_details: [
                                        {
                                          check_method: 'vcrypt',
                                          organization: 'did:web:localhost%3A3310',
                                          time: '2026-03-06T10:00:00.000Z',
                                        },
                                      ],
                                    },
                                  ],
                                },
                                claims: {
                                  healthcareRegistrationNumber: 'ES-SAN-REG-0001',
                                  professionalLicenseDid: 'did:web:college.example.org:member:12345',
                                  organizationDid: 'did:web:member.example.org',
                                },
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                  addOfficialRegistryEvidenceBatch: {
                    summary: 'Add evidence batch with body.data[]',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
                      body: {
                        data: [
                          {
                            issuedCredentialRecordId: 'urn:uuid:issued-record-001',
                            operatorDid: 'did:web:localhost%3A3310#employee-01',
                            resource: {
                              type: 'electronic_record',
                              time: '2026-03-06T10:00:00.000Z',
                              verifier: {
                                organization: 'did:web:localhost%3A3310',
                              },
                              record: {
                                type: 'official-registry',
                                source: {
                                  id: 'did:web:mercantile-registry.example.org',
                                  type: 'PublicRegistry',
                                },
                              },
                              attachments: [
                                {
                                  digest: {
                                    alg: 'sha3-384',
                                    value: '<base64>',
                                  },
                                  url: 'urn:uuid:evidence-doc-001',
                                },
                              ],
                              check_details: [
                                {
                                  check_method: 'vcrypt',
                                  organization: 'did:web:localhost%3A3310',
                                  time: '2026-03-06T10:00:00.000Z',
                                },
                              ],
                            },
                          },
                          {
                            issuedCredentialRecordId: 'urn:uuid:issued-record-001',
                            operatorDid: 'did:web:localhost%3A3310#employee-02',
                            resource: {
                              type: 'document',
                              method: 'eid',
                              time: '2026-03-06T10:05:00.000Z',
                              verifier: {
                                organization: 'did:web:localhost%3A3310',
                              },
                              document_details: {
                                type: 'official-registry-certificate',
                                document_number: 'B-123456',
                              },
                              attachments: {
                                digest: {
                                  alg: 'sha3-384',
                                  value: '<base64>',
                                },
                                url: 'urn:uuid:evidence-doc-002',
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                  addPontusXVcJwtAttachment: {
                    summary: 'Add evidence from DIDComm vc+jwt attachment (Pontus-X style)',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
                      body: {
                        issuedCredentialRecordId: 'urn:uuid:issued-record-001',
                        operatorDid: 'did:web:localhost%3A3310#employee-03',
                      },
                      attachments: [
                        {
                          id: 'pontusx-vc-001',
                          format: 'vc+jwt',
                          media_type: 'application/vc+jwt',
                          data: {
                            json: {
                              format: 'vc+jwt',
                              jwt: '<compact-vc-jwt-es256k>',
                            },
                          },
                        },
                      ],
                    },
                  },
                },
                schema: ADD_EVIDENCE_DIDCOMM_REQUEST_SCHEMA,
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _add-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint path ending in _add-response (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert': {
        post: {
          tags: ['network/policies'],
          summary: 'Upsert ICA delegation policy (ODRL)',
          description:
            'Starts async upsert of ICA delegation policies using body.data[] batch. Policies are ODRL resources (with optional Gaia-X OVC constraints) that delegate who can add/verify evidence for member organizations. Sector values must match the configured ICA supported sectors list.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  upsertDelegateInvitationPolicy: {
                    summary: 'Controller invites delegate with ODRL policy scoped to evidence type',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
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
                                  onehealth: 'https://onehealth.example/ns#',
                                },
                              ],
                              profile: 'https://w3id.org/gaia-x/ovc/1/',
                              uid: 'urn:policy:ica:es:delegate:1120:zEmailHash:official-registry:v1',
                              type: 'Set',
                              assigner: {
                                '@id': 'did:web:ica.example.org:ica:cds-ES:v1:onehealth:controller:1120:zControllerHash',
                              },
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
                                    {
                                      'ovc:leftOperand': '$.credentialSubject.identifier',
                                      'odrl:operator': 'odrl:eq',
                                      'odrl:rightOperand': 'zEmailHash',
                                    },
                                    {
                                      'ovc:leftOperand': '$.credentialSubject.walletKid',
                                      'odrl:operator': 'odrl:eq',
                                      'odrl:rightOperand': 'did:key:z6MkInvitee...#z6MkInvitee...',
                                    },
                                  ],
                                },
                              ],
                            },
                          },
                        ],
                      },
                    },
                  },
                },
                schema: POLICY_UPSERT_DIDCOMM_REQUEST_SCHEMA,
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _upsert-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint path ending in _upsert-response (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue': {
        post: {
          tags: ['network/credentials'],
          summary: 'Issue credential record',
          description:
            'Starts async persistence of issued credential records from body.data[] (resource + optional evidence) and returns polling location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'credentialType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'member-onboarding' },
              description: 'Credential classifier for collection storage.',
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  issueCredentialWithEvidence: {
                    summary: 'Issue credential batch via body.data[]',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/network/credentials/issue-request/v1',
                      body: {
                        data: [
                          {
                            resource: {
                              id: 'urn:uuid:vc-member-001',
                              type: ['VerifiableCredential', 'LegalRepresentativeCredential'],
                              issuer: 'did:web:localhost%3A3310',
                              credentialSubject: {
                                id: 'did:web:member.example.org:alice',
                                '@type': 'Person',
                                memberOf: {
                                  '@type': 'Organization',
                                  legalName: 'Acme Health SL',
                                  taxID: 'VATES-A12345678',
                                },
                              },
                              evidence: [
                                {
                                  type: 'qualification',
                                  checkedAt: '2026-03-06T10:00:00.000Z',
                                },
                              ],
                            },
                            evidence: [
                              {
                                type: 'address',
                                checkedAt: '2026-03-06T10:01:00.000Z',
                                proof: {
                                  type: 'OperatorApprovalProof',
                                  signer: 'did:web:localhost%3A3310#employee-02',
                                  signature: '<jws>',
                                },
                              },
                            ],
                          },
                          {
                            resource: {
                              id: 'urn:uuid:vc-member-002',
                              type: ['VerifiableCredential', 'OrganizationCredential'],
                              issuer: 'did:web:localhost%3A3310',
                              credentialSubject: {
                                id: 'did:web:member.example.org',
                                '@type': 'Organization',
                                legalName: 'Acme Health SL',
                                taxID: 'VATES-A12345678',
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                },
                schema: ISSUE_CREDENTIAL_DIDCOMM_REQUEST_SCHEMA,
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _issue-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint path ending in _issue-response (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status': {
        post: {
          tags: ['network/credentials'],
          summary: 'Resolve credential status',
          description:
            'Starts async credential-status lookup batch (good/revoked/unknown) from body.data[] and returns polling location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'credentialType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'member-onboarding' },
              description: 'Credential classifier used for scoped lookup.',
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  statusByCredentialId: {
                    summary: 'Query status batch via body.data[]',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/network/credentials/status-request/v1',
                      body: {
                        data: [
                          {
                            credentialId: 'urn:uuid:vc-member-001',
                            resource: {
                              id: 'urn:uuid:vc-member-001',
                              credentialStatus: {
                                id: 'urn:uuid:issued-record-001#status',
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                },
                schema: CREDENTIAL_STATUS_DIDCOMM_REQUEST_SCHEMA,
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _status-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint path ending in _status-response (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke': {
        post: {
          tags: ['network/credentials'],
          summary: 'Revoke credential record',
          description:
            'Starts async credential revocation batch from body.data[] (sets credentialStatus=revoked) and returns polling location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'credentialType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'member-onboarding' },
              description: 'Credential classifier used for scoped lookup.',
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  revokeByCredentialId: {
                    summary: 'Revoke batch via body.data[]',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/network/credentials/revoke-request/v1',
                      body: {
                        data: [
                          {
                            credentialId: 'urn:uuid:vc-member-001',
                            reason: 'membership-terminated',
                            revokedBy: 'did:web:localhost%3A3310#employee-02',
                            resource: {
                              id: 'urn:uuid:vc-member-001',
                              credentialStatus: {
                                id: 'urn:uuid:issued-record-001#status',
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                },
                schema: CREDENTIAL_REVOKE_DIDCOMM_REQUEST_SCHEMA,
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _revoke-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint path ending in _revoke-response (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_search': {
        post: {
          tags: ['network/credentials'],
          summary: 'Search credential records',
          description:
            'Starts async credential search from unit filters (FHIR-style POST _search with form parameters) and returns polling location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'credentialType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'member-onboarding' },
              description: 'Credential classifier used for scoped search.',
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/x-www-form-urlencoded': {
                examples: {
                  searchByTaxId: {
                    summary: 'Search organization credentials by taxId',
                    value: {
                      taxId: 'VATES-A12345678',
                      thid: 'thid-auto',
                    },
                  },
                  searchRepresentativeByEmail: {
                    summary: 'Search representative credential by email',
                    value: {
                      email: 'legal.rep@example.org',
                      thid: 'thid-auto',
                    },
                  },
                },
                schema: CREDENTIAL_SEARCH_REQUEST_BODY_SCHEMA,
              },
              'application/didcomm-plain+json': {
                schema: {
                  type: 'object',
                  additionalProperties: true,
                },
                description: 'Legacy compatibility mode (DIDComm body.data[]).',
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _search-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint path ending in _search-response (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/spaces/_list': {
        post: {
          tags: ['network/spaces'],
          summary: 'List spaces targets',
          description:
            'Returns current sector-scoped spaces targets used by sync adapters. Includes configured ICA_ROOT_CA_DID in response resource. Sensitive fields (`apiKey`, `license`) are never returned.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                schema: SPACES_LIST_DIDCOMM_REQUEST_SCHEMA,
                examples: {
                  listSpaces: {
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/network/spaces/list-request/v1',
                      body: {},
                    },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Spaces targets list.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/spaces/_replace': {
        post: {
          tags: ['network/spaces'],
          summary: 'Replace spaces targets',
          description:
            'Replaces the full sector-scoped spaces targets list (`body.data[]`). Credentials (`apiKey`/`license`) are accepted as write-only input and never returned.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                schema: SPACES_REPLACE_DIDCOMM_REQUEST_SCHEMA,
                examples: {
                  replaceSpaces: {
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/network/spaces/replace-request/v1',
                      body: {
                        data: [
                          {
                            resourceType: 'RuntimePlatform',
                            name: 'Pontus-X',
                            identifier: 'did:web:pontusx.example.org',
                            url: 'https://adapter.example.org/dummy-sync',
                            license: '<api-key>',
                          },
                        ],
                      },
                    },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Spaces targets replaced.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify': {
        post: {
          tags: ['terms/pdf'],
          summary: 'Submit PDF verification job',
          description:
            'Starts an async PDF verification job and returns polling location in headers.\n\n'
            + '**Required input**\n'
            + '- DIDComm plaintext request must carry the signed PDF in `attachments[]`\n\n'
            + '**V2 bootstrap**\n'
            + '- controller message-signing key travels in `meta.jws.protected.jwk`\n'
            + '- organization credential-signing public key travels as a separate `application/jwk+json` attachment\n'
            + '- if the organization JWK attachment is omitted, ICA autogenerates an ES384 organization credential-signing keypair\n'
            + '- the generated `publicKeyJwk` and `privateKeyJwk` are returned in `_verify-response` outside `body.data[].resource`\n\n'
            + '**SDK v2**\n'
            + '- `setControllerMessageSigningPublicKey()` fills `meta.jws.protected.jwk`\n'
            + '- `setOrgCredentialSigningPublicKey()` adds the organization JWK attachment\n'
            + '- `verifyTerms()` builds the request envelope for you\n\n'
            + '**Swagger UI**\n'
            + '- known Dropbox share links in `attachments[].data.links` are normalized from `dl=0` to `dl=1` before sending',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'resourceType',
              in: 'path',
              required: true,
              schema: { type: 'string', pattern: '^(?:contract|\\d{12}|test-\\d{12})$', example: 'contract' },
              description:
                'Use "contract" to skip template/content validation. Otherwise use a document version token: production yyyyddmmhhmm or testing test-yyyyddmmhhmm (requires ICA_ENABLE_TEST_TERMS_PREFIX=true).',
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  viaUrl: {
                    summary: 'DIDComm con PDF accesible por URL',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
                      body: {},
                      attachments: [
                        {
                          id: 'signed-terms',
                          media_type: 'application/pdf',
                          data: {
                            links: ['https://example.org/path/to/terms-signed-fnmt.pdf'],
                          },
                        },
                      ],
                    },
                  },
                  viaDropboxSharedUrl: {
                    summary: 'DIDComm con URL compartida de Dropbox (Swagger cambia dl=0 a dl=1)',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
                      body: {},
                      attachments: [
                        {
                          id: 'signed-terms',
                          media_type: 'application/pdf',
                          data: {
                            links: ['https://www.dropbox.com/s/example123/terms-signed.pdf?dl=0'],
                          },
                        },
                      ],
                    },
                  },
                  viaBase64: {
                    summary: 'DIDComm con PDF en base64',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
                      body: {},
                      attachments: [
                        {
                          id: 'signed-terms',
                          media_type: 'application/pdf',
                          data: {
                            base64: 'JVBERi0xLjQKJcTl8uXr...',
                          },
                        },
                      ],
                    },
                  },
                  viaBase64WithSdkV2Bootstrap: {
                    summary: 'V2 onboarding con controller key en meta y JWK de organización en attachment',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/terms/verify-request/v1',
                      meta: {
                        jws: {
                          protected: {
                            alg: 'ES384',
                            kid: 'controller-msg-es384-001',
                            jwk: {
                              kty: 'EC',
                              crv: 'P-384',
                              x: '<controller-msg-x-coordinate>',
                              y: '<controller-msg-y-coordinate>',
                            },
                          },
                        },
                      },
                      body: {},
                      attachments: [
                        {
                          id: 'signed-terms',
                          media_type: 'application/pdf',
                          data: {
                            base64: 'JVBERi0xLjQKJcTl8uXr...',
                          },
                        },
                        {
                          id: 'organization-public-jwk',
                          media_type: 'application/jwk+json',
                          filename: 'organization-public-key.jwk.json',
                          data: {
                            json: {
                              kid: 'org-cred-es384-001',
                              kty: 'EC',
                              crv: 'P-384',
                              x: '<org-cred-x-coordinate>',
                              y: '<org-cred-y-coordinate>',
                              use: 'sig',
                              alg: 'ES384',
                            },
                          },
                        },
                      ],
                    },
                  },
                },
                schema: {
                  type: 'object',
                  required: ['type', 'attachments'],
                  properties: {
                    jti: { type: 'string' },
                    thid: { type: 'string' },
                    type: { type: 'string' },
                    meta: {
                      type: 'object',
                      additionalProperties: true,
                      description:
                        'Optional DIDComm metadata. In v2, `meta.jws.protected.jwk` carries the controller message-signing public key. `ica-client-sdk-ts@2.x` fills this automatically when `setControllerMessageSigningPublicKey()` is configured.',
                    },
                    body: { type: 'object', additionalProperties: true },
                    attachments: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          id: { type: 'string' },
                          filename: { type: 'string' },
                          media_type: {
                            type: 'string',
                            example: 'application/pdf',
                            description:
                              'Use `application/pdf` for the signed terms PDF or `application/jwk+json` for the optional organization credential public key attachment.',
                          },
                          data: {
                            type: 'object',
                            properties: {
                              base64: {
                                type: 'string',
                                description: 'PDF codificado en base64.',
                              },
                              json: {
                                type: 'object',
                                additionalProperties: true,
                                description:
                                  'JSON payload for non-PDF attachments. In v2, `application/jwk+json` uses `data.json` to transport the organization credential public JWK. `ica-client-sdk-ts@2.x` adds this attachment automatically when `setOrgCredentialSigningPublicKey()` is configured.',
                              },
                              links: {
                                type: 'array',
                                description: 'URL(s) HTTP(S) desde donde descargar el PDF firmado.',
                                items: { type: 'string' },
                              },
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _verify-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint path ending in _verify-response (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_remove': {
        post: {
          tags: ['terms/pdf'],
          summary: 'Remove accepted organization terms asynchronously',
          description:
            'Starts async removal of accepted organization terms for an onboarded organization.\n\n'
            + '**Business effect**\n'
            + '- organization stops being accepted for the selected dataspace scope\n'
            + '- active DID document is removed from publication\n'
            + '- organization is removed from catalog publication\n'
            + '- organization keys are treated as revoked for that onboarding cycle\n'
            + '- a later return requires a fresh `_verify` and `_create`\n\n'
            + '**Lookup**\n'
            + '- `organization.identifier` (the organization DID) is the primary lookup key\n'
            + '- `organization.taxID` is optional and, if sent, must match the active tax ID bound to that DID\n\n'
            + '**Authorization**\n'
            + '- `controller.publicKeyJwk` must match the stored controller binding for the organization\n'
            + '- in didactic/plain mode this may travel in `meta.jws.protected.jwk`\n'
            + '- hardened production mode should use signed DIDComm so the controller key is actually proven, not just claimed\n\n'
            + '**SDK**\n'
            + '- `ica-client-sdk-ts@2.x` provides `removeOrganizationTerms()` and `pollRemoveOrganizationTermsResponse()`\n\n'
            + '**Temporary evidence mode**\n'
            + '- future hardening may add a dedicated signed offboarding PDF template\n'
            + '- for now, DID-driven removal is the primary mechanism; verifier/verification-partner/member PDF signature combinations remain a TODO\n\n'
            + '**Polling**\n'
            + '- poll `_remove-response` with the same `thid`',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'resourceType',
              in: 'path',
              required: true,
              schema: { type: 'string', pattern: '^(?:contract|\\d{12}|test-\\d{12})$', example: 'contract' },
              description:
                'Use the same `resourceType` used during terms verification for the onboarding cycle being removed.',
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                schema: {
                  type: 'object',
                  additionalProperties: true,
                },
                examples: {
                  removeAcceptedTerms: {
                    summary: 'Remove accepted terms for one organization',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/terms/remove-request/v1',
                      meta: {
                        jws: {
                          protected: {
                            alg: 'ES384',
                            kid: 'controller-msg-es384-001',
                            jwk: {
                              kty: 'EC',
                              crv: 'P-384',
                              x: '<controller-msg-x-coordinate>',
                              y: '<controller-msg-y-coordinate>',
                            },
                          },
                        },
                      },
                      body: {
                        data: [
                          {
                            resource: {
                              organization: {
                                taxID: 'VATES-B00000000',
                                identifier: 'did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000',
                              },
                              controller: {
                                sameAs: 'urn:multibase:zControllerHash',
                              },
                              reason: 'organization-requested-removal',
                            },
                          },
                        ],
                      },
                    },
                  },
                },
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _remove-response endpoint using Location header.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Polling endpoint URL including the generated `thid` query parameter, for example `/ica/cds-ES/v1/animal-care/terms/pdf/contract/_remove-response?thid=thid-remove-001`.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response': {
        post: {
          tags: ['entity/keys/credentials'],
          summary: 'Poll signing-key activation result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Activation thread id. Can also be sent in body as thid.',
            },
          ],
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same _activate-response endpoint path; continue polling with same thid.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Activation completed (success or handled failure payload).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                  examples: {
                    activationCompleted: {
                      summary: 'Activation succeeded',
                      value: ACTIVATE_RESPONSE_SUCCESS_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'Activation job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response': {
        post: {
          tags: ['network/evidence'],
          summary: 'Poll evidence add result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'evidenceType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'official-registry' },
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Evidence add thread id. Can also be sent in body as thid.',
            },
          ],
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same _add-response endpoint path; continue polling with same thid.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Evidence add completed (success or handled failure payload).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                  examples: {
                    addEvidenceCompleted: {
                      summary: 'Evidence stored',
                      value: ADD_EVIDENCE_RESPONSE_SUCCESS_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'Evidence add job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert-response': {
        post: {
          tags: ['network/policies'],
          summary: 'Poll delegation policy upsert result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Delegation policy upsert thread id. Can also be sent in body as thid.',
            },
          ],
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same _upsert-response endpoint path; continue polling with same thid.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Delegation policy upsert completed (success or handled failure payload).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                  examples: {
                    delegationPolicyUpsertCompleted: {
                      summary: 'Delegation policy upserted',
                      value: DELEGATION_POLICY_UPSERT_RESPONSE_SUCCESS_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'Delegation policy upsert job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response': {
        post: {
          tags: ['network/credentials'],
          summary: 'Poll credential issue result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'credentialType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'member-onboarding' },
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Credential issue thread id. Can also be sent in body as thid.',
            },
          ],
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same _issue-response endpoint path; continue polling with same thid.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Credential issue completed (success or handled failure payload).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                  examples: {
                    issueCompleted: {
                      summary: 'Credential stored',
                      value: ISSUE_CREDENTIAL_RESPONSE_SUCCESS_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'Credential issue job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response': {
        post: {
          tags: ['network/credentials'],
          summary: 'Poll credential status result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'credentialType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'member-onboarding' },
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Credential status thread id. Can also be sent in body as thid.',
            },
          ],
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same _status-response endpoint path; continue polling with same thid.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Credential status lookup completed (success or handled failure payload).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                  examples: {
                    statusCompleted: {
                      summary: 'Credential status resolved',
                      value: CREDENTIAL_STATUS_RESPONSE_SUCCESS_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'Credential status job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response': {
        post: {
          tags: ['network/credentials'],
          summary: 'Poll credential revoke result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'credentialType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'member-onboarding' },
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Credential revoke thread id. Can also be sent in body as thid.',
            },
          ],
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same _revoke-response endpoint path; continue polling with same thid.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Credential revocation completed (success or handled failure payload).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                  examples: {
                    revokeCompleted: {
                      summary: 'Credential revoked',
                      value: CREDENTIAL_REVOKE_RESPONSE_SUCCESS_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'Credential revoke job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_remove-response': {
        post: {
          tags: ['terms/pdf'],
          summary: 'Poll organization terms removal result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'resourceType',
              in: 'path',
              required: true,
              schema: { type: 'string', pattern: '^(?:contract|\\d{12}|test-\\d{12})$', example: 'contract' },
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Terms remove thread id. Can also be sent in body as thid.',
            },
          ],
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same `_remove-response` endpoint path; continue polling with the same `thid`.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Terms removal completed (success or handled failure payload).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'Terms remove job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_search-response': {
        post: {
          tags: ['network/credentials'],
          summary: 'Poll credential search result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'credentialType',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'member-onboarding' },
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Credential search thread id. Can also be sent in body as thid.',
            },
          ],
          responses: {
            '202': {
              description: 'Still pending.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same _search-response endpoint path; continue polling with same thid.',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Credential search completed (success or handled failure payload).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                },
              },
            },
            '400': {
              description: 'Missing or invalid thread id.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '404': {
              description: 'Credential search job not found.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate': {
        post: {
          tags: ['entity/keys/credentials'],
          summary: 'Rotate keys for credential issuance (stub)',
          description:
            'Reserved endpoint for rotating ICA keys used in credential issuance. Current implementation validates controller authorization signature and returns 202 with polling Location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  rotateCredentialsRequest: {
                    summary: 'Rotate credentials keys (controller-signed)',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/rotate-request/v1',
                      body: {
                        signature: {
                          sigFormat: 'application/jose',
                          who: {
                            reference: 'did:web:ica.example.com#ica-controller-20260305',
                          },
                          data: '<detached-compact-jws-or-base64>',
                        },
                      },
                    },
                  },
                },
                schema: ROTATE_DIDCOMM_REQUEST_SCHEMA,
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _rotate-response endpoint.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                },
                'Retry-After': {
                  schema: { type: 'string' },
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate-response': {
        post: {
          tags: ['entity/keys/credentials'],
          summary: 'Poll credential-issuance key rotation result (stub)',
          responses: {
            '501': {
              description: 'Not implemented yet.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate': {
        post: {
          tags: ['entity/keys/communications'],
          summary: 'Rotate keys for communication messages (stub)',
          description:
            'Reserved endpoint for rotating keys used in communication messages. Current implementation validates controller authorization signature and returns 202 with polling Location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/didcomm-plain+json': {
                examples: {
                  rotateCommunicationsRequest: {
                    summary: 'Rotate communications keys (controller-signed)',
                    value: {
                      jti: 'req-auto',
                      thid: 'thid-auto',
                      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/rotate-request/v1',
                      body: {
                        signature: {
                          sigFormat: 'application/jose',
                          who: {
                            reference: 'did:web:ica.example.com#ica-controller-20260305',
                          },
                          data: '<detached-compact-jws-or-base64>',
                        },
                      },
                    },
                  },
                },
                schema: ROTATE_DIDCOMM_REQUEST_SCHEMA,
              },
            },
          },
          responses: {
            '202': {
              description: 'Accepted. Poll _rotate-response endpoint.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                },
                'Retry-After': {
                  schema: { type: 'string' },
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate-response': {
        post: {
          tags: ['entity/keys/communications'],
          summary: 'Poll communication-message key rotation result (stub)',
          responses: {
            '501': {
              description: 'Not implemented yet.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response': {
        post: {
          tags: ['terms/pdf'],
          summary: 'Poll async verification result',
          description:
            'Returns the verification result.\n\n'
            + '**Organization entry**\n'
            + '- may include `publicKeyJwk`, `privateKeyJwk`, and `keySource` outside `resource`\n'
            + '- `privateKeyJwk` is present only when ICA generated the organization keypair during `_verify`\n\n'
            + '**Legal-representative / controller entry**\n'
            + '- may include only `publicKeyJwk` for the controller binding key\n\n'
            + '**SDK v2**\n'
            + '- `pollVerifyTermsResponse()` polls this endpoint\n'
            + '- `getOrganizationKeyMaterialFromVerifyResponse()` reads organization bootstrap keys\n'
            + '- `getControllerBindingPublicKeyFromVerifyResponse()` reads the controller binding key',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: supportedJurisdictionSchema,
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: supportedSectorSchema,
            },
            {
              name: 'resourceType',
              in: 'path',
              required: true,
              schema: { type: 'string', pattern: '^(?:contract|\\d{12}|test-\\d{12})$', example: 'contract' },
              description:
                'Use "contract" to skip template/content validation. Otherwise use a document version token: production yyyyddmmhhmm or testing test-yyyyddmmhhmm (requires ICA_ENABLE_TEST_TERMS_PREFIX=true).',
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Thread id. Can also be provided in JSON body.',
            },
          ],
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    thid: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '202': {
              description: 'Job still queued/running.',
              headers: {
                Location: {
                  schema: { type: 'string' },
                  description:
                    'Same polling endpoint path (thread id must be sent separately as query/body).',
                },
                'Retry-After': {
                  schema: { type: 'string' },
                  description: 'Recommended seconds before next poll.',
                },
              },
            },
            '200': {
              description: 'Verification finished (succeeded or failed).',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_VERIFY_RESPONSE_SCHEMA,
                  examples: {
                    verificationSucceededWithEvidence: {
                      summary: 'Verification succeeded with two VCs and evidence',
                      value: VERIFY_RESPONSE_SUCCESS_EXAMPLE,
                    },
                    verificationFailed: {
                      summary: 'Verification failed',
                      value: VERIFY_RESPONSE_FAILED_EXAMPLE,
                    },
                  },
                },
              },
            },
            '400': {
              description: 'Invalid request.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
            '500': {
              description: 'Internal error.',
              content: {
                'application/didcomm-plain+json': {
                  schema: DIDCOMM_ERROR_RESPONSE_SCHEMA,
                },
              },
            },
          },
        },
      },
    },
  } as const;
  return normalizeOpenApiDidcommTypeExamples(spec);
}
