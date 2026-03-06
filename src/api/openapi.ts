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
    result: VERIFY_RESULT_SCHEMA,
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
    { required: ['alg', 'privateKeyPem'] },
  ],
} as const;

const ACTIVATE_REQUEST_BODY_SCHEMA = {
  type: 'object',
  description: 'Provide either body.key (single key) or body.data[] (multiple keys).',
  properties: {
    key: ACTIVATE_KEY_SCHEMA,
    data: {
      type: 'array',
      minItems: 1,
      items: ACTIVATE_KEY_DATA_ITEM_SCHEMA,
    },
  },
  oneOf: [
    { required: ['key'] },
    { required: ['data'] },
  ],
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

const ADD_EVIDENCE_DATA_ITEM_SCHEMA = {
  type: 'object',
  required: ['evidence'],
  properties: {
    issuedCredentialRecordId: { type: 'string' },
    operatorDid: { type: 'string' },
    evidence: OIDC4IDA_EVIDENCE_SCHEMA,
  },
  additionalProperties: false,
} as const;

const ADD_EVIDENCE_REQUEST_BODY_SCHEMA = {
  type: 'object',
  description: 'Provide either body.evidence (single record) or body.data[] (batch).',
  properties: {
    issuedCredentialRecordId: { type: 'string' },
    operatorDid: { type: 'string' },
    evidence: OIDC4IDA_EVIDENCE_SCHEMA,
    data: {
      type: 'array',
      minItems: 1,
      items: ADD_EVIDENCE_DATA_ITEM_SCHEMA,
    },
  },
  oneOf: [
    { required: ['evidence'] },
    { required: ['data'] },
  ],
} as const;

const ADD_EVIDENCE_DIDCOMM_REQUEST_SCHEMA = {
  type: 'object',
  required: ['type', 'body'],
  properties: {
    jti: { type: 'string' },
    thid: { type: 'string' },
    type: { type: 'string' },
    body: ADD_EVIDENCE_REQUEST_BODY_SCHEMA,
  },
} as const;

const ISSUE_CREDENTIAL_REQUEST_BODY_SCHEMA = {
  type: 'object',
  required: ['credential'],
  properties: {
    credential: { type: 'object', additionalProperties: true },
    evidence: {
      type: 'array',
      items: { type: 'object', additionalProperties: true },
    },
  },
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
  properties: {
    issuedCredentialRecordId: { type: 'string' },
    credentialId: { type: 'string' },
    subjectId: { type: 'string' },
  },
  anyOf: [
    { required: ['issuedCredentialRecordId'] },
    { required: ['credentialId'] },
    { required: ['subjectId'] },
  ],
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
  properties: {
    issuedCredentialRecordId: { type: 'string' },
    credentialId: { type: 'string' },
    subjectId: { type: 'string' },
    reason: { type: 'string' },
    revokedBy: { type: 'string' },
  },
  anyOf: [
    { required: ['issuedCredentialRecordId'] },
    { required: ['credentialId'] },
    { required: ['subjectId'] },
  ],
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

const VERIFY_RESPONSE_SUCCESS_EXAMPLE = {
  jti: 'urn:uuid:verify-resp-001',
  iss: 'did:web:localhost%3A3310',
  aud: 'did:web:localhost%3A3310',
  thid: 'verify-terms-001',
  type: 'application/bundle-api+json',
  body: {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 2,
    result: {
      ok: true,
      verifiedAt: '2026-03-06T12:00:00.000Z',
      templateUrl:
        'https://raw.githubusercontent.com/Global-DataCare/terms/refs/heads/main/dataspace/animal-care/es/202603051133/terms.pdf',
      templateMatch: true,
      signatureValid: true,
      chainValid: true,
      revocationStatus: 'good',
      digest: {
        alg: 'sha3-384',
        signedPdfHex: 'a1b2c3',
        unsignedPdfHex: 'd4e5f6',
        templateHex: '0a0b0c',
      },
      signerCertificateSerialNumber: '1234567890',
      signerSubject: '/C=ES/O=Acme Health SL/CN=Juan Perez',
      signerIssuer: '/C=ES/O=FNMT-RCM/OU=AC REPRESENTACION',
      hashes: {
        signedPdfSha256Hex: '11aa22bb',
        unsignedPdfSha256Hex: '33cc44dd',
        templateSha256Hex: '55ee66ff',
      },
      notes: ['Verification completed.'],
    },
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
          validFrom: '2026-03-06T12:00:00.000Z',
          credentialSubject: {
            id: 'urn:organization:taxid:VATES-A12345678',
            '@type': 'Organization',
            legalName: 'Acme Health SL',
            taxID: 'VATES-A12345678',
            address: {
              '@type': 'PostalAddress',
              addressCountry: 'ES',
            },
          },
          evidence: [
            {
              type: 'electronic_signature',
              signature_type: 'pades',
              issuer: '/C=ES/O=FNMT-RCM/OU=AC REPRESENTACION',
              serial_number: '1234567890',
              created_at: '2026-03-06T12:00:00.000Z',
              attachments: [
                {
                  content_type: 'application/json',
                  content: 'eyJ2ZXJpZmljYXRpb25SZXN1bHQiOiJ2YWxpZCJ9',
                },
              ],
            },
            {
              type: 'document',
              method: 'eid',
              time: '2026-03-06T12:00:00.000Z',
              verifier: {
                organization: 'did:web:localhost%3A3310',
              },
              check_details: [
                {
                  check_method: 'vdig',
                  organization: 'did:web:localhost%3A3310',
                  time: '2026-03-06T12:00:00.000Z',
                },
                {
                  check_method: 'vcrypt',
                  organization: 'did:web:localhost%3A3310',
                  time: '2026-03-06T12:00:00.000Z',
                },
              ],
              attachments: {
                digest: {
                  alg: 'sha3-384',
                  value: 'q80=',
                },
                url: 'urn:uuid:audit-object-001',
              },
              document_details: {
                type: 'terms-and-conditions',
                document_number: '202603051133',
                serial_number: '1234567890',
                issuer: {
                  id: 'did:web:localhost%3A3310',
                  type: 'TrustServiceProvider',
                  country_code: 'ES',
                  jurisdiction: 'ES',
                },
              },
            },
          ],
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
          validFrom: '2026-03-06T12:00:00.000Z',
          credentialSubject: {
            id: 'urn:person:certificate:99999999R',
            '@type': 'Person',
            name: 'Juan Perez',
            roleName: 'legal-representative',
            memberOf: {
              '@type': 'Organization',
              legalName: 'Acme Health SL',
              taxID: 'VATES-A12345678',
            },
            identifier: '99999999R',
            nationality: 'ES',
          },
          evidence: [
            {
              type: 'electronic_signature',
              signature_type: 'pades',
              issuer: '/C=ES/O=FNMT-RCM/OU=AC REPRESENTACION',
              serial_number: '1234567890',
              created_at: '2026-03-06T12:00:00.000Z',
              attachments: [
                {
                  content_type: 'application/json',
                  content: 'eyJ2ZXJpZmljYXRpb25SZXN1bHQiOiJ2YWxpZCJ9',
                },
              ],
            },
            {
              type: 'document',
              method: 'eid',
              time: '2026-03-06T12:00:00.000Z',
              verifier: {
                organization: 'did:web:localhost%3A3310',
              },
              check_details: [
                {
                  check_method: 'vdig',
                  organization: 'did:web:localhost%3A3310',
                  time: '2026-03-06T12:00:00.000Z',
                },
                {
                  check_method: 'vcrypt',
                  organization: 'did:web:localhost%3A3310',
                  time: '2026-03-06T12:00:00.000Z',
                },
              ],
              attachments: {
                digest: {
                  alg: 'sha3-384',
                  value: 'q80=',
                },
                url: 'urn:uuid:audit-object-001',
              },
              document_details: {
                type: 'terms-and-conditions',
                document_number: '202603051133',
                serial_number: '1234567890',
                issuer: {
                  id: 'did:web:localhost%3A3310',
                  type: 'TrustServiceProvider',
                  country_code: 'ES',
                  jurisdiction: 'ES',
                },
              },
            },
          ],
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
          diagnostics: 'Credential record stored.',
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
                diagnostics: 'Credential record stored.',
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
          diagnostics: 'Credential status resolved.',
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
                diagnostics: 'Credential status resolved.',
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
          diagnostics: 'Credential status set to revoked.',
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
                diagnostics: 'Credential status set to revoked.',
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

export function buildIcaVerifyOpenApiSpec() {
  return {
    openapi: '3.1.0',
    info: {
      title: 'DataSpace ICA Verification API',
      version: '1.0.0',
      description:
        'Asynchronous API for verifying FNMT-signed PDF terms, persisting network evidence/credentials, checking credential status, revoking credentials, and activating ICA cryptographic keys before production issuance. Current deployment is monotenant and uses alternateName "ica".',
    },
    servers: [{ url: 'http://localhost:3310' }],
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
        name: 'network/credentials',
        description:
          'Credential lifecycle over network records: issue, status and revoke with async polling (_issue, _status, _revoke + *_response).',
      },
    ],
    paths: {
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
                },
              },
            },
          },
        },
      },
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate': {
        post: {
          tags: ['entity/keys/credentials'],
          summary: 'Activate ICA signing key',
          description:
            'Starts async activation/import of one or more signing keys and returns polling location. For a runnable deterministic test payload use npm run api:example:activate.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
                      jti: 'activate-req-002',
                      thid: 'activate-signing-key-002',
                      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
                      body: {
                        data: [
                          {
                            key: {
                              kid: 'ica-es384-20260305',
                              alg: 'ES384',
                              privateKeyPem: '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----',
                            },
                          },
                          {
                            key: {
                              kid: 'ica-es256k-20260305',
                              alg: 'ES256K',
                              privateKeyPem: '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----',
                            },
                          },
                        ],
                      },
                    },
                  },
                  activateEs384: {
                    summary: 'Activate ES384 key + certificate chain',
                    value: {
                      jti: 'activate-req-001',
                      thid: 'activate-signing-key-001',
                      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
                      body: {
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
            'Starts async persistence of an evidence record (`address`, `official-registry`, `qualification`, etc.) and returns polling location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
                    summary: 'Add single OIDC4IDA evidence (legacy body.evidence)',
                    value: {
                      jti: 'evidence-add-001',
                      thid: 'evidence-add-001',
                      type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
                      body: {
                        issuedCredentialRecordId: 'urn:uuid:issued-record-001',
                        operatorDid: 'did:web:localhost%3A3310#employee-01',
                        evidence: {
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
                      },
                    },
                  },
                  addOfficialRegistryEvidenceBatch: {
                    summary: 'Add evidence batch with body.data[]',
                    value: {
                      jti: 'evidence-add-002',
                      thid: 'evidence-add-002',
                      type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
                      body: {
                        data: [
                          {
                            issuedCredentialRecordId: 'urn:uuid:issued-record-001',
                            operatorDid: 'did:web:localhost%3A3310#employee-01',
                            evidence: {
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
                            },
                          },
                          {
                            issuedCredentialRecordId: 'urn:uuid:issued-record-001',
                            operatorDid: 'did:web:localhost%3A3310#employee-02',
                            evidence: {
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
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue': {
        post: {
          tags: ['network/credentials'],
          summary: 'Issue credential record',
          description:
            'Starts async persistence of an issued credential plus attached evidence records and returns polling location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
                    summary: 'Issue member credential with extra evidence',
                    value: {
                      jti: 'credential-issue-001',
                      thid: 'credential-issue-001',
                      type: 'https://globaldatacare.es/didcomm/ica/network/credentials/issue-request/v1',
                      body: {
                        credential: {
                          id: 'urn:uuid:vc-member-001',
                          type: ['VerifiableCredential', 'MemberCredential'],
                          issuer: 'did:web:localhost%3A3310',
                          credentialSubject: {
                            id: 'mailto:member@example.org',
                            membershipId: 'COL-0001',
                          },
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
            'Starts async credential status lookup (good/revoked/unknown) for a network credential and returns polling location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
                    summary: 'Query status by credential id',
                    value: {
                      jti: 'credential-status-001',
                      thid: 'credential-status-001',
                      type: 'https://globaldatacare.es/didcomm/ica/network/credentials/status-request/v1',
                      body: {
                        credentialId: 'urn:uuid:vc-member-001',
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
            'Starts async revocation update for a network credential (sets credentialStatus=revoked) and returns polling location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
                    summary: 'Revoke by credential id with operator',
                    value: {
                      jti: 'credential-revoke-001',
                      thid: 'credential-revoke-001',
                      type: 'https://globaldatacare.es/didcomm/ica/network/credentials/revoke-request/v1',
                      body: {
                        credentialId: 'urn:uuid:vc-member-001',
                        reason: 'membership-terminated',
                        revokedBy: 'did:web:localhost%3A3310#employee-02',
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
      '/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify': {
        post: {
          tags: ['terms/pdf'],
          summary: 'Submit PDF verification job',
          description: 'Starts an async verification job and returns polling location in headers.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
            },
            {
              name: 'resourceType',
              in: 'path',
              required: true,
              schema: { type: 'string', pattern: '^(?:\\d{12}|test-\\d{12})$', example: '202630011200' },
              description:
                'Document version token. Production: yyyyddmmhhmm. Testing: test-yyyyddmmhhmm (requires ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX=true).',
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
                      jti: 'verify-req-001',
                      thid: 'verify-terms-001',
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
                  viaBase64: {
                    summary: 'DIDComm con PDF en base64',
                    value: {
                      jti: 'verify-req-002',
                      thid: 'verify-terms-002',
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
                },
                schema: {
                  type: 'object',
                  required: ['type', 'attachments'],
                  properties: {
                    jti: { type: 'string' },
                    thid: { type: 'string' },
                    type: { type: 'string' },
                    body: { type: 'object', additionalProperties: true },
                    attachments: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          id: { type: 'string' },
                          media_type: { type: 'string', example: 'application/pdf' },
                          data: {
                            type: 'object',
                            properties: {
                              base64: {
                                type: 'string',
                                description: 'PDF codificado en base64.',
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
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response': {
        post: {
          tags: ['entity/keys/credentials'],
          summary: 'Poll signing-key activation result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
            },
            {
              name: 'thid',
              in: 'query',
              required: false,
              schema: { type: 'string' },
              description: 'Activation thread id. Can also be sent in body as thid or jti.',
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
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
              description: 'Evidence add thread id. Can also be sent in body as thid or jti.',
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
      '/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response': {
        post: {
          tags: ['network/credentials'],
          summary: 'Poll credential issue result',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
              description: 'Credential issue thread id. Can also be sent in body as thid or jti.',
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
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
              description: 'Credential status thread id. Can also be sent in body as thid or jti.',
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
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
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
              description: 'Credential revoke thread id. Can also be sent in body as thid or jti.',
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
      '/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate': {
        post: {
          tags: ['entity/keys/credentials'],
          summary: 'Rotate keys for credential issuance (stub)',
          description:
            'Reserved endpoint for rotating ICA keys used in credential issuance. Current implementation returns 202 with polling Location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
            },
          ],
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
            'Reserved endpoint for rotating keys used in communication messages. Current implementation returns 202 with polling Location.',
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
            },
          ],
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
          parameters: [
            {
              name: 'jurisdiction',
              in: 'path',
              required: true,
              schema: { type: 'string', example: 'ES' },
            },
            {
              name: 'sector',
              in: 'path',
              required: true,
              schema: { type: 'string', enum: ['animal-care', 'health-care'] },
            },
            {
              name: 'resourceType',
              in: 'path',
              required: true,
              schema: { type: 'string', pattern: '^(?:\\d{12}|test-\\d{12})$', example: '202630011200' },
              description:
                'Document version token. Production: yyyyddmmhhmm. Testing: test-yyyyddmmhhmm (requires ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX=true).',
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
}
