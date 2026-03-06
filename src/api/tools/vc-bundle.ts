import { randomUUID } from 'node:crypto';
import type {
  EvidenceDocumentDLT,
} from 'gdc-common-utils-ts/models/oidc4ida.document.model';
import type {
  EvidenceElectronicSignatureDLT,
  EvidenceObjectDLT,
} from 'gdc-common-utils-ts/models/oidc4ida.evidence.model';
import type {
  VerifiableCredentialV2,
} from 'gdc-common-utils-ts/models/verifiable-credential';
import type {
  OperationOutcomeResource,
  VerifyBundleResponse,
  VerifyResult,
  VerifyRouteContext,
} from '../types.ts';
import { attachProofToCredential, resolveIcaIssuerDid } from './ica-identity.ts';

function normalizeDnKey(raw: string): string {
  return raw.trim().toUpperCase().replace(/\s+/g, '');
}

function parseDistinguishedName(dn: string): Record<string, string> {
  const output: Record<string, string> = {};
  const trimmed = dn.trim();
  if (!trimmed) return output;

  const tokens = trimmed.startsWith('/')
    ? trimmed.split('/').filter(Boolean)
    : trimmed.split(',').map((part) => part.trim()).filter(Boolean);

  for (const token of tokens) {
    const separator = token.indexOf('=');
    if (separator <= 0) continue;
    const key = normalizeDnKey(token.slice(0, separator));
    const value = token.slice(separator + 1).trim();
    if (!key || !value) continue;
    if (!(key in output)) {
      output[key] = value;
    }
  }
  return output;
}

function firstDefined(...values: Array<string | undefined>): string | undefined {
  for (const value of values) {
    if (!value) continue;
    const trimmed = value.trim();
    if (trimmed) return trimmed;
  }
  return undefined;
}

function parseOrganizationTaxId(subjectDn: Record<string, string>): string | undefined {
  return firstDefined(subjectDn.ORGANIZATIONIDENTIFIER, subjectDn['OID.2.5.4.97']);
}

function determineAssuranceLevel(result: VerifyResult): 'low' | 'medium' | 'high' {
  if (
    result.signatureValid &&
    result.chainValid &&
    result.templateMatch &&
    result.revocationStatus === 'good'
  ) {
    return 'high';
  }
  if (result.signatureValid && result.chainValid) {
    return 'medium';
  }
  return 'low';
}

function hexToBase64(hex: string): string {
  if (!hex) return '';
  return Buffer.from(hex, 'hex').toString('base64');
}

function normalizeDigestAlgorithmForEvidence(alg: string | undefined): string {
  const normalized = (alg || '').trim().toLowerCase();
  if (!normalized) return 'sha3-384';
  return normalized;
}

function buildOperationOutcome(
  severity: 'information' | 'warning' | 'error' | 'fatal',
  code: string,
  diagnostics: string,
): OperationOutcomeResource {
  return {
    resourceType: 'OperationOutcome',
    issue: [{ severity, code, diagnostics }],
  };
}

function buildOidc4IdaEvidence(
  route: VerifyRouteContext,
  result: VerifyResult,
  serialNumber: string,
  verifierOrganization: string,
): EvidenceObjectDLT[] {
  const attachmentPayload = {
    profile: 'oidc4ida-evidence-v1',
    assuranceLevel: determineAssuranceLevel(result),
    verificationResult: result.ok ? 'valid' : 'invalid',
    signatureValid: result.signatureValid,
    chainValid: result.chainValid,
    revocationStatus: result.revocationStatus,
    signerSubject: result.signerSubject,
    signerIssuer: result.signerIssuer,
    digest: result.digest,
    hashes: result.hashes,
    templateUrl: result.templateUrl,
    templateMatch: result.templateMatch,
    auditDocument: result.auditDocument,
    notes: result.notes,
  };

  const evidenceDigestAlg = normalizeDigestAlgorithmForEvidence(result.digest?.alg);
  const evidenceDigestHex = result.digest?.signedPdfHex || result.hashes.signedPdfSha256Hex;

  const signatureEvidence: EvidenceElectronicSignatureDLT = {
    type: 'electronic_signature',
    signature_type: 'pades',
    issuer: result.signerIssuer || verifierOrganization,
    serial_number: serialNumber,
    created_at: result.verifiedAt,
    attachments: [
      {
        content_type: 'application/json',
        content: Buffer.from(JSON.stringify(attachmentPayload)).toString('base64'),
      },
    ],
  };

  const auditTxnRef = result.auditDocument
    ? `audit:${result.auditDocument.provider}:${result.auditDocument.objectKey}`
    : undefined;

  const documentEvidence: EvidenceDocumentDLT = {
    type: 'document',
    method: 'eid',
    time: result.verifiedAt,
    verifier: {
      organization: verifierOrganization,
    },
    check_details: [
      {
        check_method: 'vdig',
        organization: verifierOrganization,
        ...(auditTxnRef ? { txn: auditTxnRef } : {}),
        time: result.verifiedAt,
      },
      {
        check_method: 'vcrypt',
        organization: verifierOrganization,
        ...(auditTxnRef ? { txn: auditTxnRef } : {}),
        time: result.verifiedAt,
      },
    ],
    attachments: {
      digest: {
        alg: evidenceDigestAlg,
        value: hexToBase64(evidenceDigestHex),
      },
      url: result.auditDocument?.attachmentUrl || `urn:uuid:${randomUUID()}`,
    },
    document_details: {
      type: 'terms-and-conditions',
      document_number: route.resourceType,
      ...(serialNumber ? { serial_number: serialNumber } : {}),
      issuer: {
        id: verifierOrganization,
        type: 'TrustServiceProvider',
        country_code: route.jurisdiction.toUpperCase(),
        jurisdiction: route.jurisdiction.toUpperCase(),
      },
    },
  };

  return [
    signatureEvidence,
    documentEvidence,
  ];
}

export function buildVerificationVcBundle(route: VerifyRouteContext, result: VerifyResult): VerifyBundleResponse {
  const subjectDn = parseDistinguishedName(result.signerSubject);
  const issuerDid = resolveIcaIssuerDid();
  const orgLegalName = firstDefined(subjectDn.O, subjectDn.OU);
  const organizationTaxId = parseOrganizationTaxId(subjectDn);
  const representativeName =
    [subjectDn.GN || subjectDn.GIVENNAME, subjectDn.SN || subjectDn.SURNAME]
      .filter(Boolean)
      .join(' ')
    || subjectDn.CN
    || 'Representative from certificate';
  const personIdentifier = firstDefined(subjectDn.SERIALNUMBER, subjectDn['OID.2.5.4.5']);
  const country = subjectDn.C || subjectDn.COUNTRYNAME || undefined;
  const serialNumber =
    result.signerCertificateSerialNumber
    || personIdentifier
    || `cert:${route.tenantId}:${route.resourceType}`;
  const verifierOrganization = issuerDid;
  const evidence = buildOidc4IdaEvidence(route, result, serialNumber, verifierOrganization);

  const organizationSubject: Record<string, unknown> = {
    id: organizationTaxId
      ? `urn:organization:taxid:${organizationTaxId}`
      : `urn:organization:certificate:${route.tenantId}`,
    '@type': 'Organization',
  };
  if (orgLegalName) {
    organizationSubject.legalName = orgLegalName;
  }
  if (organizationTaxId) {
    organizationSubject.taxID = organizationTaxId;
  }
  if (country) {
    organizationSubject.address = { '@type': 'PostalAddress', addressCountry: country };
  }

  const unsignedOrganizationVc: VerifiableCredentialV2 = {
    id: `urn:uuid:${randomUUID()}`,
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    type: ['VerifiableCredential', 'OrganizationCredential'],
    issuer: issuerDid,
    validFrom: result.verifiedAt,
    credentialSubject: organizationSubject,
    evidence,
  };

  const organizationRef: Record<string, unknown> = {
    '@type': 'Organization',
  };
  if (orgLegalName) {
    organizationRef.legalName = orgLegalName;
  }
  if (organizationTaxId) {
    organizationRef.taxID = organizationTaxId;
  }

  const personSubject: Record<string, unknown> = {
    id: personIdentifier
      ? `urn:person:certificate:${personIdentifier}`
      : `urn:person:certificate:${route.tenantId}`,
    '@type': 'Person',
    name: representativeName,
    roleName: 'legal-representative',
    memberOf: organizationRef,
  };
  if (subjectDn.GN || subjectDn.GIVENNAME) {
    personSubject.givenName = subjectDn.GN || subjectDn.GIVENNAME;
  }
  if (subjectDn.SN || subjectDn.SURNAME) {
    personSubject.familyName = subjectDn.SN || subjectDn.SURNAME;
  }
  if (personIdentifier) {
    personSubject.identifier = personIdentifier;
  }
  if (country) {
    personSubject.nationality = country;
  }

  const unsignedPersonVc: VerifiableCredentialV2 = {
    id: `urn:uuid:${randomUUID()}`,
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    type: ['VerifiableCredential', 'PersonCredential', 'LegalRepresentativeCredential'],
    issuer: issuerDid,
    validFrom: result.verifiedAt,
    credentialSubject: personSubject,
    evidence,
  };

  const organizationVc = attachProofToCredential(unsignedOrganizationVc, route);
  const personVc = attachProofToCredential(unsignedPersonVc, route);

  const entryOutcome = buildOperationOutcome(
    result.ok ? 'information' : 'warning',
    result.ok ? 'informational' : 'processing',
    result.ok ? 'Verification completed.' : 'Verification completed with warnings.',
  );

  return {
    resourceType: 'Bundle',
    type: 'batch-response',
    issues: entryOutcome,
    total: 2,
    data: [
      {
        type: 'Organization-verification-v1.0',
        response: {
          status: '200',
          outcome: buildOperationOutcome(
            result.ok ? 'information' : 'warning',
            result.ok ? 'informational' : 'processing',
            result.ok
              ? 'Organization credential extracted from verified document.'
              : 'Organization credential extracted with verification warnings.',
          ),
        },
        resource: organizationVc,
      },
      {
        type: 'LegalRepresentative-verification-v1.0',
        response: {
          status: '200',
          outcome: buildOperationOutcome(
            result.ok ? 'information' : 'warning',
            result.ok ? 'informational' : 'processing',
            result.ok
              ? 'Legal representative credential extracted from verified document.'
              : 'Legal representative credential extracted with verification warnings.',
          ),
        },
        resource: personVc,
      },
    ],
  };
}
