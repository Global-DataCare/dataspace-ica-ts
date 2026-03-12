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

  const normalized = trimmed.replace(/\r/g, '');
  const tokens = normalized.startsWith('/')
    ? normalized.split('/').filter(Boolean)
    : normalized.split(/[,\n]+/).map((part) => part.trim()).filter(Boolean);

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

const ANNEX_ORGANIZATION_ADDITIONAL_TYPE = 'organization.additionalType';
const ANNEX_ORGANIZATION_SAME_AS = 'organization.sameAs';
const ANNEX_ORGANIZATION_URL = 'organization.url';
const ANNEX_ORGANIZATION_ALTERNATE_NAME = 'organization.alternateName';
const ANNEX_ORGANIZATION_REGISTRATION_NUMBER = 'organization.registrationNumber';
const ANNEX_ORGANIZATION_EMAIL = 'organization.email';
const ANNEX_PERSON_EMAIL = 'person.email';
const ANNEX_PERSON_ALTERNATE_NAME = 'person.alternateName';
const ANNEX_PERSON_ADDITIONAL_TYPE = 'person.additionalType';

function getAnnexField(result: VerifyResult, name: string): string | undefined {
  const directValue = result.annexFormFields?.[name];
  const value = directValue !== undefined
    ? directValue
    : Object.entries(result.annexFormFields || {}).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
  const normalized = typeof value === 'string' ? value.trim() : '';
  return normalized || undefined;
}

function getAnnexOrganizationDid(result: VerifyResult): string | undefined {
  const candidate = getAnnexField(result, ANNEX_ORGANIZATION_SAME_AS);
  if (!candidate) return undefined;
  return candidate.startsWith('did:web:') ? candidate : undefined;
}

function normalizeOrganizationUrl(value: string | undefined): string | undefined {
  const trimmed = (value || '').trim();
  if (!trimmed) return undefined;
  return trimmed
    .replace(/^https?:\/\//i, '')
    .replace(/\/+$/g, '');
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

function parseCommaSeparatedUrls(raw: string): string[] {
  return raw
    .split(',')
    .map((value) => value.trim())
    .filter((value) => /^https?:\/\//i.test(value));
}

function extractVerificationUrls(notes: string[], prefix: string): string[] {
  const urls: string[] = [];
  for (const note of notes) {
    if (!note.startsWith(prefix)) continue;
    const raw = note.slice(prefix.length).trim();
    urls.push(...parseCommaSeparatedUrls(raw));
  }
  return urls;
}

function normalizeForMatching(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function filterIntermediateUrlsByIssuer(urls: string[], signerIssuer: string): string[] {
  if (!urls.length) return urls;
  const issuer = normalizeForMatching(signerIssuer);
  const targetKeyword = issuer.includes('ac representacion')
    ? 'representacion'
    : issuer.includes('ac sector publico')
      ? 'sector_publico'
      : issuer.includes('ac fnmt usuarios')
        ? 'usuarios'
        : '';
  if (!targetKeyword) return urls;
  const filtered = urls.filter((url) => normalizeForMatching(url).includes(targetKeyword));
  return filtered.length ? filtered : urls;
}

function normalizeRevocationChecksForEvidence(
  checks: NonNullable<VerifyResult['revocationDebug']>['checks'],
  finalStatus: VerifyResult['revocationStatus'],
): Array<{
  phase: string;
  status: string;
  url?: string;
  httpStatus?: number;
  message?: string;
}> {
  if (!checks.length) return [];
  const fallbackSucceeded = checks.some((check) =>
    check.phase === 'verify'
    && check.status === 'ok'
    && (check.message || '').includes('mode=-crl_check fallback')
  );

  return checks
    .filter((check) => {
      if (finalStatus !== 'good' || !fallbackSucceeded) return true;
      if (check.phase !== 'verify') return true;
      if (check.status !== 'verify_error') return true;
      return !(check.message || '').includes('mode=-crl_check_all');
    })
    .map((check) => ({
      phase: check.phase,
      status: check.status,
      ...(check.url ? { url: check.url } : {}),
      ...(check.httpStatus !== undefined ? { httpStatus: check.httpStatus } : {}),
      ...(check.message ? { message: check.message } : {}),
    }));
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
  const evidenceDigestAlg = normalizeDigestAlgorithmForEvidence(result.digest?.alg);
  const evidenceDigestHex = result.digest?.signedPdfHex || result.hashes.signedPdfSha256Hex;
  const notes = result.notes || [];
  const trustAnchors = extractVerificationUrls(notes, 'FNMT root loaded from ');
  const intermediates = filterIntermediateUrlsByIssuer(
    extractVerificationUrls(notes, 'FNMT intermediate loaded from '),
    result.signerIssuer || '',
  );
  const revocationSources = extractVerificationUrls(notes, 'CRL loaded from ');
  const revocationChecks = normalizeRevocationChecksForEvidence(
    result.revocationDebug?.checks || [],
    result.revocationStatus,
  );

  // Keep evidence attachment compact; detailed debug stays in Bundle.result.
  const attachmentPayload = {
    profile: 'oidc4ida-evidence-v1',
    assuranceLevel: determineAssuranceLevel(result),
    verificationResult: result.ok ? 'valid' : 'invalid',
    signatureValid: result.signatureValid,
    chainValid: result.chainValid,
    revocationStatus: result.revocationStatus,
    signerSubject: result.signerSubject,
    signerIssuer: result.signerIssuer,
    verificationTrace: {
      cmsSignatureValidated: notes.includes('CMS signature and authenticated attributes validated.'),
      chainValidated: notes.includes('Signer chain validated against FNMT root/intermediate.'),
      ...(trustAnchors.length ? { trustAnchors } : {}),
      ...(intermediates.length ? { intermediates } : {}),
      ...(revocationSources.length ? { revocationSources } : {}),
      ...(revocationChecks.length ? { revocationChecks } : {}),
    },
  };
  const compactAttachmentJson = JSON.stringify(attachmentPayload);
  const compactAttachmentDataUri = `data:application/json;base64,${Buffer.from(compactAttachmentJson).toString('base64')}`;

  const signatureEvidence: EvidenceElectronicSignatureDLT = {
    type: 'electronic_signature',
    signature_type: 'pades',
    issuer: result.signerIssuer || verifierOrganization,
    serial_number: serialNumber,
    created_at: result.verifiedAt,
    attachments: [
      {
        content_type: 'application/json',
        content: compactAttachmentDataUri,
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
  if (result.annexFormFields && Object.keys(result.annexFormFields).length) {
    const details = documentEvidence.document_details as unknown as Record<string, unknown>;
    details.annexFormFields = result.annexFormFields;
  }

  return [
    signatureEvidence,
    documentEvidence,
  ];
}

export function buildVerificationVcBundle(
  route: VerifyRouteContext,
  result: VerifyResult,
  issuerDidInput?: string,
): VerifyBundleResponse {
  const subjectDn = parseDistinguishedName(result.signerSubject);
  const issuerDid = (issuerDidInput || '').trim() || resolveIcaIssuerDid();

  const orgLegalName = firstDefined(subjectDn.O, subjectDn.OU);
  const organizationDid = getAnnexOrganizationDid(result);
  const organizationAdditionalType = getAnnexField(result, ANNEX_ORGANIZATION_ADDITIONAL_TYPE);
  const organizationAlternateName = getAnnexField(result, ANNEX_ORGANIZATION_ALTERNATE_NAME);
  const organizationRegistrationNumber = getAnnexField(result, ANNEX_ORGANIZATION_REGISTRATION_NUMBER);
  const organizationUrl = normalizeOrganizationUrl(getAnnexField(result, ANNEX_ORGANIZATION_URL));
  const organizationEmail = getAnnexField(result, ANNEX_ORGANIZATION_EMAIL);
  const organizationTaxId = parseOrganizationTaxId(subjectDn);
  const representativeName =
    [subjectDn.GN || subjectDn.GIVENNAME, subjectDn.SN || subjectDn.SURNAME]
      .filter(Boolean)
      .join(' ')
    || subjectDn.CN
    || 'Representative from certificate';
  const personIdentifier = firstDefined(subjectDn.SERIALNUMBER, subjectDn['OID.2.5.4.5']);
  const personEmail = firstDefined(
    getAnnexField(result, ANNEX_PERSON_EMAIL),
    subjectDn.EMAILADDRESS,
    subjectDn.EMAIL,
    subjectDn.E,
  );
  const personAlternateName = getAnnexField(result, ANNEX_PERSON_ALTERNATE_NAME);
  const personAdditionalType = getAnnexField(result, ANNEX_PERSON_ADDITIONAL_TYPE);
  const country = subjectDn.C || subjectDn.COUNTRYNAME || undefined;
  const serialNumber =
    result.signerCertificateSerialNumber
    || personIdentifier
    || `cert:${route.tenantId}:${route.resourceType}`;
  const verifierOrganization = issuerDid;
  const evidence = buildOidc4IdaEvidence(
    route,
    result,
    serialNumber,
    verifierOrganization,
  );

  const organizationSubject: Record<string, unknown> = {
    id: organizationDid || (organizationTaxId
      ? `urn:organization:taxid:${organizationTaxId}`
      : `urn:organization:certificate:${route.tenantId}`),
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
  if (organizationAdditionalType) {
    organizationSubject.additionalType = organizationAdditionalType;
  }
  if (organizationDid) {
    organizationSubject.sameAs = organizationDid;
  }
  if (organizationAlternateName) {
    organizationSubject.alternateName = organizationAlternateName;
  }
  if (organizationRegistrationNumber) {
    organizationSubject.registrationNumber = organizationRegistrationNumber;
  }
  if (organizationEmail) {
    organizationSubject.email = organizationEmail;
  }
  if (organizationUrl) {
    organizationSubject.url = organizationUrl;
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
      ? `urn:person:identifier:${personIdentifier}`
      : `urn:person:identifier:${route.tenantId}`,
    '@type': 'Person',
    name: representativeName,
    hasOccupation: {
      '@type': 'Occupation',
      name: 'LegalRepresentative',
      identifier: 'urn:ilo:ilostat:isco-08:1120',
    },
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
  if (personEmail) {
    personSubject.email = personEmail;
  }
  if (personAlternateName) {
    personSubject.alternateName = personAlternateName;
  }
  if (personAdditionalType) {
    personSubject.additionalType = personAdditionalType;
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

  const organizationVc = attachProofToCredential(unsignedOrganizationVc, route, issuerDid);
  const personVc = attachProofToCredential(unsignedPersonVc, route, issuerDid);

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
