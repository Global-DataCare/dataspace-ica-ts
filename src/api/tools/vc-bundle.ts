import { createHash, randomUUID } from 'node:crypto';
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
import {
  serializeServiceCapabilityTokens,
  ServiceCapability,
} from 'gdc-common-utils-ts/constants/service-capabilities';
import { toJwkThumbprintSha256Urn } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import type {
  OperationOutcomeResource,
  VerifyBundleResponse,
  VerifyResult,
  VerifyRouteContext,
} from '../types.ts';
import { attachProofToCredential, resolveVcIssuerDid } from './ica-identity.ts';
import { buildOrganizationDidFromTaxId } from './organization-did.ts';
import {
  multibase58CidV1RawSha3_256Hex,
  multibase58CidV1RawSha3_384Hex,
  normalizeSameAsHash,
} from './multihash.ts';
import { loadIcaSecurityConfigFromEnv } from '../security-mode.ts';

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
    : normalized
      .split(/(?<!\\),|\n+/)
      .map((part) => part.trim())
      .filter(Boolean);

  let lastParsedKey: string | undefined;
  for (const token of tokens) {
    const separator = token.indexOf('=');
    if (separator <= 0) {
      // Some DN emitters split escaped commas in values as separate fragments
      // (e.g. "O=ACME\\, S.L." => ["O=ACME\\", "S.L."]).
      // Stitch the fragment back to the previous key value.
      if (lastParsedKey && output[lastParsedKey]) {
        output[lastParsedKey] = `${output[lastParsedKey]}, ${token.trim()}`;
      }
      continue;
    }
    const key = normalizeDnKey(token.slice(0, separator));
    const value = token
      .slice(separator + 1)
      .trim()
      .replace(/\\,/g, ',')
      .replace(/\\\\/g, '\\');
    if (!key || !value) continue;
    if (!(key in output)) {
      output[key] = value;
    }
    lastParsedKey = key;
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

function parseOrganizationTaxIdFromPayload(
  route: VerifyRouteContext,
  payload: Record<string, unknown> | undefined,
): string | undefined {
  const raw = firstDefined(
    typeof payload?.taxID === 'string' ? payload.taxID : undefined,
    typeof payload?.taxId === 'string' ? payload.taxId : undefined,
    typeof payload?.unsecureFormOrganizationTaxID === 'string' ? payload.unsecureFormOrganizationTaxID : undefined,
    typeof payload?.unsecureFormOrganizationTaxId === 'string' ? payload.unsecureFormOrganizationTaxId : undefined,
    typeof payload?.unsecureFormOrganizationCif === 'string' ? payload.unsecureFormOrganizationCif : undefined,
    typeof payload?.unsecureFormOrganizationNif === 'string' ? payload.unsecureFormOrganizationNif : undefined,
  );
  if (!raw) return undefined;
  return normalizePdfOrganizationTaxId(raw, resolveDefaultOrganizationJurisdiction(route));
}

function parseOrganizationLegalNameFromPayload(payload: Record<string, unknown> | undefined): string | undefined {
  const raw = firstDefined(
    typeof payload?.legalName === 'string' ? payload.legalName : undefined,
    typeof payload?.name === 'string' ? payload.name : undefined,
    typeof payload?.companyName === 'string' ? payload.companyName : undefined,
    typeof payload?.unsecureFormOrganizationLegalName === 'string' ? payload.unsecureFormOrganizationLegalName : undefined,
    typeof payload?.unsecureFormOrganizationName === 'string' ? payload.unsecureFormOrganizationName : undefined,
  );
  return normalizePdfOrganizationLegalName(raw);
}

function parseLegalRepresentativeNameFromPayload(payload: Record<string, unknown> | undefined): string | undefined {
  return firstDefined(
    typeof payload?.name === 'string' ? payload.name : undefined,
    typeof payload?.fullName === 'string' ? payload.fullName : undefined,
    typeof payload?.unsecureFormLegalRepresentativeName === 'string' ? payload.unsecureFormLegalRepresentativeName : undefined,
  );
}

function parseLegalRepresentativeIdentifierFromPayload(payload: Record<string, unknown> | undefined): string | undefined {
  return firstDefined(
    typeof payload?.identifier === 'string' ? payload.identifier : undefined,
    typeof payload?.id === 'string' ? payload.id : undefined,
    typeof payload?.serialNumber === 'string' ? payload.serialNumber : undefined,
    typeof payload?.unsecureFormLegalRepresentativeIdentifier === 'string'
      ? payload.unsecureFormLegalRepresentativeIdentifier
      : undefined,
  );
}

const ANNEX_ORGANIZATION_ADDITIONAL_TYPE = 'organization.additionalType';
const ANNEX_ORGANIZATION_SAME_AS = 'organization.sameAs';
const ANNEX_ORGANIZATION_URL = 'organization.url';
const ANNEX_ORGANIZATION_ALTERNATE_NAME = 'organization.alternateName';
const ANNEX_ORGANIZATION_IDENTIFIER_TYPE = 'organization.identifierType';
const ANNEX_ORGANIZATION_IDENTIFIER_VALUE = 'organization.identifierValue';
const ANNEX_ORGANIZATION_REGISTRATION_NUMBER = 'organization.registrationNumber';
const ANNEX_PERSON_EMAIL = 'person.email';
const ANNEX_PERSON_ALTERNATE_NAME = 'person.alternateName';
const ANNEX_PERSON_ADDITIONAL_TYPE = 'person.additionalType';
const ANNEX_ORGANIZATION_VISIBLE_TAX_ID_FIELDS = [
  'organization.taxID',
  'organization.taxId',
  'organization.tax id',
  'organization.tax identifier',
  'organization.taxIdentifier',
  'organization.taxNumber',
  'organization.tax number',
  'organization.vat',
  'organization.vatID',
  'organization.vatId',
  'organization.vat id',
  'organization.vat number',
  'organization.vatNumber',
  'organization.vat/cif',
  'organization.cif',
  'organization.nif',
  'taxID',
  'taxId',
  'tax id',
  'tax identifier',
  'taxNumber',
  'tax number',
  'vat',
  'vatID',
  'vatId',
  'vat id',
  'vat number',
  'vatNumber',
  'vat/cif',
  'cif',
  'nif',
  'company tax id',
  'company vat',
  'organization identifier',
  'identificacion empresa',
  'identificación empresa',
  'identificacion',
  'identificación',
];
const ANNEX_ORGANIZATION_VISIBLE_LEGAL_NAME_FIELDS = [
  'organization.legalName',
  'organization.legalname',
  'organization.legal name',
  'organization.name',
  'organization.companyName',
  'organization.company name',
  'organization.company',
  'organization.businessName',
  'organization.business name',
  'organization.organizationName',
  'organization.organization name',
  'organization.razonSocial',
  'organization.razon social',
  'legalName',
  'legalname',
  'legal name',
  'name',
  'companyName',
  'company name',
  'company',
  'businessName',
  'business name',
  'organizationName',
  'organization name',
  'razonSocial',
  'razon social',
  'razón social',
];

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

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

/**
 * Resolves the schema.org PropertyValue used as the organization identifier in
 * the dataspace. Explicit PDF identifier fields win. The legacy registration
 * number is retained as a local registration and, only when neither exists,
 * the normalized PDF/certificate tax identifier is copied as VAT/TAX.
 *
 * This is not itself a Gaia-X LegalRegistrationNumber credential. It is the
 * jurisdiction-qualified source value that a GW/notary flow uses to obtain or
 * reference that separate credential.
 */
function resolveOrganizationPropertyValueIdentifier(
  result: VerifyResult,
  organizationTaxId: string | undefined,
  organizationRegistrationNumber: string | undefined,
): Record<string, string> | undefined {
  const explicitType = getAnnexField(result, ANNEX_ORGANIZATION_IDENTIFIER_TYPE);
  const explicitValue = getAnnexField(result, ANNEX_ORGANIZATION_IDENTIFIER_VALUE);
  if (explicitValue) {
    return {
      '@type': 'PropertyValue',
      additionalType: explicitType || 'LOCAL',
      value: explicitValue,
    };
  }
  if (organizationRegistrationNumber) {
    return {
      '@type': 'PropertyValue',
      additionalType: explicitType || 'LOCAL',
      value: organizationRegistrationNumber,
    };
  }
  if (!organizationTaxId) return undefined;
  return {
    '@type': 'PropertyValue',
    additionalType: /^VAT[A-Z]{2}-/i.test(organizationTaxId) ? 'VAT' : 'TAX',
    value: organizationTaxId,
  };
}

/**
 * Resolves the canonical controller-binding identifier to project into the
 * representative VC as `credentialSubject.hasCredential.material`.
 *
 * Preferred representation:
 * - RFC 9278 JWK-thumbprint URN derived from the controller binding public JWK
 *
 * Fallback:
 * - existing `kid` when the JWK does not expose enough parameters for a
 *   canonical RFC 7638 thumbprint derivation
 *
 * @param controllerPublicKeyJwk Controller binding public JWK captured during `_verify`.
 */
function resolveRepresentativeCredentialMaterial(
  controllerPublicKeyJwk: Record<string, unknown> | undefined,
): string | undefined {
  const jwk = asObject(controllerPublicKeyJwk);
  if (!jwk) return undefined;

  const kty = typeof jwk.kty === 'string' ? jwk.kty.trim() : '';
  try {
    if (kty === 'EC') {
      const crv = typeof jwk.crv === 'string' ? jwk.crv.trim() : '';
      const x = typeof jwk.x === 'string' ? jwk.x.trim() : '';
      const y = typeof jwk.y === 'string' ? jwk.y.trim() : '';
      if (crv && x && y) {
        return toJwkThumbprintSha256Urn({ kty, crv, x, y });
      }
    }
    if (kty === 'RSA') {
      const e = typeof jwk.e === 'string' ? jwk.e.trim() : '';
      const n = typeof jwk.n === 'string' ? jwk.n.trim() : '';
      if (e && n) {
        return toJwkThumbprintSha256Urn({ kty, e, n });
      }
    }
    if (kty === 'OKP') {
      const crv = typeof jwk.crv === 'string' ? jwk.crv.trim() : '';
      const x = typeof jwk.x === 'string' ? jwk.x.trim() : '';
      if (crv && x) {
        return toJwkThumbprintSha256Urn({ kty, crv, x });
      }
    }
  } catch {
    // Fall back to `kid` below when thumbprint derivation is not possible.
  }

  const kid = typeof jwk.kid === 'string' ? jwk.kid.trim() : '';
  return kid || undefined;
}

/**
 * Resolves whether the current ICA runtime explicitly allows demo-only
 * representative identity fallbacks.
 */
function isDemoRepresentativePayloadFallbackEnabled(): boolean {
  return loadIcaSecurityConfigFromEnv().securityMode === 'demo';
}

/**
 * Extracts a representative `sameAs` candidate from the optional payload.
 *
 * Demo policy:
 * - accept `legalRepresentativePayload.sameAs` verbatim and normalize it into
 *   the canonical multibase/email form
 * - otherwise accept `legalRepresentativePayload.email`
 *
 * Non-demo modes must ignore this payload and rely exclusively on the signed
 * PDF annex or signer certificate identity.
 *
 * @param payload Optional legal representative payload carried in `_verify`.
 */
function extractRepresentativeSameAsFromPayload(payload: Record<string, unknown> | undefined): string | undefined {
  const sameAsCandidate = firstDefined(
    typeof payload?.sameAs === 'string' ? payload.sameAs : undefined,
    typeof payload?.email === 'string' ? payload.email : undefined,
  );
  const normalized = normalizeSameAsHash(sameAsCandidate || '');
  return normalized || undefined;
}

/**
 * Resolves the canonical representative `sameAs` value for the person VC.
 *
 * Source priority:
 * 1. signed annex `person.email`
 * 2. signer certificate email DN fields
 * 3. demo-only payload fallback (`legalRepresentativePayload.sameAs|email`)
 *
 * @param result Verified ICA result bundle.
 * @param subjectDn Parsed signer DN.
 */
function resolveRepresentativeSameAs(
  result: VerifyResult,
  subjectDn: Record<string, string>,
): string | undefined {
  const signedIdentityCandidate = firstDefined(
    getFirstAnnexField(result, ANNEX_PERSON_EMAIL_FIELDS),
    subjectDn.EMAILADDRESS,
    subjectDn.EMAIL,
    subjectDn.E,
  );
  const normalizedSignedIdentity = normalizeSameAsHash(signedIdentityCandidate || '');
  if (normalizedSignedIdentity) return normalizedSignedIdentity;
  if (!isDemoRepresentativePayloadFallbackEnabled()) return undefined;
  return extractRepresentativeSameAsFromPayload(result.legalRepresentativePayload);
}

function getFirstAnnexField(result: VerifyResult, names: string[]): string | undefined {
  for (const name of names) {
    const value = getAnnexField(result, name);
    if (value) return value;
  }
  return undefined;
}

function normalizePdfOrganizationLegalName(value: string | undefined): string | undefined {
  const normalized = (value || '')
    .trim()
    .replace(/[\\\/]+$/g, '')
    .trim()
    .replace(/\s+/g, ' ');
  return normalized ? normalized.toUpperCase() : undefined;
}

function normalizePdfOrganizationTaxId(
  value: string | undefined,
  defaultJurisdiction: string,
): string | undefined {
  const normalizedValue = (value || '').trim().toUpperCase();
  const jurisdiction = defaultJurisdiction.trim().toUpperCase();
  if (!normalizedValue || !jurisdiction) return undefined;

  const explicitVatCountryMatch = /^VAT([A-Z]{2})[\s-]*([A-Z0-9]+)$/i.exec(normalizedValue.replace(/\s+/g, ''));
  if (explicitVatCountryMatch) {
    return `VAT${explicitVatCountryMatch[1].toUpperCase()}-${explicitVatCountryMatch[2].toUpperCase()}`;
  }
  const explicitVatesMatch = /^VATES[\s-]*([A-Z0-9]+)$/i.exec(normalizedValue.replace(/\s+/g, ''));
  if (explicitVatesMatch) {
    return `VATES-${explicitVatesMatch[1].toUpperCase()}`;
  }

  const vatPrefix = `VAT${jurisdiction}`;
  const withoutVatPrefix = normalizedValue.startsWith(vatPrefix)
    ? normalizedValue.slice(vatPrefix.length)
    : normalizedValue;
  const prefixPattern = new RegExp(`^${jurisdiction}(?:[\\s-]*)`, 'i');
  const withoutPrefix = prefixPattern.test(withoutVatPrefix)
    ? withoutVatPrefix.replace(prefixPattern, '')
    : withoutVatPrefix;
  const normalizedTaxNumber = withoutPrefix.replace(/[\s-]+/g, '');
  if (!normalizedTaxNumber) return undefined;
  return `${vatPrefix}-${normalizedTaxNumber}`;
}

function resolveDefaultOrganizationJurisdiction(route: VerifyRouteContext): string {
  return route.jurisdiction.toUpperCase();
}

function resolveOrganizationTaxCountryFromPdf(route: VerifyRouteContext, result: VerifyResult): string {
  for (const [key, value] of Object.entries(result.annexFormFields || {})) {
    const normalizedKey = normalizeForMatching(key);
    if (!normalizedKey.includes('domicilio fiscal') && !normalizedKey.includes('fiscal address')) continue;
    const normalizedValue = normalizeForMatching(String(value || ''));
    if (/\bportugal\b/.test(normalizedValue) || /\bportuguesa\b/.test(normalizedValue)) {
      return 'PT';
    }
  }
  return resolveDefaultOrganizationJurisdiction(route);
}

function extractOrganizationIdentityFromPdf(
  route: VerifyRouteContext,
  result: VerifyResult,
): { taxID?: string; legalName?: string; hasTaxIdField: boolean; hasLegalNameField: boolean } {
  const jurisdiction = resolveOrganizationTaxCountryFromPdf(route, result);
  const rawTaxId = getFirstAnnexField(result, ANNEX_ORGANIZATION_VISIBLE_TAX_ID_FIELDS);
  const rawLegalName = getFirstAnnexField(result, ANNEX_ORGANIZATION_VISIBLE_LEGAL_NAME_FIELDS);
  return {
    taxID: normalizePdfOrganizationTaxId(rawTaxId, jurisdiction),
    legalName: normalizePdfOrganizationLegalName(rawLegalName),
    hasTaxIdField: Boolean(rawTaxId),
    hasLegalNameField: Boolean(rawLegalName),
  };
}

function resolveOrganizationPublicDid(route: VerifyRouteContext, organizationTaxId: string | undefined): string | undefined {
  const normalizedTaxId = (organizationTaxId || '').trim();
  if (!normalizedTaxId) return undefined;
  return buildOrganizationDidFromTaxId(route.sector, normalizedTaxId);
}

function resolveOrganizationSubjectIdentifiers(
  route: VerifyRouteContext,
  organizationTaxId: string | undefined,
  annexSameAsDid: string | undefined,
): { id: string; sameAs?: string } {
  const publicDid = resolveOrganizationPublicDid(route, organizationTaxId);
  const alternateDid = annexSameAsDid && annexSameAsDid !== publicDid
    ? annexSameAsDid
    : undefined;

  if (publicDid) {
    return {
      id: publicDid,
      ...(alternateDid ? { sameAs: alternateDid } : {}),
    };
  }

  if (annexSameAsDid) {
    return {
      id: annexSameAsDid,
    };
  }

  if (organizationTaxId) {
    return {
      id: `urn:organization:taxid:${organizationTaxId}`,
    };
  }

  return {
    id: `urn:organization:certificate:${route.tenantId}`,
  };
}

function normalizeOrganizationUrl(value: string | undefined): string | undefined {
  const trimmed = (value || '').trim();
  if (!trimmed) return undefined;
  return trimmed
    .replace(/^https?:\/\//i, '')
    .replace(/\/+$/g, '');
}

function determineEvidenceSource(certificateOrganizationTaxId: string | undefined): 'qualified_certification' | 'visible_pdf_fields' {
  // Source is qualified only when the org identity was extracted from the signer certificate itself
  // (signer DN contained O= or organizationIdentifier with the company VAT).
  // If org data came from visible PDF form fields (fallback), source is visible_pdf_fields.
  return certificateOrganizationTaxId ? 'qualified_certification' : 'visible_pdf_fields';
}

function determineAssuranceLevel(result: VerifyResult, source: 'qualified_certification' | 'visible_pdf_fields'): 'low' | 'medium' | 'high' {
  // Qualified certificates with valid chain and revocation = high assurance
  if (source === 'qualified_certification') {
    if (
      result.signatureValid &&
      result.chainValid &&
      result.templateMatch &&
      result.revocationStatus === 'good'
    ) {
      return 'high';
    }
    // Qualified cert with valid chain but other issues = medium
    if (result.signatureValid && result.chainValid) {
      return 'medium';
    }
    return 'low';
  }
  
  // Fallback to visible PDF fields (no qualified cert) = lower assurance baseline
  if (source === 'visible_pdf_fields') {
    if (
      result.signatureValid &&
      result.chainValid &&
      result.templateMatch &&
      result.revocationStatus === 'good'
    ) {
      return 'medium';
    }
    if (result.signatureValid && result.chainValid) {
      return 'medium';
    }
    return 'low';
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

function parseBooleanEnv(value: string | undefined, fallback = false): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function normalizeVatId(value: string | undefined): string | undefined {
  const trimmed = (value || '').trim();
  return trimmed ? trimmed.toUpperCase() : undefined;
}

function isDeterministicVcByContractEnabled(): boolean {
  return parseBooleanEnv(process.env.DETERMINISTIC_VC_BY_CONTRACT, false);
}

function isStrictIdentitySourcesEnabled(): boolean {
  // TODO(security): In production deployments, remove or hard-block this override
  // so strict identity sources cannot be disabled via env vars from runtime operators.
  // Suggested policy: ignore DISABLE_STRICT_IDENTITY_SOURCE when NODE_ENV=production.
  return !parseBooleanEnv(process.env.DISABLE_STRICT_IDENTITY_SOURCE, false);
}

function normalizeUrnSegment(value: string, fallback: string): string {
  const normalized = (value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-');
  const collapsed = normalized.replace(/-+/g, '-').replace(/^-+|-+$/g, '');
  return collapsed || fallback;
}

function resolveDataspaceUrnNamespace(route: VerifyRouteContext): string {
  const configured = process.env.DATASPACE_URN_NAMESPACE;
  if (configured && configured.trim()) {
    return normalizeUrnSegment(configured, 'dataspace');
  }
  return normalizeUrnSegment(route.tenantId, 'dataspace');
}

function normalizeHexDigest(hex: string): string {
  return (hex || '').trim().toLowerCase();
}

function normalizeIsoTimestampToSecondPrecision(value: string, fieldName: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`${fieldName} is not a valid ISO timestamp: ${value}`);
  }
  parsed.setMilliseconds(0);
  return parsed.toISOString();
}

function resolveVcEvidenceTimestamp(
  result: VerifyResult,
  deterministicVcByContract: boolean,
  fieldName: 'organizationSigningTime' | 'personSigningTime' | 'verifierSigningTime',
): string {
  const signingTime = result[fieldName] || result.signerSigningTime;
  if (signingTime) {
    return normalizeIsoTimestampToSecondPrecision(signingTime, fieldName);
  }
  if (deterministicVcByContract) {
    throw new Error(`Deterministic staging mode requires ${fieldName} (or signerSigningTime) extracted from signature metadata.`);
  }
  return normalizeIsoTimestampToSecondPrecision(result.verifiedAt, 'verifiedAt');
}

function deriveDocumentContentCidV1Raw(evidenceDigestAlg: string, evidenceDigestHex: string): string {
  const normalizedAlg = (evidenceDigestAlg || '').trim().toLowerCase();
  const normalizedHex = normalizeHexDigest(evidenceDigestHex);
  if (!/^[0-9a-f]+$/.test(normalizedHex)) {
    throw new Error('Signed document digest must be hexadecimal to derive deterministic document version ID.');
  }
  if (normalizedAlg === 'sha3-384' && normalizedHex.length === 96) {
    return multibase58CidV1RawSha3_384Hex(normalizedHex);
  }
  if (normalizedAlg === 'sha3-256' && normalizedHex.length === 64) {
    return multibase58CidV1RawSha3_256Hex(normalizedHex);
  }
  const digestBytes = Buffer.from(normalizedHex, 'hex');
  const derivedSha3_384 = createHash('sha3-384').update(digestBytes).digest('hex');
  return multibase58CidV1RawSha3_384Hex(derivedSha3_384);
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
  verifierOrganizationDid: string,
  certificateOrganizationTaxId: string | undefined,
  documentContentCid: string,
  deterministicVcByContract: boolean,
  signatureEvidenceTimestamp: string,
  documentEvidenceTimestamp: string,
  includeElectronicSignatureEvidence = true,
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

  // Determine signature source: qualified eIDAS-4 certificate or fallback to visible PDF fields
  const evidenceSource = determineEvidenceSource(certificateOrganizationTaxId);

  // Keep evidence attachment compact; detailed debug stays in Bundle.result.
  const attachmentPayload = {
    profile: 'oidc4ida-evidence-v1',
    source: evidenceSource,
    assuranceLevel: determineAssuranceLevel(result, evidenceSource),
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

  const evidences: EvidenceObjectDLT[] = [];
  if (includeElectronicSignatureEvidence) {
    const signatureEvidence: EvidenceElectronicSignatureDLT = {
      type: 'electronic_signature',
      signature_type: 'pades',
      issuer: result.signerIssuer || verifierOrganizationDid,
      serial_number: serialNumber,
      created_at: signatureEvidenceTimestamp,
      attachments: [
        {
          content_type: 'application/json',
          content: compactAttachmentDataUri,
        },
      ],
    };
    evidences.push(signatureEvidence);
  }

  // tx reference must identify immutable document content, not storage location.
  // Keep operational audit path internal and expose CID for contract-level traceability.
  const documentTxnRef = documentContentCid;

  const documentEvidence: EvidenceDocumentDLT = {
    type: 'document',
    method: 'eid',
    time: documentEvidenceTimestamp,
    verifier: {
      organization: verifierOrganizationDid,
    },
    check_details: [
      {
        check_method: 'vdig',
        organization: verifierOrganizationDid,
        txn: documentTxnRef,
        time: documentEvidenceTimestamp,
      },
      ...(includeElectronicSignatureEvidence
        ? [
            {
              check_method: 'vcrypt' as const,
              organization: verifierOrganizationDid,
              txn: documentTxnRef,
              time: documentEvidenceTimestamp,
            },
          ]
        : []),
    ],
    attachments: {
      digest: {
        alg: evidenceDigestAlg,
        value: hexToBase64(evidenceDigestHex),
      },
      url: `ipfs://${documentContentCid}`,
    },
    document_details: {
      type: 'terms-and-conditions',
      document_number: route.resourceType,
      ...(serialNumber ? { serial_number: serialNumber } : {}),
      issuer: {
        id: verifierOrganizationDid,
        type: 'TrustServiceProvider',
        country_code: route.jurisdiction.toUpperCase(),
        jurisdiction: route.jurisdiction.toUpperCase(),
      },
    },
  };
  evidences.push(documentEvidence);
  return evidences;
}

function extractAdditionalOrganizationDataFromPdf(result: VerifyResult): Record<string, unknown> {
  // TODO: Extract additional schema.org fields (like address, telephone) directly from the PDF fields
  if (isStrictIdentitySourcesEnabled()) {
    return {};
  }
  if (process.env.ICA_ALLOW_UNVERIFIED_CREDENTIAL_PAYLOADS === 'true') {
    return (result.organizationPayload as Record<string, unknown>) || {};
  }
  return {};
}

function isDemoOrganizationCategoryFallbackEnabled(): boolean {
  return loadIcaSecurityConfigFromEnv().securityMode === 'demo';
}

function resolveOrganizationOfferCategory(
  route: VerifyRouteContext,
  organizationSubject: Record<string, unknown>,
): string | undefined {
  const existingMakesOffer = asObject(organizationSubject.makesOffer);
  const existingCategory = firstDefined(
    typeof existingMakesOffer?.category === 'string' ? existingMakesOffer.category : undefined,
    typeof organizationSubject.category === 'string' ? String(organizationSubject.category) : undefined,
  );
  if (existingCategory) return existingCategory;
  if (!isDemoOrganizationCategoryFallbackEnabled()) return undefined;
  return String(route.sector || '').trim() || undefined;
}

function resolveServiceTypeClaimValue(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return serializeServiceCapabilityTokens(value.split(','));
  }
  if (Array.isArray(value)) {
    return serializeServiceCapabilityTokens(
      value.map((item) => (typeof item === 'string' ? item : undefined)),
    );
  }
  return undefined;
}

function resolveOrganizationOfferServiceType(
  organizationSubject: Record<string, unknown>,
): string | undefined {
  const existingMakesOffer = asObject(organizationSubject.makesOffer);
  const existingServiceType = resolveServiceTypeClaimValue(existingMakesOffer?.serviceType)
    || resolveServiceTypeClaimValue(organizationSubject.serviceType);
  if (existingServiceType) return existingServiceType;
  if (!isDemoOrganizationCategoryFallbackEnabled()) return undefined;
  return serializeServiceCapabilityTokens([
    ServiceCapability.IndexProvider,
    ServiceCapability.DigitalTwinProvider,
  ]);
}

function extractAdditionalPersonDataFromPdf(result: VerifyResult): Record<string, unknown> {
  // TODO: Extract additional schema.org fields directly from the PDF fields
  if (isStrictIdentitySourcesEnabled()) {
    return {};
  }
  if (process.env.ICA_ALLOW_UNVERIFIED_CREDENTIAL_PAYLOADS === 'true') {
    return (result.legalRepresentativePayload as Record<string, unknown>) || {};
  }
  return {};
}

const ANNEX_PERSON_NAME_FIELDS = [
  'person.name',
  'person.fullName',
  'person.fullname',
  'person.legalRepresentativeName',
  'person.representativeName',
  'legalRepresentative.name',
  'legalRepresentative.fullName',
  'representative.name',
  'representante legal',
  'representante',
];

const ANNEX_PERSON_IDENTIFIER_FIELDS = [
  'person.identifier',
  'person.id',
  'person.serialNumber',
  'person.serialnumber',
  'person.nif',
  'person.nie',
  'person.dni',
  'legalRepresentative.identifier',
  'legalRepresentative.nif',
  'representative.identifier',
  'identificacion',
  'identificación',
  'identificacion representante',
  'identificación representante',
];

const ANNEX_PERSON_GIVEN_NAME_FIELDS = [
  'person.givenName',
  'person.givenname',
  'legalRepresentative.givenName',
  'representative.givenName',
];

const ANNEX_PERSON_FAMILY_NAME_FIELDS = [
  'person.familyName',
  'person.familyname',
  'person.surname',
  'legalRepresentative.familyName',
  'representative.familyName',
];

const ANNEX_PERSON_EMAIL_FIELDS = [
  ANNEX_PERSON_EMAIL,
  'correo electronico',
  'correo electrónico',
  'email',
  'e-mail',
];

function mergePostalAddress(
  baseAddress: unknown,
  addressCountry: string | undefined,
): Record<string, unknown> | undefined {
  const normalizedBase = baseAddress && typeof baseAddress === 'object'
    ? { ...(baseAddress as Record<string, unknown>) }
    : {};

  if (!addressCountry && Object.keys(normalizedBase).length === 0) {
    return undefined;
  }

  return {
    '@type': 'PostalAddress',
    ...normalizedBase,
    ...(addressCountry ? { addressCountry } : {}),
  };
}

export function buildVerificationVcBundle(
  route: VerifyRouteContext,
  result: VerifyResult,
  issuerDidInput?: string,
): VerifyBundleResponse {
  const subjectDn = result.signerSubject ? parseDistinguishedName(result.signerSubject) : {};
  const issuerDid = (issuerDidInput || '').trim() || resolveVcIssuerDid();
  const strictIdentitySources = isStrictIdentitySourcesEnabled();
  const allowUnverifiedPayloads = process.env.ICA_ALLOW_UNVERIFIED_CREDENTIAL_PAYLOADS === 'true';
  const allowPayloadIdentityFallback = !strictIdentitySources && allowUnverifiedPayloads;

  const organizationIdentityFromPdf = extractOrganizationIdentityFromPdf(route, result);
  const certificateOrganizationLegalName = normalizePdfOrganizationLegalName(
    firstDefined(subjectDn.O, subjectDn.OU),
  );
  const certificateOrganizationTaxId = parseOrganizationTaxId(subjectDn);
  const payloadOrganizationTaxId = parseOrganizationTaxIdFromPayload(route, result.organizationPayload);
  const payloadOrganizationLegalName = parseOrganizationLegalNameFromPayload(result.organizationPayload);
  const payloadRepresentativeName = parseLegalRepresentativeNameFromPayload(result.legalRepresentativePayload);
  const payloadRepresentativeIdentifier = parseLegalRepresentativeIdentifierFromPayload(result.legalRepresentativePayload);
  const signerOrganizationTaxId = parseOrganizationTaxId(subjectDn);
  const signerBelongsToVerifier = Boolean(
    normalizeVatId(signerOrganizationTaxId)
    && normalizeVatId(result.verifierVatId)
    && normalizeVatId(signerOrganizationTaxId) === normalizeVatId(result.verifierVatId),
  );
  const organizationTaxId = signerBelongsToVerifier
    ? firstDefined(
      organizationIdentityFromPdf.taxID,
      allowPayloadIdentityFallback ? payloadOrganizationTaxId : undefined,
    )
    : firstDefined(certificateOrganizationTaxId, organizationIdentityFromPdf.taxID);
  const orgLegalName = signerBelongsToVerifier
    ? firstDefined(
      organizationIdentityFromPdf.legalName,
      allowPayloadIdentityFallback ? payloadOrganizationLegalName : undefined,
    )
    : firstDefined(certificateOrganizationLegalName, organizationIdentityFromPdf.legalName);

  if (!certificateOrganizationTaxId) {
    if (!organizationIdentityFromPdf.taxID) {
      throw new Error(
        'PDF must include a visible organization VAT/CIF field when signer certificate does not contain organization tax ID.',
      );
    }
    if (!organizationIdentityFromPdf.legalName) {
      throw new Error(
        'PDF must include a visible organization legal name field when signer certificate does not contain organization tax ID.',
      );
    }
  }
  if (signerBelongsToVerifier) {
    if (!organizationTaxId) {
      throw new Error(
        'Organization tax ID is required when the only client evidence is document-level verification. '
        + 'Provide visible PDF fields, or disable strict identity source mode and send organization payload.',
      );
    }
    if (!orgLegalName) {
      throw new Error(
        'Organization legal name is required when the only client evidence is document-level verification. '
        + 'Provide visible PDF fields, or disable strict identity source mode and send organization payload.',
      );
    }
  }

  const annexOrganizationDid = getAnnexOrganizationDid(result);
  const organizationAdditionalType = getAnnexField(result, ANNEX_ORGANIZATION_ADDITIONAL_TYPE);
  const organizationAlternateName = getAnnexField(result, ANNEX_ORGANIZATION_ALTERNATE_NAME);
  const organizationRegistrationNumber = getAnnexField(result, ANNEX_ORGANIZATION_REGISTRATION_NUMBER);
  const organizationUrl = normalizeOrganizationUrl(getAnnexField(result, ANNEX_ORGANIZATION_URL));
  const includeElectronicSignatureEvidence = !signerBelongsToVerifier;

  const givenName = subjectDn.GN || subjectDn.GIVENNAME;
  const familyName = subjectDn.SN || subjectDn.SURNAME;
  const personNameFromForm = getFirstAnnexField(result, ANNEX_PERSON_NAME_FIELDS);
  const personIdentifierFromForm = getFirstAnnexField(result, ANNEX_PERSON_IDENTIFIER_FIELDS);
  const personGivenNameFromForm = getFirstAnnexField(result, ANNEX_PERSON_GIVEN_NAME_FIELDS);
  const personFamilyNameFromForm = getFirstAnnexField(result, ANNEX_PERSON_FAMILY_NAME_FIELDS);
  const representativeNameFromCertificate = [givenName, familyName].filter(Boolean).join(' ') || subjectDn.CN;
  // TODO(multi-representatives): when OCR/form extraction finds more than one natural person
  // signer (for example, two partners signing), emit a stable multi-person model instead of
  // collapsing names into one Person credential string.
  const representativeName = signerBelongsToVerifier
    ? firstDefined(
      personNameFromForm,
      [personGivenNameFromForm, personFamilyNameFromForm].filter(Boolean).join(' '),
      allowPayloadIdentityFallback ? payloadRepresentativeName : undefined,
    )
    : firstDefined(representativeNameFromCertificate, personNameFromForm);
  const personIdentifierFromCertificate = firstDefined(subjectDn.SERIALNUMBER, subjectDn['OID.2.5.4.5']);
  const personIdentifier = signerBelongsToVerifier
    ? firstDefined(personIdentifierFromForm, allowPayloadIdentityFallback ? payloadRepresentativeIdentifier : undefined)
    : firstDefined(personIdentifierFromCertificate, personIdentifierFromForm);
  const personSameAs = resolveRepresentativeSameAs(result, subjectDn);
  const personCredentialMaterial = resolveRepresentativeCredentialMaterial(result.controllerPublicKeyJwk);
  const personAlternateName = getAnnexField(result, ANNEX_PERSON_ALTERNATE_NAME);
  const personAdditionalType = getAnnexField(result, ANNEX_PERSON_ADDITIONAL_TYPE);
  const country = subjectDn.C || subjectDn.COUNTRYNAME || undefined;
  const serialNumber =
    result.signerCertificateSerialNumber
    || personIdentifier
    || `cert:${route.tenantId}:${route.resourceType}`;
  const deterministicVcByContract = isDeterministicVcByContractEnabled();
  const organizationEvidenceTimestamp = resolveVcEvidenceTimestamp(
    result,
    deterministicVcByContract,
    'organizationSigningTime',
  );
  const personEvidenceTimestamp = resolveVcEvidenceTimestamp(
    result,
    deterministicVcByContract,
    'personSigningTime',
  );
  const verifierEvidenceTimestamp = resolveVcEvidenceTimestamp(
    result,
    deterministicVcByContract,
    'verifierSigningTime',
  );
  const verifierOrganizationDid = resolveOrganizationPublicDid(
    route,
    result.verifierVatId || certificateOrganizationTaxId || organizationTaxId,
  )
    || issuerDid;
  const dataspaceUrnNamespace = resolveDataspaceUrnNamespace(route);
  const urnSector = normalizeUrnSegment(route.sector, 'unknown-sector');
  const evidenceDigestAlg = normalizeDigestAlgorithmForEvidence(result.digest?.alg);
  const evidenceDigestHex = result.digest?.signedPdfHex || result.hashes.signedPdfSha256Hex;
  const documentContentCid = deriveDocumentContentCidV1Raw(evidenceDigestAlg, evidenceDigestHex);
  const organizationEvidence = buildOidc4IdaEvidence(
    route,
    result,
    serialNumber,
    verifierOrganizationDid,
    certificateOrganizationTaxId,
    documentContentCid,
    deterministicVcByContract,
    organizationEvidenceTimestamp,
    verifierEvidenceTimestamp,
    includeElectronicSignatureEvidence,
  );
  const personEvidence = buildOidc4IdaEvidence(
    route,
    result,
    serialNumber,
    verifierOrganizationDid,
    certificateOrganizationTaxId,
    documentContentCid,
    deterministicVcByContract,
    personEvidenceTimestamp,
    verifierEvidenceTimestamp,
    includeElectronicSignatureEvidence,
  );
  const organizationIdentifiers = resolveOrganizationSubjectIdentifiers(route, organizationTaxId, annexOrganizationDid);
  const organizationPropertyValueIdentifier = resolveOrganizationPropertyValueIdentifier(
    result,
    organizationTaxId,
    organizationRegistrationNumber,
  );

  const organizationSubject: Record<string, unknown> = {
    ...extractAdditionalOrganizationDataFromPdf(result),
    id: organizationIdentifiers.id,
    '@type': 'Organization',
  };
  if (orgLegalName) {
    organizationSubject.legalName = orgLegalName;
  }
  if (organizationTaxId) {
    organizationSubject.taxID = organizationTaxId;
  }
  if (organizationPropertyValueIdentifier) {
    organizationSubject.identifier = organizationPropertyValueIdentifier;
  }
  const organizationAddress = mergePostalAddress(organizationSubject.address, country);
  if (organizationAddress) {
    organizationSubject.address = organizationAddress;
  }
  if (organizationAdditionalType) {
    organizationSubject.additionalType = organizationAdditionalType;
  }
  if (organizationIdentifiers.sameAs) {
    organizationSubject.sameAs = organizationIdentifiers.sameAs;
  }
  if (organizationAlternateName) {
    organizationSubject.alternateName = organizationAlternateName;
  }
  if (organizationRegistrationNumber) {
    organizationSubject.registrationNumber = organizationRegistrationNumber;
  }
  if (organizationUrl) {
    organizationSubject.url = organizationUrl;
  }
  const organizationOfferCategory = resolveOrganizationOfferCategory(route, organizationSubject);
  if (organizationOfferCategory) {
    const existingMakesOffer = asObject(organizationSubject.makesOffer) || {};
    organizationSubject.makesOffer = {
      ...existingMakesOffer,
      '@type': typeof existingMakesOffer['@type'] === 'string' ? existingMakesOffer['@type'] : 'Offer',
      category: organizationOfferCategory,
    };
  }
  const organizationOfferServiceType = resolveOrganizationOfferServiceType(organizationSubject);
  if (organizationOfferServiceType) {
    const existingMakesOffer = asObject(organizationSubject.makesOffer) || {};
    organizationSubject.makesOffer = {
      ...existingMakesOffer,
      '@type': typeof existingMakesOffer['@type'] === 'string' ? existingMakesOffer['@type'] : 'Offer',
      serviceType: organizationOfferServiceType,
    };
  }

  const unsignedOrganizationVc: VerifiableCredentialV2 = {
    id: deterministicVcByContract
      ? `urn:${dataspaceUrnNamespace}:${urnSector}:organization:vc:${documentContentCid}`
      : `urn:uuid:${randomUUID()}`,
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    type: ['VerifiableCredential', 'OrganizationCredential'],
    issuer: issuerDid,
    // Policy: credential validity starts when verifier/promoter signs the document.
    validFrom: verifierEvidenceTimestamp,
    credentialSubject: organizationSubject,
    evidence: organizationEvidence,
  };
  (unsignedOrganizationVc as unknown as Record<string, unknown>).credentialStatus = {
    id: `${unsignedOrganizationVc.id}#status`,
    type: 'SimpleCredentialStatus2026',
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
  if (organizationPropertyValueIdentifier) {
    organizationRef.identifier = organizationPropertyValueIdentifier;
  }
  const personSubject: Record<string, unknown> = {
    ...extractAdditionalPersonDataFromPdf(result),
    id: personIdentifier
      ? `urn:person:identifier:${personIdentifier}`
      : `urn:person:identifier:${route.tenantId}`,
    '@type': 'Person',
    ...(representativeName ? { name: representativeName } : {}),
    hasOccupation: {
      '@type': 'Occupation',
      name: 'LegalRepresentative',
      identifier: 'urn:ilo:ilostat:isco-08:1120',
    },
    ...(certificateOrganizationTaxId ? { memberOf: organizationRef } : {}),
  };
  const resolvedGivenName = signerBelongsToVerifier ? personGivenNameFromForm : firstDefined(givenName, personGivenNameFromForm);
  const resolvedFamilyName = signerBelongsToVerifier ? personFamilyNameFromForm : firstDefined(familyName, personFamilyNameFromForm);
  if (resolvedGivenName) {
    personSubject.givenName = resolvedGivenName;
  }
  if (resolvedFamilyName) {
    personSubject.familyName = resolvedFamilyName;
  }
  if (personIdentifier) {
    personSubject.identifier = personIdentifier;
  }
  if (country) {
    personSubject.nationality = country;
  }
  if (personSameAs) {
    personSubject.sameAs = personSameAs;
  }
  if (personCredentialMaterial) {
    personSubject.hasCredential = {
      material: personCredentialMaterial,
    };
  }
  if (personAlternateName) {
    personSubject.alternateName = personAlternateName;
  }
  if (personAdditionalType) {
    personSubject.additionalType = personAdditionalType;
  }

  const hasVerifiablePersonIdentity = Boolean(
    representativeName
    || personIdentifier
    || resolvedGivenName
    || resolvedFamilyName,
  );

  const unsignedPersonVc: VerifiableCredentialV2 | undefined = hasVerifiablePersonIdentity ? {
    id: deterministicVcByContract
      ? `urn:${dataspaceUrnNamespace}:${urnSector}:organization-representative:vc:${documentContentCid}`
      : `urn:uuid:${randomUUID()}`,
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    type: ['VerifiableCredential', 'PersonCredential', 'LegalRepresentativeCredential'],
    issuer: issuerDid,
    // Policy: credential validity starts when verifier/promoter signs the document.
    validFrom: verifierEvidenceTimestamp,
    credentialSubject: personSubject,
    evidence: personEvidence,
  } : undefined;
  if (unsignedPersonVc) {
    (unsignedPersonVc as unknown as Record<string, unknown>).credentialStatus = {
      id: `${unsignedPersonVc.id}#status`,
      type: 'SimpleCredentialStatus2026',
    };
  }

  const proofCreatedAtOverride = deterministicVcByContract ? verifierEvidenceTimestamp : undefined;
  const organizationVc = attachProofToCredential(
    unsignedOrganizationVc,
    route,
    issuerDid,
    proofCreatedAtOverride,
  );
  const personVc = unsignedPersonVc
    ? attachProofToCredential(
      unsignedPersonVc,
      route,
      issuerDid,
      proofCreatedAtOverride,
    )
    : undefined;

  const entryOutcome = buildOperationOutcome(
    result.ok ? 'information' : 'warning',
    result.ok ? 'informational' : 'processing',
    result.ok ? 'Verification completed.' : 'Verification completed with warnings.',
  );

  const data: VerifyBundleResponse['data'] = [
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
  ];

  if (personVc) {
    data.push({
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
    });
  }

  return {
    resourceType: 'Bundle',
    type: 'batch-response',
    issues: entryOutcome,
    total: data.length,
    data,
  };
}
