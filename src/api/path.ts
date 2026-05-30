import type {
  ActivateAction,
  ActivateRouteContext,
  AddEvidenceAction,
  AddEvidenceRouteContext,
  AllowedSector,
  CreateDidDocumentAction,
  CreateDidDocumentRouteContext,
  TermsRemoveAction,
  TermsRemoveRouteContext,
  DelegationPolicyAction,
  DelegationPolicyRouteContext,
  CredentialRevokeAction,
  CredentialRevokeRouteContext,
  CredentialRetrieveAction,
  CredentialRetrieveRouteContext,
  CredentialSearchAction,
  CredentialSearchRouteContext,
  CredentialStatusAction,
  CredentialStatusRouteContext,
  SpacesAction,
  SpacesRouteContext,
  DcatCatalogDatasetRouteContext,
  DcatCatalogDdoDatasetRouteContext,
  DcatCatalogDdoRequestRouteContext,
  DcatCatalogRequestRouteContext,
  ControllerExchangeAction,
  ControllerExchangeRouteContext,
  ApiKeyProvisioningAction,
  ApiKeyProvisioningRouteContext,
  IdentityAuthAction,
  IdentityAuthRouteContext,
  IssueCredentialAction,
  IssueCredentialRouteContext,
  RotateAction,
  RotateRouteContext,
  VerifyAction,
  VerifyRouteContext,
} from './types.ts';
import {
  getSupportedJurisdictionErrorMessage,
  isSupportedJurisdiction,
} from './supported-jurisdictions.ts';
import { getSupportedSectorErrorMessage, isSupportedSector } from './supported-sectors.ts';

const VERIFY_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/terms\/pdf\/(?<resourceType>[^/]+)\/(?<action>_verify(?:-response)?)$/i;
const TERMS_REMOVE_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/terms\/pdf\/(?<resourceType>[^/]+)\/(?<action>_remove(?:-response)?)$/i;
const ENTITY_KEYS_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/entity\/keys\/(?<resourceType>credentials|communications)\/(?<action>_(?:activate(?:-response)?|rotate(?:-response)?))$/i;
const ENTITY_DID_DOCUMENT_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/entity\/did\/document\/(?<action>_create(?:-response)?)$/i;
const NETWORK_EVIDENCE_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/network\/evidence\/(?<evidenceType>[^/]+)\/(?<action>_add(?:-response)?)$/i;
const NETWORK_POLICY_DELEGATION_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/network\/policies\/delegations\/(?<action>_upsert(?:-response)?)$/i;
const NETWORK_CREDENTIAL_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/network\/credentials\/(?<credentialType>[^/]+)\/(?<action>_issue(?:-response)?)$/i;
const NETWORK_CREDENTIAL_STATUS_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/network\/credentials\/(?<credentialType>[^/]+)\/(?<action>_status(?:-response)?)$/i;
const NETWORK_CREDENTIAL_REVOKE_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/network\/credentials\/(?<credentialType>[^/]+)\/(?<action>_revoke(?:-response)?)$/i;
const NETWORK_CREDENTIAL_SEARCH_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/network\/credentials\/(?<credentialType>[^/]+)\/(?<action>_search(?:-response)?)$/i;
const NETWORK_CREDENTIAL_RETRIEVE_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/network\/credentials\/(?<credentialType>[^/]+)\/(?<action>_retrieve(?:-response)?)$/i;
const NETWORK_SPACES_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/network\/spaces\/(?<action>_(?:list|replace))$/i;
const DCAT_CATALOG_REQUEST_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/dcat3\/catalog\/request$/i;
const DCAT_CATALOG_DATASET_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/dcat3\/catalog\/datasets\/(?<datasetId>[^/]+)$/i;
const DCAT_CATALOG_DDO_REQUEST_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/dcat3\/catalog\/ddo\/request$/i;
const DCAT_CATALOG_DDO_DATASET_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/dcat3\/catalog\/ddo\/datasets\/(?<datasetId>[^/]+)$/i;
const CONTROLLER_EXCHANGE_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/organization\/dataspace\/auth\/(?<action>_exchange(?:-response)?)$/i;
const API_KEY_PROVISIONING_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/api-key\/org\.schema\/action\/(?<action>_(?:create|disable|remove|search)(?:-response)?)$/i;
const IDENTITY_AUTH_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/identity\/auth\/(?<action>_(?:dcr|code|token|exchange)(?:-response)?)$/i;

export const WELL_KNOWN_DCAT_DISCOVERY_CATALOG_PATH = '/.well-known/dcat3/catalog';
export const DCAT_DISCOVERY_CATALOG_ALIAS_PATH = '/dcat3/catalog/dcat.json';

export function buildDcatDiscoveryCatalogPath(): string {
  return WELL_KNOWN_DCAT_DISCOVERY_CATALOG_PATH;
}

export function buildDcatDiscoveryCatalogAliasPath(): string {
  return DCAT_DISCOVERY_CATALOG_ALIAS_PATH;
}

function asAction(raw: string): VerifyAction {
  return raw.toLowerCase() === '_verify-response' ? '_verify-response' : '_verify';
}

function asTermsRemoveAction(raw: string): TermsRemoveAction {
  return raw.toLowerCase() === '_remove-response' ? '_remove-response' : '_remove';
}

function asActivateAction(raw: string): ActivateAction {
  return raw.toLowerCase() === '_activate-response' ? '_activate-response' : '_activate';
}

function asRotateAction(raw: string): RotateAction {
  return raw.toLowerCase() === '_rotate-response' ? '_rotate-response' : '_rotate';
}

function asCreateDidDocumentAction(raw: string): CreateDidDocumentAction {
  return raw.toLowerCase() === '_create-response' ? '_create-response' : '_create';
}

function asAddEvidenceAction(raw: string): AddEvidenceAction {
  return raw.toLowerCase() === '_add-response' ? '_add-response' : '_add';
}

function asDelegationPolicyAction(raw: string): DelegationPolicyAction {
  return raw.toLowerCase() === '_upsert-response' ? '_upsert-response' : '_upsert';
}

function asIssueCredentialAction(raw: string): IssueCredentialAction {
  return raw.toLowerCase() === '_issue-response' ? '_issue-response' : '_issue';
}

function asCredentialStatusAction(raw: string): CredentialStatusAction {
  return raw.toLowerCase() === '_status-response' ? '_status-response' : '_status';
}

function asCredentialRevokeAction(raw: string): CredentialRevokeAction {
  return raw.toLowerCase() === '_revoke-response' ? '_revoke-response' : '_revoke';
}

function asCredentialSearchAction(raw: string): CredentialSearchAction {
  return raw.toLowerCase() === '_search-response' ? '_search-response' : '_search';
}

function asCredentialRetrieveAction(raw: string): CredentialRetrieveAction {
  return raw.toLowerCase() === '_retrieve-response' ? '_retrieve-response' : '_retrieve';
}

function asSpacesAction(raw: string): SpacesAction {
  return raw.toLowerCase() === '_replace' ? '_replace' : '_list';
}

function asControllerExchangeAction(raw: string): ControllerExchangeAction {
  return raw.toLowerCase() === '_exchange-response' ? '_exchange-response' : '_exchange';
}

function asApiKeyProvisioningAction(raw: string): ApiKeyProvisioningAction {
  const normalized = raw.toLowerCase();
  if (normalized === '_create-response') return '_create-response';
  if (normalized === '_disable') return '_disable';
  if (normalized === '_disable-response') return '_disable-response';
  if (normalized === '_remove') return '_remove';
  if (normalized === '_remove-response') return '_remove-response';
  if (normalized === '_search') return '_search';
  if (normalized === '_search-response') return '_search-response';
  return '_create';
}

function asIdentityAuthAction(raw: string): IdentityAuthAction {
  const normalized = raw.toLowerCase();
  if (normalized === '_dcr-response') return '_dcr-response';
  if (normalized === '_code') return '_code';
  if (normalized === '_code-response') return '_code-response';
  if (normalized === '_token') return '_token';
  if (normalized === '_token-response') return '_token-response';
  if (normalized === '_exchange') return '_exchange';
  if (normalized === '_exchange-response') return '_exchange-response';
  return '_dcr';
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function isUnifiedTestTermsPrefixEnabled(): boolean | undefined {
  if (process.env.ICA_ENABLE_TEST_TERMS_PREFIX === undefined) return undefined;
  return parseBoolean(process.env.ICA_ENABLE_TEST_TERMS_PREFIX, false);
}

function parseCsvList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function isValidVersionToken(resourceType: string): boolean {
  if (!/^\d{12}$/.test(resourceType)) return false;
  const year = Number.parseInt(resourceType.slice(0, 4), 10);
  const day = Number.parseInt(resourceType.slice(4, 6), 10);
  const month = Number.parseInt(resourceType.slice(6, 8), 10);
  const hour = Number.parseInt(resourceType.slice(8, 10), 10);
  const minute = Number.parseInt(resourceType.slice(10, 12), 10);
  if (year < 2000 || year > 2100) return false;
  if (day < 1 || day > 31) return false;
  if (month < 1 || month > 12) return false;
  if (hour < 0 || hour > 23) return false;
  return minute >= 0 && minute <= 59;
}

function configuredLocalTenantId(): string | null {
  const localTenantId = (process.env.ICA_LOCAL_TENANT_ID || '').trim();
  return localTenantId || null;
}

function configuredActiveResourceTypes(): Set<string> | null {
  const values = parseCsvList(process.env.ICA_TERMS_ACTIVE_RESOURCE_TYPES);
  if (!values.length) return null;
  return new Set(values.map((value) => value.toLowerCase()));
}

function validateJurisdiction(jurisdiction: string):
  | { ok: false; statusCode: number; message: string }
  | null {
  if (!jurisdiction) {
    return { ok: false, statusCode: 400, message: 'jurisdiction is required in path.' };
  }
  if (!isSupportedJurisdiction(jurisdiction)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedJurisdictionErrorMessage(),
    };
  }
  return null;
}

function parseResourceType(rawResourceType: string):
  | { ok: true; normalized: string }
  | { ok: false; statusCode: number; message: string } {
  const resourceType = rawResourceType.trim();
  if (!resourceType) {
    return {
      ok: false,
      statusCode: 400,
      message: 'resourceType must be provided in path.',
    };
  }

  if (resourceType.toLowerCase() === 'contract') {
    return { ok: true, normalized: 'contract' };
  }

  const unifiedFlag = isUnifiedTestTermsPrefixEnabled();
  const allowTestPrefix = unifiedFlag !== undefined
    ? unifiedFlag
    : parseBoolean(process.env.ICA_ALLOW_TEST_RESOURCE_TYPE_PREFIX, false);
  const isTestVersion = resourceType.toLowerCase().startsWith('test-');
  if (!isTestVersion) {
    if (!isValidVersionToken(resourceType)) {
      return {
        ok: false,
        statusCode: 400,
        message: 'resourceType must be "contract" or a version token in format yyyyddmmhhmm.',
      };
    }
    return { ok: true, normalized: resourceType };
  }

  if (!allowTestPrefix) {
    return {
      ok: false,
      statusCode: 400,
      message:
        'resourceType with "test-" prefix is disabled. Set ICA_ENABLE_TEST_TERMS_PREFIX=true for testing.',
    };
  }

  const innerVersion = resourceType.slice(5);
  if (!isValidVersionToken(innerVersion)) {
    return {
      ok: false,
      statusCode: 400,
      message: 'resourceType must use format test-yyyyddmmhhmm when test prefix is enabled.',
    };
  }

  return { ok: true, normalized: `test-${innerVersion}` };
}

export type ParsedRoute =
  | { ok: true; context: VerifyRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseVerifyRoute(pathname: string): ParsedRoute | null {
  const match = VERIFY_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const rawResourceType = match.groups.resourceType.trim();
  const action = asAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }
  const parsedResourceType = parseResourceType(rawResourceType);
  if (!parsedResourceType.ok) return parsedResourceType;
  const activeResourceTypes = configuredActiveResourceTypes();
  if (activeResourceTypes && !activeResourceTypes.has(parsedResourceType.normalized.toLowerCase())) {
    return {
      ok: false,
      statusCode: 400,
      message: `resourceType "${parsedResourceType.normalized}" is not active for verification.`,
    };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'terms',
      format: 'pdf',
      resourceType: parsedResourceType.normalized,
      action,
    },
  };
}

export type ParsedTermsRemoveRoute =
  | { ok: true; context: TermsRemoveRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseTermsRemoveRoute(pathname: string): ParsedTermsRemoveRoute | null {
  const match = TERMS_REMOVE_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const rawResourceType = match.groups.resourceType.trim();
  const action = asTermsRemoveAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }
  const parsedResourceType = parseResourceType(rawResourceType);
  if (!parsedResourceType.ok) return parsedResourceType;

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'terms',
      format: 'pdf',
      resourceType: parsedResourceType.normalized,
      action,
    },
  };
}

export function buildTermsRemoveResponseLocation(
  context: TermsRemoveRouteContext,
  params?: Record<string, string | undefined>,
): string {
  const base = `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/terms/pdf/${context.resourceType}/_remove-response`;
  if (!params) return base;
  const entries = Object.entries(params).filter(([, value]) => value && value.trim());
  if (!entries.length) return base;
  const search = new URLSearchParams();
  for (const [key, value] of entries) {
    if (value) search.set(key, value);
  }
  const suffix = search.toString();
  return suffix ? `${base}?${suffix}` : base;
}

export function buildVerifyResponseLocation(
  context: VerifyRouteContext,
  params?: Record<string, string | undefined>,
): string {
  const base = `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/terms/pdf/${context.resourceType}/_verify-response`;
  if (!params) return base;
  const entries = Object.entries(params).filter(([, value]) => value && value.trim());
  if (!entries.length) return base;
  const search = new URLSearchParams();
  for (const [key, value] of entries) {
    if (value) search.set(key, value);
  }
  const suffix = search.toString();
  return suffix ? `${base}?${suffix}` : base;
}

export type ParsedActivateRoute =
  | { ok: true; context: ActivateRouteContext }
  | { ok: false; statusCode: number; message: string };

type ParsedEntityKeysRoute =
  | {
    ok: true;
    route: {
      tenantId: string;
      jurisdiction: string;
      sector: AllowedSector;
      resourceType: 'credentials' | 'communications';
      action: string;
    };
  }
  | { ok: false; statusCode: number; message: string };

function parseEntityKeysRoute(pathname: string): ParsedEntityKeysRoute | null {
  const match = ENTITY_KEYS_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const resourceType = match.groups.resourceType.trim().toLowerCase() as 'credentials' | 'communications';
  const action = match.groups.action.trim().toLowerCase();

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }

  return {
    ok: true,
    route: {
      tenantId,
      jurisdiction,
      sector,
      resourceType,
      action,
    },
  };
}

export function parseActivateRoute(pathname: string): ParsedActivateRoute | null {
  const parsed = parseEntityKeysRoute(pathname);
  if (!parsed) return null;
  if (!parsed.ok) return parsed;
  const { route } = parsed;
  if (route.action !== '_activate' && route.action !== '_activate-response') return null;
  if (route.resourceType !== 'credentials') {
    return {
      ok: false,
      statusCode: 400,
      message: 'Only /entity/keys/credentials supports _activate actions.',
    };
  }

  return {
    ok: true,
    context: {
      tenantId: route.tenantId,
      jurisdiction: route.jurisdiction,
      sector: route.sector,
      section: 'entity',
      format: 'keys',
      resourceType: 'credentials',
      action: asActivateAction(route.action),
    },
  };
}

export function buildActivateResponseLocation(context: ActivateRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/entity/keys/credentials/_activate-response`;
}

export type ParsedRotateRoute =
  | { ok: true; context: RotateRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseRotateRoute(pathname: string): ParsedRotateRoute | null {
  const parsed = parseEntityKeysRoute(pathname);
  if (!parsed) return null;
  if (!parsed.ok) return parsed;
  const { route } = parsed;
  if (route.action !== '_rotate' && route.action !== '_rotate-response') return null;

  return {
    ok: true,
    context: {
      tenantId: route.tenantId,
      jurisdiction: route.jurisdiction,
      sector: route.sector,
      section: 'entity',
      format: 'keys',
      resourceType: route.resourceType,
      action: asRotateAction(route.action),
    },
  };
}

export function buildRotateResponseLocation(context: RotateRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/entity/keys/${context.resourceType}/_rotate-response`;
}

export type ParsedCreateDidDocumentRoute =
  | { ok: true; context: CreateDidDocumentRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseCreateDidDocumentRoute(pathname: string): ParsedCreateDidDocumentRoute | null {
  const match = ENTITY_DID_DOCUMENT_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const action = asCreateDidDocumentAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'entity',
      format: 'did',
      resourceType: 'document',
      action,
    },
  };
}

export function buildCreateDidDocumentResponseLocation(
  context: CreateDidDocumentRouteContext,
  params?: Record<string, string | undefined>,
): string {
  const base = `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/entity/did/document/_create-response`;
  if (!params) return base;
  const entries = Object.entries(params).filter(([, value]) => value && value.trim());
  if (!entries.length) return base;
  const search = new URLSearchParams();
  for (const [key, value] of entries) {
    if (value) search.set(key, value);
  }
  const suffix = search.toString();
  return suffix ? `${base}?${suffix}` : base;
}

export type ParsedAddEvidenceRoute =
  | { ok: true; context: AddEvidenceRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseAddEvidenceRoute(pathname: string): ParsedAddEvidenceRoute | null {
  const match = NETWORK_EVIDENCE_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const evidenceType = match.groups.evidenceType.trim().toLowerCase();
  const action = asAddEvidenceAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }
  if (!evidenceType) {
    return { ok: false, statusCode: 400, message: 'evidenceType is required in path.' };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'network',
      format: 'evidence',
      evidenceType,
      action,
    },
  };
}

export function buildAddEvidenceResponseLocation(context: AddEvidenceRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/network/evidence/${context.evidenceType}/_add-response`;
}

export type ParsedDelegationPolicyRoute =
  | { ok: true; context: DelegationPolicyRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseDelegationPolicyRoute(pathname: string): ParsedDelegationPolicyRoute | null {
  const match = NETWORK_POLICY_DELEGATION_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const action = asDelegationPolicyAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'network',
      format: 'policies',
      policyType: 'delegations',
      action,
    },
  };
}

export function buildDelegationPolicyResponseLocation(context: DelegationPolicyRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/network/policies/delegations/_upsert-response`;
}

export type ParsedIssueCredentialRoute =
  | { ok: true; context: IssueCredentialRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseIssueCredentialRoute(pathname: string): ParsedIssueCredentialRoute | null {
  const match = NETWORK_CREDENTIAL_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const credentialType = match.groups.credentialType.trim();
  const action = asIssueCredentialAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }
  if (!credentialType) {
    return { ok: false, statusCode: 400, message: 'credentialType is required in path.' };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'network',
      format: 'credentials',
      credentialType,
      action,
    },
  };
}

export function buildIssueCredentialResponseLocation(context: IssueCredentialRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/network/credentials/${context.credentialType}/_issue-response`;
}

export type ParsedCredentialStatusRoute =
  | { ok: true; context: CredentialStatusRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseCredentialStatusRoute(pathname: string): ParsedCredentialStatusRoute | null {
  const match = NETWORK_CREDENTIAL_STATUS_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const credentialType = match.groups.credentialType.trim();
  const action = asCredentialStatusAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }
  if (!credentialType) {
    return { ok: false, statusCode: 400, message: 'credentialType is required in path.' };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'network',
      format: 'credentials',
      credentialType,
      action,
    },
  };
}

export function buildCredentialStatusResponseLocation(context: CredentialStatusRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/network/credentials/${context.credentialType}/_status-response`;
}

export type ParsedCredentialRevokeRoute =
  | { ok: true; context: CredentialRevokeRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseCredentialRevokeRoute(pathname: string): ParsedCredentialRevokeRoute | null {
  const match = NETWORK_CREDENTIAL_REVOKE_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const credentialType = match.groups.credentialType.trim();
  const action = asCredentialRevokeAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }
  if (!credentialType) {
    return { ok: false, statusCode: 400, message: 'credentialType is required in path.' };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'network',
      format: 'credentials',
      credentialType,
      action,
    },
  };
}

export function buildCredentialRevokeResponseLocation(context: CredentialRevokeRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/network/credentials/${context.credentialType}/_revoke-response`;
}

export type ParsedCredentialSearchRoute =
  | { ok: true; context: CredentialSearchRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseCredentialSearchRoute(pathname: string): ParsedCredentialSearchRoute | null {
  const match = NETWORK_CREDENTIAL_SEARCH_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const credentialType = match.groups.credentialType.trim();
  const action = asCredentialSearchAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }
  if (!credentialType) {
    return { ok: false, statusCode: 400, message: 'credentialType is required in path.' };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'network',
      format: 'credentials',
      credentialType,
      action,
    },
  };
}

export function buildCredentialSearchResponseLocation(context: CredentialSearchRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/network/credentials/${context.credentialType}/_search-response`;
}

export type ParsedCredentialRetrieveRoute =
  | { ok: true; context: CredentialRetrieveRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseCredentialRetrieveRoute(pathname: string): ParsedCredentialRetrieveRoute | null {
  const match = NETWORK_CREDENTIAL_RETRIEVE_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const credentialType = match.groups.credentialType.trim();
  const action = asCredentialRetrieveAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }
  if (!credentialType) {
    return { ok: false, statusCode: 400, message: 'credentialType is required in path.' };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'network',
      format: 'credentials',
      credentialType,
      action,
    },
  };
}

export function buildCredentialRetrieveResponseLocation(context: CredentialRetrieveRouteContext): string {
  return `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/network/credentials/${context.credentialType}/_retrieve-response`;
}

export type ParsedSpacesRoute =
  | { ok: true; context: SpacesRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseSpacesRoute(pathname: string): ParsedSpacesRoute | null {
  const match = NETWORK_SPACES_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;

  const tenantId = match.groups.tenantId.trim();
  const jurisdiction = match.groups.jurisdiction.trim();
  const sector = match.groups.sector.trim().toLowerCase() as AllowedSector;
  const action = asSpacesAction(match.groups.action.trim());

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }

  return {
    ok: true,
    context: {
      tenantId,
      jurisdiction,
      sector,
      section: 'network',
      format: 'spaces',
      action,
    },
  };
}

type ParsedAuthRouteBase =
  | {
    ok: true;
    route: {
      tenantId: string;
      jurisdiction: string;
      sector: AllowedSector;
      action: string;
    };
  }
  | { ok: false; statusCode: number; message: string };

function parseAuthRouteBase(groups: Record<string, string>): ParsedAuthRouteBase {
  const tenantId = groups.tenantId.trim();
  const jurisdiction = groups.jurisdiction.trim();
  const sector = groups.sector.trim().toLowerCase() as AllowedSector;
  const action = groups.action.trim().toLowerCase();

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }

  return {
    ok: true,
    route: {
      tenantId,
      jurisdiction,
      sector,
      action,
    },
  };
}

export type ParsedControllerExchangeRoute =
  | { ok: true; context: ControllerExchangeRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseControllerExchangeRoute(pathname: string): ParsedControllerExchangeRoute | null {
  const match = CONTROLLER_EXCHANGE_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;
  const parsed = parseAuthRouteBase(match.groups as Record<string, string>);
  if (!parsed.ok) return parsed;
  const action = asControllerExchangeAction(parsed.route.action);
  return {
    ok: true,
    context: {
      tenantId: parsed.route.tenantId,
      jurisdiction: parsed.route.jurisdiction,
      sector: parsed.route.sector,
      section: 'organization',
      format: 'dataspace-auth',
      action,
    },
  };
}

export function buildControllerExchangeResponseLocation(
  context: ControllerExchangeRouteContext,
  params?: Record<string, string | undefined>,
): string {
  const base = `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/organization/dataspace/auth/_exchange-response`;
  if (!params) return base;
  const entries = Object.entries(params).filter(([, value]) => value && value.trim());
  if (!entries.length) return base;
  const search = new URLSearchParams();
  for (const [key, value] of entries) {
    if (value) search.set(key, value);
  }
  const suffix = search.toString();
  return suffix ? `${base}?${suffix}` : base;
}

export type ParsedApiKeyProvisioningRoute =
  | { ok: true; context: ApiKeyProvisioningRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseApiKeyProvisioningRoute(pathname: string): ParsedApiKeyProvisioningRoute | null {
  const match = API_KEY_PROVISIONING_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;
  const parsed = parseAuthRouteBase(match.groups as Record<string, string>);
  if (!parsed.ok) return parsed;
  const action = asApiKeyProvisioningAction(parsed.route.action);
  return {
    ok: true,
    context: {
      tenantId: parsed.route.tenantId,
      jurisdiction: parsed.route.jurisdiction,
      sector: parsed.route.sector,
      section: 'api-key',
      format: 'org.schema.action',
      action,
    },
  };
}

export function buildApiKeyProvisioningResponseLocation(
  context: ApiKeyProvisioningRouteContext,
  params?: Record<string, string | undefined>,
): string {
  const actionBase = context.action.endsWith('-response') ? context.action.slice(0, -9) : context.action;
  const base = `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/api-key/org.schema/action/${actionBase}-response`;
  if (!params) return base;
  const entries = Object.entries(params).filter(([, value]) => value && value.trim());
  if (!entries.length) return base;
  const search = new URLSearchParams();
  for (const [key, value] of entries) {
    if (value) search.set(key, value);
  }
  const suffix = search.toString();
  return suffix ? `${base}?${suffix}` : base;
}

export type ParsedIdentityAuthRoute =
  | { ok: true; context: IdentityAuthRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseIdentityAuthRoute(pathname: string): ParsedIdentityAuthRoute | null {
  const match = IDENTITY_AUTH_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;
  const parsed = parseAuthRouteBase(match.groups as Record<string, string>);
  if (!parsed.ok) return parsed;
  const action = asIdentityAuthAction(parsed.route.action);
  return {
    ok: true,
    context: {
      tenantId: parsed.route.tenantId,
      jurisdiction: parsed.route.jurisdiction,
      sector: parsed.route.sector,
      section: 'identity',
      format: 'auth',
      action,
    },
  };
}

export function buildIdentityAuthResponseLocation(
  context: IdentityAuthRouteContext,
  params?: Record<string, string | undefined>,
): string {
  const actionBase = context.action.endsWith('-response') ? context.action.slice(0, -9) : context.action;
  const base = `/${context.tenantId}/cds-${context.jurisdiction}/v1/${context.sector}/identity/auth/${actionBase}-response`;
  if (!params) return base;
  const entries = Object.entries(params).filter(([, value]) => value && value.trim());
  if (!entries.length) return base;
  const search = new URLSearchParams();
  for (const [key, value] of entries) {
    if (value) search.set(key, value);
  }
  const suffix = search.toString();
  return suffix ? `${base}?${suffix}` : base;
}

type ParsedDcatRouteBase =
  | {
    ok: true;
    route: {
      tenantId: string;
      jurisdiction: string;
      sector: AllowedSector;
    };
  }
  | { ok: false; statusCode: number; message: string };

function parseDcatRouteBase(groups: Record<string, string>): ParsedDcatRouteBase {
  const tenantId = groups.tenantId.trim();
  const jurisdiction = groups.jurisdiction.trim();
  const sector = groups.sector.trim().toLowerCase() as AllowedSector;

  if (!tenantId) {
    return { ok: false, statusCode: 400, message: 'tenantId is required in path.' };
  }
  const localTenantId = configuredLocalTenantId();
  if (localTenantId && tenantId.toLowerCase() !== localTenantId.toLowerCase()) {
    return {
      ok: false,
      statusCode: 400,
      message: `tenantId must be "${localTenantId}" for this ICA deployment.`,
    };
  }
  const jurisdictionValidation = validateJurisdiction(jurisdiction);
  if (jurisdictionValidation) return jurisdictionValidation;
  if (!isSupportedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: getSupportedSectorErrorMessage(),
    };
  }

  return {
    ok: true,
    route: {
      tenantId,
      jurisdiction,
      sector,
    },
  };
}

export type ParsedDcatCatalogRequestRoute =
  | { ok: true; context: DcatCatalogRequestRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseDcatCatalogRequestRoute(pathname: string): ParsedDcatCatalogRequestRoute | null {
  const match = DCAT_CATALOG_REQUEST_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;
  const parsed = parseDcatRouteBase(match.groups as Record<string, string>);
  if (!parsed.ok) return parsed;
  return {
    ok: true,
    context: {
      tenantId: parsed.route.tenantId,
      jurisdiction: parsed.route.jurisdiction,
      sector: parsed.route.sector,
      section: 'dcat3',
      format: 'catalog',
      action: 'request',
    },
  };
}

export type ParsedDcatCatalogDatasetRoute =
  | { ok: true; context: DcatCatalogDatasetRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseDcatCatalogDatasetRoute(pathname: string): ParsedDcatCatalogDatasetRoute | null {
  const match = DCAT_CATALOG_DATASET_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;
  const parsed = parseDcatRouteBase(match.groups as Record<string, string>);
  if (!parsed.ok) return parsed;
  const datasetId = match.groups.datasetId.trim();
  if (!datasetId) {
    return { ok: false, statusCode: 400, message: 'dataset id is required in path.' };
  }
  return {
    ok: true,
    context: {
      tenantId: parsed.route.tenantId,
      jurisdiction: parsed.route.jurisdiction,
      sector: parsed.route.sector,
      section: 'dcat3',
      format: 'catalog',
      action: 'dataset',
      datasetId,
    },
  };
}

export type ParsedDcatCatalogDdoRequestRoute =
  | { ok: true; context: DcatCatalogDdoRequestRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseDcatCatalogDdoRequestRoute(pathname: string): ParsedDcatCatalogDdoRequestRoute | null {
  const match = DCAT_CATALOG_DDO_REQUEST_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;
  const parsed = parseDcatRouteBase(match.groups as Record<string, string>);
  if (!parsed.ok) return parsed;
  return {
    ok: true,
    context: {
      tenantId: parsed.route.tenantId,
      jurisdiction: parsed.route.jurisdiction,
      sector: parsed.route.sector,
      section: 'dcat3',
      format: 'catalog-ddo',
      action: 'ddo-request',
    },
  };
}

export type ParsedDcatCatalogDdoDatasetRoute =
  | { ok: true; context: DcatCatalogDdoDatasetRouteContext }
  | { ok: false; statusCode: number; message: string };

export function parseDcatCatalogDdoDatasetRoute(pathname: string): ParsedDcatCatalogDdoDatasetRoute | null {
  const match = DCAT_CATALOG_DDO_DATASET_ROUTE_REGEX.exec(pathname);
  if (!match?.groups) return null;
  const parsed = parseDcatRouteBase(match.groups as Record<string, string>);
  if (!parsed.ok) return parsed;
  const datasetId = match.groups.datasetId.trim();
  if (!datasetId) {
    return { ok: false, statusCode: 400, message: 'dataset id is required in path.' };
  }
  return {
    ok: true,
    context: {
      tenantId: parsed.route.tenantId,
      jurisdiction: parsed.route.jurisdiction,
      sector: parsed.route.sector,
      section: 'dcat3',
      format: 'catalog-ddo',
      action: 'ddo-dataset',
      datasetId,
    },
  };
}
