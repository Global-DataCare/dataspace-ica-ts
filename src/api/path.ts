import type {
  ActivateAction,
  ActivateRouteContext,
  AddEvidenceAction,
  AddEvidenceRouteContext,
  AllowedSector,
  DelegationPolicyAction,
  DelegationPolicyRouteContext,
  CredentialRevokeAction,
  CredentialRevokeRouteContext,
  CredentialStatusAction,
  CredentialStatusRouteContext,
  IssueCredentialAction,
  IssueCredentialRouteContext,
  RotateAction,
  RotateRouteContext,
  VerifyAction,
  VerifyRouteContext,
} from './types.ts';

const VERIFY_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/terms\/pdf\/(?<resourceType>[^/]+)\/(?<action>_verify(?:-response)?)$/i;
const ENTITY_KEYS_ROUTE_REGEX =
  /^\/(?<tenantId>[^/]+)\/cds-(?<jurisdiction>[^/]+)\/v1\/(?<sector>[^/]+)\/entity\/keys\/(?<resourceType>credentials|communications)\/(?<action>_(?:activate(?:-response)?|rotate(?:-response)?))$/i;
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

const ONEHEALTH_SECTOR_PREFIXES = ['animal', 'health'] as const;
const ALLOWED_SECTOR_ERROR =
  'sector must start with "animal" or "health" (onehealth-compatible sector namespaces).';

function isAllowedSector(rawSector: string): rawSector is AllowedSector {
  const normalized = rawSector.trim().toLowerCase();
  if (!normalized) return false;
  return ONEHEALTH_SECTOR_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function asAction(raw: string): VerifyAction {
  return raw.toLowerCase() === '_verify-response' ? '_verify-response' : '_verify';
}

function asActivateAction(raw: string): ActivateAction {
  return raw.toLowerCase() === '_activate-response' ? '_activate-response' : '_activate';
}

function asRotateAction(raw: string): RotateAction {
  return raw.toLowerCase() === '_rotate-response' ? '_rotate-response' : '_rotate';
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
        message: 'resourceType must be a version token in format yyyyddmmhhmm.',
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
  if (!jurisdiction) {
    return { ok: false, statusCode: 400, message: 'jurisdiction is required in path.' };
  }
  if (!isAllowedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: ALLOWED_SECTOR_ERROR,
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
  if (!jurisdiction) {
    return { ok: false, statusCode: 400, message: 'jurisdiction is required in path.' };
  }
  if (!isAllowedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: ALLOWED_SECTOR_ERROR,
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
  if (!jurisdiction) {
    return { ok: false, statusCode: 400, message: 'jurisdiction is required in path.' };
  }
  if (!isAllowedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: ALLOWED_SECTOR_ERROR,
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
  if (!jurisdiction) {
    return { ok: false, statusCode: 400, message: 'jurisdiction is required in path.' };
  }
  if (!isAllowedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: ALLOWED_SECTOR_ERROR,
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
  if (!jurisdiction) {
    return { ok: false, statusCode: 400, message: 'jurisdiction is required in path.' };
  }
  if (!isAllowedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: ALLOWED_SECTOR_ERROR,
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
  if (!jurisdiction) {
    return { ok: false, statusCode: 400, message: 'jurisdiction is required in path.' };
  }
  if (!isAllowedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: ALLOWED_SECTOR_ERROR,
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
  if (!jurisdiction) {
    return { ok: false, statusCode: 400, message: 'jurisdiction is required in path.' };
  }
  if (!isAllowedSector(sector)) {
    return {
      ok: false,
      statusCode: 400,
      message: ALLOWED_SECTOR_ERROR,
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
