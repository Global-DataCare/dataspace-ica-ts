import { multibase58MultihashSha3_256 } from './multihash.ts';

type ControllerMemberDescriptor = {
  did: string;
  didJsonPath: string;
  tenantId: string;
  jurisdiction: string;
  sector: string;
  memberType: string;
  role: string;
  idHash: string;
};

const DID_WEB_PREFIX = 'did:web:';

function normalizeRole(raw: string | undefined): string {
  const value = (raw || '').trim();
  if (!value) return '1120';
  return value.replace(/[^A-Za-z0-9._-]/g, '');
}

function normalizeEmailForControllerId(email: string): string {
  return email.trim().toLowerCase();
}

function normalizeCsvToken(raw: string | undefined): string {
  return (raw || '').trim();
}

function resolveControllerSector(raw: string | undefined): string {
  const normalized = normalizeCsvToken(raw).toLowerCase();
  const sanitized = normalized.replace(/[^a-z0-9._-]/g, '');
  if (!sanitized || sanitized === 'controller' || sanitized === 'administration') return 'management';
  return sanitized;
}

function resolveControllerMemberType(raw: string | undefined): string {
  const normalized = normalizeCsvToken(raw).toLowerCase();
  const sanitized = normalized.replace(/[^a-z0-9._-]/g, '');
  return sanitized || 'controller';
}

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parseDidWebSegments(did: string): string[] | null {
  const normalized = did.trim();
  if (!normalized.startsWith(DID_WEB_PREFIX)) return null;
  const suffix = normalized.slice(DID_WEB_PREFIX.length).trim();
  if (!suffix) return null;
  const segments = suffix.split(':').map((part) => part.trim()).filter(Boolean);
  if (!segments.length) return null;
  return segments;
}

function buildDidWeb(segments: string[]): string {
  return `${DID_WEB_PREFIX}${segments.join(':')}`;
}

function toDidWebDidJsonPath(did: string): string | null {
  const segments = parseDidWebSegments(did);
  if (!segments) return null;
  const pathSegments = segments.slice(1).map((segment) => safeDecodeURIComponent(segment));
  if (!pathSegments.length) return '/did.json';
  return `/${pathSegments.join('/')}/did.json`;
}

export function deriveControllerEmailHashFromEmail(email: string): string {
  const normalized = normalizeEmailForControllerId(email);
  if (!normalized) {
    throw new Error('Cannot derive controller email hash from empty email.');
  }
  return multibase58MultihashSha3_256(normalized);
}

export function resolveConfiguredControllerEmailHash(): string {
  const configuredHash = normalizeCsvToken(process.env.ICA_SELF_CONTROLLER_EMAIL_HASH);
  if (configuredHash) return configuredHash;
  const email = normalizeCsvToken(process.env.ICA_SELF_CONTROLLER_EMAIL);
  if (!email) return '';
  return deriveControllerEmailHashFromEmail(email);
}

export function resolveControllerMemberDescriptor(issuerDid: string): ControllerMemberDescriptor | null {
  const explicitDid = normalizeCsvToken(process.env.ICA_SELF_CONTROLLER_DID);
  if (explicitDid) {
    const didJsonPath = toDidWebDidJsonPath(explicitDid);
    if (!didJsonPath) return null;
    const idHash = resolveConfiguredControllerEmailHash();
    return {
      did: explicitDid,
      didJsonPath,
      tenantId: normalizeCsvToken(process.env.ICA_SELF_CONTROLLER_TENANT_ID || process.env.ICA_LOCAL_TENANT_ID || 'ica') || 'ica',
      jurisdiction: normalizeCsvToken(process.env.ICA_SELF_CONTROLLER_JURISDICTION).toUpperCase(),
      sector: resolveControllerSector(process.env.ICA_SELF_CONTROLLER_SECTOR),
      memberType: resolveControllerMemberType(process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE),
      role: normalizeRole(process.env.ICA_SELF_CONTROLLER_ROLE),
      idHash,
    };
  }

  const idHash = resolveConfiguredControllerEmailHash();
  if (!idHash) return null;

  const role = normalizeRole(process.env.ICA_SELF_CONTROLLER_ROLE);
  const tenantId = normalizeCsvToken(process.env.ICA_SELF_CONTROLLER_TENANT_ID || process.env.ICA_LOCAL_TENANT_ID || 'ica') || 'ica';
  const jurisdiction = normalizeCsvToken(process.env.ICA_SELF_CONTROLLER_JURISDICTION).toUpperCase();
  const sector = resolveControllerSector(process.env.ICA_SELF_CONTROLLER_SECTOR);
  const memberType = resolveControllerMemberType(process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE);
  if (!jurisdiction) {
    return null;
  }

  const issuerSegments = parseDidWebSegments(issuerDid);
  if (!issuerSegments) return null;
  const controllerSegments = [
    ...issuerSegments,
    tenantId,
    `cds-${jurisdiction}`,
    'v1',
    sector,
    memberType,
    role,
    idHash,
  ];
  const did = buildDidWeb(controllerSegments);
  const didJsonPath = toDidWebDidJsonPath(did);
  if (!didJsonPath) return null;

  return {
    did,
    didJsonPath,
    tenantId,
    jurisdiction,
    sector,
    memberType,
    role,
    idHash,
  };
}
