import { createHash } from 'node:crypto';

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
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const MULTIHASH_SHA3_256_CODE = 0x16;
const MULTIHASH_SHA3_256_SIZE = 0x20;

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
  return normalized || 'controller';
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

function base58btcEncode(input: Buffer<ArrayBufferLike>): string {
  if (!input.length) return '';
  const digits: number[] = [0];
  for (const byte of input) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      const value = digits[index] * 256 + carry;
      digits[index] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = '';
  for (const byte of input) {
    if (byte === 0) output += BASE58_ALPHABET[0];
    else break;
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    output += BASE58_ALPHABET[digits[index]];
  }
  return output;
}

export function deriveControllerEmailHashFromEmail(email: string): string {
  const normalized = normalizeEmailForControllerId(email);
  if (!normalized) {
    throw new Error('Cannot derive controller email hash from empty email.');
  }
  const digest = createHash('sha3-256').update(normalized, 'utf8').digest();
  const multihash = Buffer.concat([Buffer.from([MULTIHASH_SHA3_256_CODE, MULTIHASH_SHA3_256_SIZE]), digest]);
  return `z${base58btcEncode(multihash)}`;
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
