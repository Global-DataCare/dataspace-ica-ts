import type {
  CreateDidDocumentControllerInput,
  CreateDidDocumentInput,
  SupportedSigningAlgorithm,
} from '../types.ts';
import { computeRfc7638JwkThumbprint } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import { base58btcEncode } from './multihash.ts';
import { maybeAttachOrganizationX5c } from './organization-self-ca.ts';

type JsonObject = Record<string, unknown>;
type ParsedOrganizationDid = {
  authority: string;
  sector: string;
  taxId: string;
};

function normalizeDidWebAuthority(raw: string | undefined): string {
  const trimmed = (raw || '').trim();
  if (!trimmed) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      return new URL(trimmed).host.toLowerCase();
    } catch {
      return '';
    }
  }
  return trimmed.split('/')[0].trim().toLowerCase();
}

function encodeDidWebAuthority(authority: string): string {
  return authority.replace(/:/g, '%3A');
}

function normalizeTaxId(raw: string | undefined): string {
  return (raw || '').trim().toUpperCase();
}

function parseDidWebSegments(did: string): string[] | null {
  const normalized = did.trim();
  if (!normalized.startsWith('did:web:')) return null;
  const suffix = normalized.slice('did:web:'.length).trim();
  if (!suffix) return null;
  return suffix.split(':').map((part) => part.trim()).filter(Boolean);
}

function parseOrganizationDid(did: string): ParsedOrganizationDid | null {
  const segments = parseDidWebSegments(did);
  if (!segments || segments.length < 5) return null;
  const [rawAuthority, sector, resourceType, idType, ...taxIdParts] = segments;
  if (!rawAuthority || !sector || resourceType !== 'organization' || idType !== 'taxid' || !taxIdParts.length) {
    return null;
  }
  return {
    authority: rawAuthority,
    sector,
    taxId: taxIdParts.join(':').toUpperCase(),
  };
}

export function extractOrganizationDidTaxId(did: string): string | undefined {
  return parseOrganizationDid(did)?.taxId;
}

function inferJurisdictionFromTaxId(taxId: string): string | undefined {
  const normalized = normalizeTaxId(taxId);
  if (!normalized) return undefined;
  if (normalized.startsWith('VATES')) return 'ES';
  const match = /^VAT([A-Z]{2})(?:[-:].*)?$/.exec(normalized);
  if (match?.[1]) return match[1];
  return undefined;
}

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function inferAlgFromJwk(publicKeyJwk: JsonObject): SupportedSigningAlgorithm | undefined {
  const configured = asNonEmptyString(publicKeyJwk.alg).toUpperCase();
  if (configured === 'ES384') return 'ES384';
  if (configured === 'ES256K') return 'ES256K';
  if (configured === 'RS256') return 'RS256';
  if (configured === 'PS256') return 'PS256';
  if (configured === 'EDDSA') return 'EdDSA';

  const kty = asNonEmptyString(publicKeyJwk.kty);
  const crv = asNonEmptyString(publicKeyJwk.crv);
  if (kty === 'EC' && crv === 'P-384') return 'ES384';
  if (kty === 'EC' && crv === 'secp256k1') return 'ES256K';
  if (kty === 'RSA') return 'RS256';
  if (kty === 'OKP' && (crv === 'Ed25519' || crv === 'Ed448')) return 'EdDSA';
  return undefined;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((entry) => (typeof entry === 'string' ? entry.trim() : '')).filter(Boolean)
    : [];
}

function stripPrivateJwkParameters(publicKeyJwk: JsonObject): JsonObject {
  const clone: JsonObject = { ...publicKeyJwk };
  // EC/OKP private parameter
  delete clone.d;
  // RSA private parameters
  delete clone.p;
  delete clone.q;
  delete clone.dp;
  delete clone.dq;
  delete clone.qi;
  delete clone.oth;
  // Symmetric secret key material
  delete clone.k;
  return clone;
}

function assertPublicJwk(publicKeyJwk: JsonObject, label: string): void {
  const privateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
  const exposed = privateMembers.find((member) => member in publicKeyJwk);
  if (exposed) {
    throw new Error(`${label} must not contain private JWK member "${exposed}".`);
  }
}

function normalizeDidDocumentMethodJwk(publicKeyJwk: JsonObject, fallbackUse?: 'sig' | 'enc'): JsonObject {
  const sanitizedPublicJwk = stripPrivateJwkParameters(publicKeyJwk);
  const kid = asNonEmptyString(sanitizedPublicJwk.kid)
    || computeRfc7638JwkThumbprint(normalizeJwkForThumbprint(sanitizedPublicJwk));
  const alg = inferAlgFromJwk(sanitizedPublicJwk);
  return {
    ...sanitizedPublicJwk,
    kid,
    ...(alg && !asNonEmptyString(sanitizedPublicJwk.alg) ? { alg } : {}),
    ...(fallbackUse && !asNonEmptyString(sanitizedPublicJwk.use) ? { use: fallbackUse } : {}),
  };
}

function classifyDidDocumentRelationships(publicKeyJwk: JsonObject): {
  assertionMethod: boolean;
  authentication: boolean;
  keyAgreement: boolean;
} {
  const purposes = new Set(asStringArray(publicKeyJwk.purposes).map((entry) => entry.toLowerCase()));
  const use = asNonEmptyString(publicKeyJwk.use).toLowerCase();
  return {
    assertionMethod: purposes.has('vc-sign'),
    authentication: purposes.has('didcomm-sign') || (purposes.size === 0 && use === 'sig'),
    keyAgreement: purposes.has('didcomm-enc') || (purposes.size === 0 && use === 'enc'),
  };
}


// Returns the canonical domain for did:web identifiers.
// 1. If DID_WEB_DOMAIN is set, extract the domain (if starts with did:web:, use third segment; else use as is).
// 2. If not set, autodetect from request (host/ip:port) if available, else throw error.
export function resolveOrganizationNodeOperatorDomain(req?: { headers?: { host?: string } }): string {
  const didWebDomain = process.env.DID_WEB_DOMAIN;
  if (didWebDomain && didWebDomain.startsWith('did:web:')) {
    const parts = didWebDomain.split(':');
    if (parts.length > 2 && parts[2]) {
      return normalizeDidWebAuthority(parts[2]);
    }
  } else if (didWebDomain) {
    return normalizeDidWebAuthority(didWebDomain);
  }
  // Autodetect from request if available
  if (req && req.headers && req.headers.host) {
    return normalizeDidWebAuthority(req.headers.host);
  }
  throw new Error('DID_WEB_DOMAIN is not set and request host is unavailable. Cannot determine did:web domain.');
}

export function buildOrganizationDidFromTaxId(sector: string, taxId: string, authority?: string): string {
  const normalizedTaxId = normalizeTaxId(taxId);
  if (!normalizedTaxId) {
    throw new Error('Organization taxID is required to derive organization did:web.');
  }
  const normalizedAuthority = normalizeDidWebAuthority(
    authority !== undefined ? authority : resolveOrganizationNodeOperatorDomain(),
  );
  if (!normalizedAuthority) {
    throw new Error(
      authority !== undefined
        ? 'organization.url is empty or invalid.'
        : 'ORG_PUBLIC_DOMAIN_NODE_OPERATOR is empty or invalid.',
    );
  }
  return `did:web:${encodeDidWebAuthority(normalizedAuthority)}:${sector}:organization:taxid:${normalizedTaxId}`;
}

export function resolveOrganizationDid(
  sector: string,
  input: { id?: string; organization?: { identifier?: string; taxID?: string; taxId?: string } },
): string {
  const explicitId = asNonEmptyString(input.id || input.organization?.identifier);
  if (explicitId) return explicitId;
  const taxId = asNonEmptyString(input.organization?.taxID || input.organization?.taxId);
  return buildOrganizationDidFromTaxId(sector, taxId);
}

export function validateOrganizationDidInput(input: {
  did: string;
  sector: string;
  jurisdiction: string;
  taxId?: string;
}): void {
  const parsed = parseOrganizationDid(input.did);
  if (!parsed) {
    throw new Error('organization.identifier must use did:web:<authority>:<sector>:organization:taxid:<taxID>.');
  }
  if (parsed.sector.toLowerCase() !== input.sector.trim().toLowerCase()) {
    throw new Error(`organization.identifier sector "${parsed.sector}" must match path sector "${input.sector}".`);
  }

  const expectedTaxId = normalizeTaxId(input.taxId);
  if (expectedTaxId && parsed.taxId !== expectedTaxId) {
    throw new Error(`organization.identifier taxid "${parsed.taxId}" must match organization.taxID "${expectedTaxId}".`);
  }

  const jurisdictionFromTaxId = inferJurisdictionFromTaxId(expectedTaxId || parsed.taxId);
  if (jurisdictionFromTaxId && jurisdictionFromTaxId !== input.jurisdiction.trim().toUpperCase()) {
    throw new Error(
      `organization.taxID jurisdiction "${jurisdictionFromTaxId}" must match path jurisdiction "${input.jurisdiction.toUpperCase()}".`,
    );
  }
}

function normalizeJwkForThumbprint(publicKeyJwk: JsonObject): Record<string, string> {
  const sanitizedPublicJwk = stripPrivateJwkParameters(publicKeyJwk);
  return Object.fromEntries(
    Object.entries(sanitizedPublicJwk)
      .filter(([, value]) => typeof value === 'string')
      .map(([key, value]) => [key, String(value)]),
  );
}

function decodeBase64Url(value: string, label: string): Buffer {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${label} is empty.`);
  }
  return Buffer.from(trimmed, 'base64url');
}

function encodeVarint(value: number): Buffer {
  const bytes: number[] = [];
  let current = value >>> 0;
  while (current >= 0x80) {
    bytes.push((current & 0x7f) | 0x80);
    current >>>= 7;
  }
  bytes.push(current);
  return Buffer.from(bytes);
}

function compressEcPublicKey(xBytes: Buffer, yBytes: Buffer): Buffer {
  const yLastByte = yBytes[yBytes.length - 1] || 0;
  const prefix = (yLastByte & 1) === 1 ? 0x03 : 0x02;
  return Buffer.concat([Buffer.from([prefix]), xBytes]);
}

function deriveDidKeyFromPublicJwk(publicKeyJwk: JsonObject): string {
  const kty = asNonEmptyString(publicKeyJwk.kty);
  const crv = asNonEmptyString(publicKeyJwk.crv);

  if (kty === 'EC') {
    const xBytes = decodeBase64Url(asNonEmptyString(publicKeyJwk.x), 'publicKeyJwk.x');
    const yBytes = decodeBase64Url(asNonEmptyString(publicKeyJwk.y), 'publicKeyJwk.y');
    let codec: number;
    if (crv === 'P-384') codec = 0x1201;
    else if (crv === 'P-256') codec = 0x1200;
    else if (crv === 'secp256k1') codec = 0xe7;
    else throw new Error(`Unsupported EC curve for did:key derivation: ${crv || 'unknown'}.`);
    const compressed = compressEcPublicKey(xBytes, yBytes);
    const multicodec = Buffer.concat([encodeVarint(codec), compressed]);
    return `did:key:z${base58btcEncode(multicodec)}`;
  }

  if (kty === 'OKP') {
    const xBytes = decodeBase64Url(asNonEmptyString(publicKeyJwk.x), 'publicKeyJwk.x');
    let codec: number;
    if (crv === 'Ed25519') codec = 0xed;
    else if (crv === 'X25519') codec = 0xec;
    else throw new Error(`Unsupported OKP curve for did:key derivation: ${crv || 'unknown'}.`);
    const multicodec = Buffer.concat([encodeVarint(codec), xBytes]);
    return `did:key:z${base58btcEncode(multicodec)}`;
  }

  throw new Error(`Unsupported JWK kty for did:key derivation: ${kty || 'unknown'}.`);
}

export function buildOrganizationDidDocument(input: {
  did: string;
  controller: CreateDidDocumentControllerInput;
  organization: CreateDidDocumentInput['organization'];
}): {
  didDocument: JsonObject;
  verificationMethodId: string;
  verificationMethodKid: string;
  controllerKid: string;
  nodeOperator: string;
} {
  const did = asNonEmptyString(input.did);
  if (!did.startsWith('did:web:')) {
    throw new Error('Organization DID document id must be a did:web identifier.');
  }
  const organizationPublicKeyJwk = asObject(input.organization.publicKeyJwk);
  if (!organizationPublicKeyJwk) {
    throw new Error('organization.publicKeyJwk is required.');
  }
  const enrichedOrganizationPublicKeyJwk = maybeAttachOrganizationX5c({
    did,
    organization: input.organization,
    publicKeyJwk: organizationPublicKeyJwk,
  });
  const controllerPublicKeyJwk = asObject(input.controller.publicKeyJwk);
  if (!controllerPublicKeyJwk) {
    throw new Error('controller.publicKeyJwk is required.');
  }
  assertPublicJwk(controllerPublicKeyJwk, 'controller.publicKeyJwk');
  const organizationThumbprint = computeRfc7638JwkThumbprint(normalizeJwkForThumbprint(enrichedOrganizationPublicKeyJwk));
  const controllerThumbprint = computeRfc7638JwkThumbprint(normalizeJwkForThumbprint(controllerPublicKeyJwk));
  if (organizationThumbprint === controllerThumbprint) {
    throw new Error('organization.publicKeyJwk and controller.publicKeyJwk must be different keys.');
  }

  const controllerKid =
    asNonEmptyString(controllerPublicKeyJwk.kid)
    || controllerThumbprint;
  const explicitControllerDid = asNonEmptyString(input.controller.did);
  if (explicitControllerDid && !explicitControllerDid.startsWith('did:')) {
    throw new Error('controller.did must be a DID identifier.');
  }
  const controllerKeys = Array.isArray(input.controller.jwks?.keys) ? input.controller.jwks.keys : [];
  if (controllerKeys.length && !explicitControllerDid) {
    throw new Error('controller.did is required when controller.jwks contains additional keys.');
  }
  const seenControllerThumbprints = new Set<string>([controllerThumbprint]);
  for (const [index, candidate] of controllerKeys.entries()) {
    const controllerJwk = asObject(candidate);
    if (!controllerJwk) {
      throw new Error(`controller.jwks.keys[${index}] must be an object.`);
    }
    assertPublicJwk(controllerJwk, `controller.jwks.keys[${index}]`);
    const thumbprint = computeRfc7638JwkThumbprint(normalizeJwkForThumbprint(controllerJwk));
    if (seenControllerThumbprints.has(thumbprint)) {
      throw new Error(`controller.jwks.keys[${index}] duplicates another controller key.`);
    }
    seenControllerThumbprints.add(thumbprint);
  }
  const controllerDid = explicitControllerDid || deriveDidKeyFromPublicJwk(controllerPublicKeyJwk);
  const verificationMethodKid =
    asNonEmptyString(enrichedOrganizationPublicKeyJwk.kid)
    || organizationThumbprint;
  const verificationMethodId = `${did}#${verificationMethodKid}`;
  const normalizedOrganizationJwk = normalizeDidDocumentMethodJwk(
    {
      ...enrichedOrganizationPublicKeyJwk,
      ...(input.organization.alg ? { alg: input.organization.alg } : {}),
      use: 'sig',
    },
    'sig',
  );

  const verificationMethod: JsonObject[] = [
    {
      id: verificationMethodId,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: normalizedOrganizationJwk,
    },
  ];
  const assertionMethod = new Set<string>([verificationMethodId]);
  const authentication = new Set<string>([verificationMethodId]);
  const keyAgreement = new Set<string>();
  const seenMethodKids = new Set<string>([verificationMethodKid]);

  for (const extraKey of Array.isArray(input.organization.jwks?.keys) ? input.organization.jwks.keys : []) {
    const extraJwk = asObject(extraKey);
    if (!extraJwk) continue;
    const normalizedExtraJwk = normalizeDidDocumentMethodJwk(extraJwk);
    const extraKid = asNonEmptyString(normalizedExtraJwk.kid);
    if (!extraKid) {
      throw new Error('organization.jwks.keys[].kid could not be resolved.');
    }
    if (seenMethodKids.has(extraKid)) {
      throw new Error(`organization.jwks.keys[] contains duplicate key "${extraKid}".`);
    }
    const extraThumbprint = computeRfc7638JwkThumbprint(normalizeJwkForThumbprint(normalizedExtraJwk));
    if (extraThumbprint == controllerThumbprint) {
      throw new Error('organization.jwks.keys[] must not reuse controller.publicKeyJwk.');
    }
    seenMethodKids.add(extraKid);
    const extraMethodId = `${did}#${extraKid}`;
    verificationMethod.push({
      id: extraMethodId,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: normalizedExtraJwk,
    });
    const relationships = classifyDidDocumentRelationships(normalizedExtraJwk);
    if (relationships.assertionMethod) assertionMethod.add(extraMethodId);
    if (relationships.authentication) authentication.add(extraMethodId);
    if (relationships.keyAgreement) keyAgreement.add(extraMethodId);
  }

  const didDocument: JsonObject = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    controller: controllerDid,
    verificationMethod,
    assertionMethod: Array.from(assertionMethod),
    authentication: Array.from(authentication),
  };
  if (keyAgreement.size) {
    didDocument.keyAgreement = Array.from(keyAgreement);
  }

  const alsoKnownAsValues = [
    asNonEmptyString(input.organization?.sameAs),
  ].filter(Boolean);
  const uniqueAlsoKnownAs = alsoKnownAsValues.filter((value, index) => alsoKnownAsValues.indexOf(value) === index);
  if (uniqueAlsoKnownAs.length) {
    didDocument.alsoKnownAs = uniqueAlsoKnownAs;
  }

  return {
    didDocument,
    verificationMethodId,
    verificationMethodKid,
    controllerKid,
    nodeOperator: resolveOrganizationNodeOperatorDomain(),
  };
}
