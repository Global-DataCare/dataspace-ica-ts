import { createHash, createPublicKey, createVerify } from 'node:crypto';
import { toJwkThumbprintSha256Urn } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import type { VerifyResult, VerifyRouteContext, VerifySubmission } from './types.ts';

type JsonObject = Record<string, unknown>;

export type PreauthorizedHostEvidence = {
  domain: string;
  did: string;
  verificationMethod: string;
  ownerCredentialMaterial: string;
  governanceReference: string;
  requestSha384Hex: string;
};

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : undefined;
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function csv(value: string | undefined): string[] {
  return String(value || '').split(',').map((entry) => entry.trim().toLowerCase()).filter(Boolean);
}

function didWebDomain(did: string): string {
  if (!did.toLowerCase().startsWith('did:web:')) return '';
  const authority = did.slice('did:web:'.length).split(':')[0] || '';
  try {
    return decodeURIComponent(authority).split(':')[0].toLowerCase();
  } catch {
    return '';
  }
}

function didWebUrl(did: string): URL {
  const parts = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
  const authority = parts.shift();
  if (!authority) throw new Error('Preauthorized host must use a valid did:web issuer.');
  const path = parts.length ? `/${parts.map(encodeURIComponent).join('/')}/did.json` : '/.well-known/did.json';
  return new URL(`https://${authority}${path}`);
}

function configuredHostMatches(domain: string): boolean {
  return csv(process.env.ICA_PREAUTHORIZED_HOST_DOMAINS).some(
    (allowed) => domain === allowed || domain.endsWith(`.${allowed}`),
  );
}

function extractServiceDomain(claims: JsonObject): string {
  const rawUrl = text(claims['org.schema.Service.url']);
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    throw new Error('PDF-free host verification requires a valid org.schema.Service.url claim.');
  }
}

function decodeSegment(segment: string, label: string): Buffer {
  if (!segment) throw new Error(`Host authorization JWS ${label} is required.`);
  try {
    return Buffer.from(segment, 'base64url');
  } catch {
    throw new Error(`Host authorization JWS ${label} is invalid.`);
  }
}

/**
 * Authorizes the PDF-free branch from server policy and a signed did:web
 * request. The hostname allowlist establishes governance eligibility; the JWS
 * and resolved DID document establish control of that configured host.
 */
export async function verifyPreauthorizedHostEvidence(input: {
  route: VerifyRouteContext;
  envelope: JsonObject;
  resource: JsonObject;
}): Promise<PreauthorizedHostEvidence> {
  const allowedNetworks = csv(process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS || 'local-network');
  if (!allowedNetworks.includes(input.route.section.toLowerCase())) {
    throw new Error(`Network kind '${input.route.section}' is not authorized for PDF-free host verification.`);
  }
  const issuerDid = text(input.envelope.iss);
  const issuerDomain = didWebDomain(issuerDid);
  const organization = asObject(input.resource.organization) || {};
  const organizationDid = text(organization.did);
  const organizationDomain = didWebDomain(organizationDid);
  const meta = asObject(input.resource.meta);
  const claims = asObject(meta?.claims) || {};
  const serviceDomain = extractServiceDomain(claims);
  if (!issuerDomain || issuerDomain !== organizationDomain || issuerDomain !== serviceDomain) {
    throw new Error('PDF-free host verification requires matching issuer, organization did:web and Service URL domains.');
  }
  if (!configuredHostMatches(issuerDomain)) {
    throw new Error(`Host '${issuerDomain}' is not present in ICA_PREAUTHORIZED_HOST_DOMAINS.`);
  }

  const body = asObject(input.envelope.body) || {};
  const proof = asObject(body.hostAuthorizationProof);
  const compact = text(proof?.jws);
  const parts = compact.split('.');
  if (parts.length !== 3) throw new Error('PDF-free host verification requires body.hostAuthorizationProof.jws.');
  const [protectedEncoded, payloadEncoded, signatureEncoded] = parts;
  const header = JSON.parse(decodeSegment(protectedEncoded, 'protected header').toString('utf8')) as JsonObject;
  const signedAuthorization = JSON.parse(decodeSegment(payloadEncoded, 'payload').toString('utf8')) as JsonObject;
  const expectedAuthorization = {
    jurisdiction: input.route.jurisdiction.toUpperCase(),
    sector: input.route.sector,
    networkKind: input.route.section,
    resourceType: input.route.resourceType,
    resource: input.resource,
  };
  if (JSON.stringify(signedAuthorization) !== JSON.stringify(expectedAuthorization)) {
    throw new Error('Host authorization JWS payload must equal the ICA route scope plus body.data[0].resource.');
  }
  const headerKid = text(header.kid);
  if (!headerKid) throw new Error('Host authorization JWS kid is required.');
  const kid = headerKid.includes('#') ? headerKid : `${issuerDid}#${headerKid}`;
  if (!kid.startsWith(`${issuerDid}#`)) throw new Error('Host authorization JWS kid must belong to the issuer did:web.');
  if (text(header.alg).toUpperCase() !== 'ES384') throw new Error('Host authorization JWS must use ES384.');

  const response = await fetch(didWebUrl(issuerDid));
  if (!response.ok) throw new Error(`Unable to resolve preauthorized host DID document (${response.status}).`);
  const didDocument = await response.json() as JsonObject;
  if (text(didDocument.id) !== issuerDid) throw new Error('Resolved host DID document id does not match the request issuer.');
  const methods = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : [];
  const method = methods.map(asObject).find((candidate) => text(candidate?.id) === kid);
  const publicKeyJwk = asObject(method?.publicKeyJwk);
  if (!publicKeyJwk) throw new Error('Host authorization verification method was not found in the issuer DID document.');
  const verifier = createVerify('sha384');
  verifier.update(`${protectedEncoded}.${payloadEncoded}`);
  verifier.end();
  const valid = verifier.verify(
    { key: createPublicKey({ key: publicKeyJwk as any, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    decodeSegment(signatureEncoded, 'signature'),
  );
  if (!valid) throw new Error('Invalid preauthorized host JWS signature.');

  return {
    domain: issuerDomain,
    did: issuerDid,
    verificationMethod: kid,
    ownerCredentialMaterial: toJwkThumbprintSha256Urn(publicKeyJwk),
    governanceReference: `env:ICA_PREAUTHORIZED_HOST_DOMAINS#${issuerDomain}`,
    requestSha384Hex: createHash('sha384').update(payloadEncoded).digest('hex'),
  };
}

/** Builds the normal verification-result shape from governed host evidence. */
export class PreauthorizedHostVerificationService {
  async verify(_route: VerifyRouteContext, submission: VerifySubmission): Promise<VerifyResult> {
    const evidence = submission.preauthorizedHost;
    if (submission.evidenceKind !== 'preauthorized-host' || !evidence) {
      throw new Error('Preauthorized host evidence is required.');
    }
    const sha256 = createHash('sha256').update(evidence.requestSha384Hex).digest('hex');
    return {
      ok: true,
      evidenceKind: 'preauthorized-host',
      verifiedAt: new Date().toISOString(),
      templateUrl: '',
      templateMatch: true,
      signatureValid: true,
      chainValid: true,
      revocationStatus: 'good',
      digest: {
        alg: 'sha384',
        signedPdfHex: evidence.requestSha384Hex,
        unsignedPdfHex: evidence.requestSha384Hex,
        templateHex: evidence.requestSha384Hex,
      },
      signerSubject: evidence.did,
      signerIssuer: evidence.governanceReference,
      hashes: {
        signedPdfSha256Hex: sha256,
        unsignedPdfSha256Hex: sha256,
        templateSha256Hex: sha256,
      },
      notes: [
        `Host '${evidence.domain}' authorized by the server-side governance allowlist.`,
        `Host control verified with ${evidence.verificationMethod}.`,
        'No PDF was required or persisted for this governed host authorization.',
      ],
      annexFormFields: submission.annexFormFields,
      organizationPayload: submission.organizationPayload,
      legalRepresentativePayload: submission.legalRepresentativePayload,
    };
  }
}
