import { createHash, createPublicKey, createVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { toJwkThumbprintSha256Urn } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import type { VerifyResult, VerifyRouteContext, VerifySubmission } from './types.ts';
import { createHostActivationServiceFromEnv } from './host-activation.ts';

type JsonObject = Record<string, unknown>;

export type PreauthorizedHostEvidence = {
  domain: string;
  did: string;
  verificationMethod: string;
  ownerCredentialMaterial: string;
  governanceReference: string;
  requestSha384Hex: string;
  didDocumentSource: 'host-activation' | 'governance-configuration' | 'did-web-resolution';
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

/**
 * Resolves a governance-pinned public DID document for a host that has not yet
 * deployed its DNS/TLS workload.
 *
 * The configuration contains public verification material only. When the
 * variable is present it is authoritative and fails closed: ICA never falls
 * back to a network document for an omitted or malformed configured host.
 * This removes the bootstrap cycle while the request JWS still proves control
 * of the corresponding private key.
 */
function configuredHostDidDocument(issuerDid: string): JsonObject | undefined {
  const configuredFile = text(process.env.ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_FILE);
  let raw = text(process.env.ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_JSON);
  let source = 'ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_JSON';
  if (configuredFile) {
    source = `ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_FILE '${configuredFile}'`;
    try {
      raw = readFileSync(configuredFile, 'utf8').trim();
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`${source} could not be read: ${reason}`);
    }
  }
  if (!raw) {
    if (configuredFile) throw new Error(`${source} must not be empty.`);
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${source} must contain valid JSON.`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`${source} must contain an array of public DID documents.`);
  }
  const documents = parsed.map(asObject);
  if (documents.some((document) => !document)) {
    throw new Error(`${source} contains a non-object entry.`);
  }
  const matches = documents.filter((document) => text(document?.id) === issuerDid) as JsonObject[];
  if (matches.length !== 1) {
    throw new Error(`Governance configuration must contain exactly one public DID document for '${issuerDid}'.`);
  }
  if (/"d"\s*:/.test(JSON.stringify(matches[0]))) {
    throw new Error('Governance-pinned host DID documents must not contain private JWK material.');
  }
  return matches[0];
}

async function resolveHostDidDocument(issuerDid: string): Promise<{
  document: JsonObject;
  source: PreauthorizedHostEvidence['didDocumentSource'];
}> {
  const configured = configuredHostDidDocument(issuerDid);
  if (configured) return { document: configured, source: 'governance-configuration' };
  const response = await fetch(didWebUrl(issuerDid));
  if (!response.ok) throw new Error(`Unable to resolve preauthorized host DID document (${response.status}).`);
  return { document: await response.json() as JsonObject, source: 'did-web-resolution' };
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
 * Authorizes the PDF-free branch from server policy and a signed host request.
 * The hostname allowlist establishes governance eligibility. A one-time host
 * activation authorizes the submitted public JWK; the legacy DID resolution
 * branch remains available for already deployed integrations.
 */
export async function verifyPreauthorizedHostEvidence(input: {
  route: VerifyRouteContext;
  envelope: JsonObject;
  resource: JsonObject;
  activationCode?: string;
  thid: string;
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

  let publicKeyJwk: JsonObject | undefined;
  let didDocumentSource: PreauthorizedHostEvidence['didDocumentSource'];
  let governanceReference: string;
  if (text(input.activationCode)) {
    publicKeyJwk = asObject(organization.publicKeyJwk);
    if (!publicKeyJwk || text(publicKeyJwk.d)) {
      throw new Error('Host activation requires one public organization.publicKeyJwk without private material.');
    }
    didDocumentSource = 'host-activation';
    governanceReference = '';
  } else {
    const resolvedDidDocument = await resolveHostDidDocument(issuerDid);
    const didDocument = resolvedDidDocument.document;
    if (text(didDocument.id) !== issuerDid) throw new Error('Resolved host DID document id does not match the request issuer.');
    const methods = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : [];
    const method = methods.map(asObject).find((candidate) => text(candidate?.id) === kid);
    publicKeyJwk = asObject(method?.publicKeyJwk);
    if (!publicKeyJwk) throw new Error('Host authorization verification method was not found in the issuer DID document.');
    didDocumentSource = resolvedDidDocument.source;
    governanceReference = `env:ICA_PREAUTHORIZED_HOST_DOMAINS#${issuerDomain}`;
  }
  const verifier = createVerify('sha384');
  verifier.update(`${protectedEncoded}.${payloadEncoded}`);
  verifier.end();
  const valid = verifier.verify(
    { key: createPublicKey({ key: publicKeyJwk as any, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    decodeSegment(signatureEncoded, 'signature'),
  );
  if (!valid) throw new Error('Invalid preauthorized host JWS signature.');

  if (text(input.activationCode)) {
    const activation = await createHostActivationServiceFromEnv().consume({
      activationCode: text(input.activationCode),
      domain: issuerDomain,
      networkKind: input.route.section,
      thid: input.thid,
      approval: {
        jurisdiction: input.route.jurisdiction,
        sector: input.route.sector,
        legalName: text(claims['org.schema.Organization.legalName']),
        addressCountry: text(claims['org.schema.Organization.address.addressCountry']),
        controllerEmail: text(claims['org.schema.Service.owner.email']),
        serviceUrl: text(claims['org.schema.Service.url']),
        ...(text(claims['org.schema.Organization.taxID'])
          ? { taxId: text(claims['org.schema.Organization.taxID']) }
          : {
              identifierType: text(claims['org.schema.Organization.identifier.additionalType']),
              identifierValue: text(claims['org.schema.Organization.identifier.value']),
            }),
      },
    });
    governanceReference = `host-activation:${activation.id}`;
  }

  return {
    domain: issuerDomain,
    did: issuerDid,
    verificationMethod: kid,
    ownerCredentialMaterial: toJwkThumbprintSha256Urn(publicKeyJwk),
    governanceReference,
    requestSha384Hex: createHash('sha384').update(payloadEncoded).digest('hex'),
    didDocumentSource,
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
        `Host request-key verification source: ${evidence.didDocumentSource}.`,
        'No PDF was required or persisted for this governed host authorization.',
      ],
      annexFormFields: submission.annexFormFields,
      organizationPayload: submission.organizationPayload,
      legalRepresentativePayload: submission.legalRepresentativePayload,
    };
  }
}
