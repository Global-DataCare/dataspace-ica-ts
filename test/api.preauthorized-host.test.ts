/**
 * Flow contract — governed host onboarding without a PDF:
 * 1. A GW forwards one DIDComm `_verify` request for its own governed host identity.
 * 2. ICA derives the host from the canonical Service URL and organization did:web.
 * 3. ICA accepts the PDF-free request only when that host and route network kind are configured server-side.
 * 4. ICA projects the governed organization claims into verification evidence used for VC issuance.
 * 5. A mismatching/unlisted host or an unauthorized network kind fails before the PDF verifier or persistence runs.
 * Authorization invariant: client route values never create trust; the ICA environment allowlist does.
 * Persistence invariant: the governed request digest is auditable, but it is never stored or labelled as a PDF.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import test from 'node:test';
import { parseVerifyRoute } from '../src/api/path.ts';
import { parseVerifySubmission } from '../src/api/request-parsing.ts';
import { PreauthorizedHostVerificationService } from '../src/api/preauthorized-host-verifier.ts';
import { InMemoryVerificationJobStore } from '../src/api/job-store.ts';
import { VerifyRequestManager } from '../src/api/managers/verify-request-manager.ts';
import { buildVerificationVcBundle } from '../src/api/tools/vc-bundle.ts';
import { buildVcJwtAttachments } from '../src/api/tools/vc-jwt.ts';
import { activateSigningKey, resetActiveSigningKeysStateForTests } from '../src/api/tools/active-signing-keys.ts';
import { PRIVATE_KEY_PEM } from './test-signing-key.fixture.ts';

const previousHosts = process.env.ICA_PREAUTHORIZED_HOST_DOMAINS;
const previousNetworks = process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS;
const previousFetch = global.fetch;
const previousDidWebDomain = process.env.DID_WEB_DOMAIN;

test.afterEach(() => {
  if (previousHosts === undefined) delete process.env.ICA_PREAUTHORIZED_HOST_DOMAINS;
  else process.env.ICA_PREAUTHORIZED_HOST_DOMAINS = previousHosts;
  if (previousNetworks === undefined) delete process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS;
  else process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS = previousNetworks;
  global.fetch = previousFetch;
  if (previousDidWebDomain === undefined) delete process.env.DID_WEB_DOMAIN;
  else process.env.DID_WEB_DOMAIN = previousDidWebDomain;
  resetActiveSigningKeysStateForTests();
});

function requestForHost(hostDomain: string, networkKind = 'local-network'): {
  req: IncomingMessage;
  route: NonNullable<ReturnType<typeof parseVerifyRoute>> extends infer _T ? any : never;
} {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const publicKeyJwk = publicKey.export({ format: 'jwk' });
  const claims = {
    'org.schema.Organization.legalName': hostDomain === 'globaldatacare.es' ? 'GLOBAL DATA CARE SL' : 'EXAMPLE MEMBER ORGANIZATION LTD.',
    'org.schema.Organization.taxID': hostDomain === 'globaldatacare.es' ? 'VATES-B42215152' : 'VATES-B00000001',
    'org.schema.Service.url': `https://${hostDomain}/host/cds-ES/v1/health-care`,
    'org.schema.Service.category': 'health-care',
    'org.schema.Service.owner.email': `controller@${hostDomain}`,
  };
  const resource = {
    meta: { claims },
    organization: { did: `did:web:${hostDomain}`, publicKeyJwk },
  };
  const proofPayload = Buffer.from(JSON.stringify({
    jurisdiction: 'ES',
    sector: 'health-care',
    networkKind,
    resourceType: 'contract',
    resource,
  })).toString('base64url');
  // GW KMS selects its local key by fragment; ICA expands it against the
  // authenticated issuer DID before resolving the public verification method.
  const protectedHeader = Buffer.from(JSON.stringify({ alg: 'ES384', kid: 'host-signing-1' })).toString('base64url');
  const signature = sign('sha384', Buffer.from(`${protectedHeader}.${proofPayload}`), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    jti: `host-${hostDomain}`,
    thid: `host-${hostDomain}`,
    iss: `did:web:${hostDomain}`,
    aud: 'did:web:ica.local',
    type: 'https://globaldatacare.es/didcomm/ica/host/verify-request/v1',
    body: {
      data: [{
        resource: {
          ...resource,
        },
      }],
      hostAuthorizationProof: {
        jws: `${protectedHeader}.${proofPayload}.${signature}`,
      },
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  global.fetch = async () => new Response(JSON.stringify({
    id: `did:web:${hostDomain}`,
    verificationMethod: [{
      id: `did:web:${hostDomain}#host-signing-1`,
      type: 'JsonWebKey2020',
      controller: `did:web:${hostDomain}`,
      publicKeyJwk,
    }],
  }), { status: 200, headers: { 'content-type': 'application/json' } });
  (req as any).headers = {
    host: 'ica.local:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };
  const parsed = parseVerifyRoute(`/ica/cds-ES/v1/health-care/${networkKind}/pdf/contract/_verify`);
  assert.ok(parsed && parsed.ok);
  return { req, route: parsed.context };
}

test('preauthorized local-network host is accepted without a PDF and produces governed evidence', async () => {
  process.env.ICA_PREAUTHORIZED_HOST_DOMAINS = 'globaldatacare.es,member.example';
  process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS = 'local-network';
  process.env.DID_WEB_DOMAIN = 'globaldatacare.es';
  const { req, route } = requestForHost('globaldatacare.es');

  const submission = await parseVerifySubmission(req, { route });
  assert.equal(submission.evidenceKind, 'preauthorized-host');
  assert.equal(submission.preauthorizedHost?.domain, 'globaldatacare.es');
  assert.equal(submission.annexFormFields?.['organization.taxID'], 'VATES-B42215152');
  assert.equal(submission.annexFormFields?.['organization.legalName'], 'GLOBAL DATA CARE SL');

  const result = await new PreauthorizedHostVerificationService().verify(route, submission);
  assert.equal(result.ok, true);
  assert.equal(result.evidenceKind, 'preauthorized-host');
  assert.equal(result.signatureValid, true);
  assert.match(result.notes.join(' '), /server-side governance allowlist/i);
  activateSigningKey({ kid: 'ica-local-es384', alg: 'ES384', privateKeyPem: PRIVATE_KEY_PEM });
  const bundle = buildVerificationVcBundle(route, result, 'did:web:ica.local');
  const organizationCredential = bundle.data
    .map((entry) => entry.resource)
    .find((resource) => {
      const candidate = resource as Record<string, unknown>;
      return Array.isArray(candidate.type) && candidate.type.includes('OrganizationCredential');
    });
  assert.ok(organizationCredential, 'governed evidence must still issue the normal OrganizationCredential');
  const hostCredential = bundle.data
    .map((entry) => entry.resource as Record<string, unknown>)
    .find((resource) => Array.isArray(resource.type)
      && resource.type.includes('HostingServiceCredential'));
  assert.ok(hostCredential, 'preauthorized host evidence must issue HostingServiceCredential');
  assert.equal((hostCredential.credentialSubject as Record<string, unknown>).id,
    'https://globaldatacare.es');
  assert.doesNotMatch(JSON.stringify(hostCredential.evidence), /pades|terms-and-conditions|ipfs:\/\//i);
  assert.match(JSON.stringify(hostCredential.evidence), /governed-host-authorization/i);

  const attachments = buildVcJwtAttachments(route, bundle, 'did:web:ica.local');
  const hostJwt = attachments
    .map((attachment) => attachment.data?.json as Record<string, unknown> | undefined)
    .find((entry) => entry?.credentialId === hostCredential.id)?.jwt;
  assert.equal(typeof hostJwt, 'string');
  const jwtPayload = JSON.parse(Buffer.from(String(hostJwt).split('.')[1] || '', 'base64url').toString('utf8'));
  assert.equal(jwtPayload.jti, hostCredential.id);
  assert.equal(jwtPayload.sub, (hostCredential.credentialSubject as Record<string, unknown>).id);
  assert.deepEqual(jwtPayload.vc.type,
    ['VerifiableCredential', 'ServiceCredential', 'HostingServiceCredential']);
});

test('unlisted host cannot use the PDF-free verification path', async () => {
  process.env.ICA_PREAUTHORIZED_HOST_DOMAINS = 'globaldatacare.es,member.example';
  process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS = 'local-network';
  const { req, route } = requestForHost('attacker.example');

  await assert.rejects(
    parseVerifySubmission(req, { route }),
    /not present in ICA_PREAUTHORIZED_HOST_DOMAINS/i,
  );
});

test('preauthorized host cannot move its PDF-free authorization to another network kind', async () => {
  process.env.ICA_PREAUTHORIZED_HOST_DOMAINS = 'globaldatacare.es,member.example';
  process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS = 'local-network';
  const { req, route } = requestForHost('member.example', 'network');

  await assert.rejects(
    parseVerifySubmission(req, { route }),
    /not authorized for PDF-free host verification/i,
  );
});

test('signed governed-host authorization cannot be replayed into another sector route', async () => {
  process.env.ICA_PREAUTHORIZED_HOST_DOMAINS = 'globaldatacare.es,member.example';
  process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS = 'local-network';
  const { req, route } = requestForHost('globaldatacare.es');

  await assert.rejects(
    parseVerifySubmission(req, { route: { ...route, sector: 'animal-care' } }),
    /route scope plus body\.data\[0\]\.resource/i,
  );
});

test('VerifyRequestManager bypasses both PDF verification and PDF persistence for governed host evidence', async () => {
  process.env.ICA_PREAUTHORIZED_HOST_DOMAINS = 'globaldatacare.es,member.example';
  process.env.ICA_PREAUTHORIZED_HOST_NETWORK_KINDS = 'local-network';
  const { req, route } = requestForHost('member.example');
  const store = new InMemoryVerificationJobStore(60);
  let pdfVerifierCalls = 0;
  let pdfPersistenceCalls = 0;
  const manager = new VerifyRequestManager(
    store,
    { verify: async () => { pdfVerifierCalls += 1; throw new Error('PDF verifier must not run.'); } },
    { persistVerifiedPdf: async () => { pdfPersistenceCalls += 1; throw new Error('PDF persistence must not run.'); } } as any,
  );

  const outcome = await manager.submit(route, req);
  assert.equal(outcome.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(pdfVerifierCalls, 0);
  assert.equal(pdfPersistenceCalls, 0);
  assert.equal(store.get('host-member.example')?.status, 'succeeded');
  assert.equal(store.get('host-member.example')?.result?.evidenceKind, 'preauthorized-host');
});
