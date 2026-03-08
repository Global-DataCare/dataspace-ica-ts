import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { InMemoryVerificationJobStore } from '../src/api/job-store.ts';
import { InMemoryActivationJobStore } from '../src/api/activation-job-store.ts';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import {
  buildActivateResponseLocation,
  buildAddEvidenceResponseLocation,
  buildCredentialRevokeResponseLocation,
  buildCredentialStatusResponseLocation,
  buildIssueCredentialResponseLocation,
  buildRotateResponseLocation,
  buildVerifyResponseLocation,
  parseActivateRoute,
  parseAddEvidenceRoute,
  parseCredentialRevokeRoute,
  parseCredentialStatusRoute,
  parseIssueCredentialRoute,
  parseRotateRoute,
  parseVerifyRoute,
} from '../src/api/path.ts';
import { buildVerificationVcBundle } from '../src/api/server.ts';
import { ActivateRequestManager } from '../src/api/managers/activate-request-manager.ts';
import { AddEvidenceRequestManager } from '../src/api/managers/add-evidence-request-manager.ts';
import { AddEvidenceResponseManager } from '../src/api/managers/add-evidence-response-manager.ts';
import { CredentialRevokeRequestManager } from '../src/api/managers/credential-revoke-request-manager.ts';
import { CredentialRevokeResponseManager } from '../src/api/managers/credential-revoke-response-manager.ts';
import { CredentialStatusRequestManager } from '../src/api/managers/credential-status-request-manager.ts';
import { CredentialStatusResponseManager } from '../src/api/managers/credential-status-response-manager.ts';
import { IssueCredentialRequestManager } from '../src/api/managers/issue-credential-request-manager.ts';
import { IssueCredentialResponseManager } from '../src/api/managers/issue-credential-response-manager.ts';
import { VerifyRequestManager } from '../src/api/managers/verify-request-manager.ts';
import { VerifyResponseManager } from '../src/api/managers/verify-response-manager.ts';
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import { computePdfLogicalFingerprint, resolveTemplateResourceVersion } from '../src/api/fnmt-pdf-verifier.ts';
import { parseActivateSigningKeySubmission, parseRotateSubmission } from '../src/api/request-parsing.ts';
import { SignatureVerificationManager } from '../src/api/signature-verification-manager.ts';
import { AuditDocumentStorageService } from '../src/api/tools/audit-document-storage.ts';
import { buildDidcommMessage } from '../src/api/tools/didcomm-message.ts';
import {
  activateSigningKey,
  resetActiveSigningKeysStateForTests,
} from '../src/api/tools/active-signing-keys.ts';
import {
  validateRotateControllerDidcommProof,
} from '../src/api/tools/controller-didcomm-proof.ts';
import {
  computeRfc7638JwkThumbprint,
  deriveDeterministicEcPrivateKeyPem,
} from '../src/api/tools/deterministic-key-material.ts';
import { computeControllerAuthorizationPayloadBase64Url } from '../src/api/tools/controller-authorization-payload.ts';
import {
  resetVerificationCollectionsMemStateForTests,
  VerificationCollectionsService,
} from '../src/api/tools/verification-collections-storage.ts';
import type {
  ActivateSigningKeyInput,
  AddEvidenceResult,
  AddEvidenceRouteContext,
  CredentialRevokeResult,
  CredentialRevokeRouteContext,
  CredentialStatusResult,
  CredentialStatusRouteContext,
  IssueCredentialResult,
  IssueCredentialRouteContext,
  SignatureVerifierAdapter,
  VerificationErrorDetails,
  VerifyResult,
  VerifySubmission,
} from '../src/api/types.ts';

function base64UrlEncodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function buildControllerProofJws(input: {
  kid: string;
  thid: string;
  action: '_activate' | '_rotate';
  privateKeyPem: string;
  jti?: string;
  resourceType?: string;
  activateKeys?: ActivateSigningKeyInput[];
  authorizationBody?: Record<string, unknown>;
}): string {
  const header = {
    alg: 'ES384',
    kid: input.kid,
  };

  const protectedEncoded = base64UrlEncodeJson(header);
  const payloadEncoded = input.action === '_activate'
    ? computeControllerAuthorizationPayloadBase64Url(
      input.authorizationBody || { data: (input.activateKeys || []).map((key) => ({ key })) },
    )
    : base64UrlEncodeJson({
      thid: input.thid,
      action: input.action,
      kid: input.kid,
      ...(input.jti ? { jti: input.jti } : {}),
      ...(input.resourceType ? { resourceType: input.resourceType } : {}),
    });
  const signingInput = `${protectedEncoded}.${payloadEncoded}`;
  const signer = createSign('sha384');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign({
    key: input.privateKeyPem,
    dsaEncoding: 'ieee-p1363',
  });
  if (input.action === '_activate') {
    return `${protectedEncoded}..${signature.toString('base64url')}`;
  }
  return `${protectedEncoded}.${payloadEncoded}.${signature.toString('base64url')}`;
}

function buildNonDetachedActivateProofJws(input: {
  kid: string;
  thid: string;
  privateKeyPem: string;
  jti?: string;
}): string {
  const header = {
    alg: 'ES384',
    kid: input.kid,
  };
  const payload = {
    thid: input.thid,
    action: '_activate',
    kid: input.kid,
    ...(input.jti ? { jti: input.jti } : {}),
  };
  const protectedEncoded = base64UrlEncodeJson(header);
  const payloadEncoded = base64UrlEncodeJson(payload);
  const signingInput = `${protectedEncoded}.${payloadEncoded}`;
  const signer = createSign('sha384');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign({
    key: input.privateKeyPem,
    dsaEncoding: 'ieee-p1363',
  });
  return `${protectedEncoded}.${payloadEncoded}.${signature.toString('base64url')}`;
}

const CONTROLLER_CA_TEST_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDe//4WRdJpBh0HUfhn
RC3KNHZXZ3tI5iFP2tQgix+x1FuIDGb9jbAFL4y9Okx7NiGhZANiAAS67JrcZoTf
bfGNYSsO3gNw7jJ39Xd6cIm85TPuYB7rdPPQl6Di0XxmWOMuW5ckd0v3eLIXCaVP
E1nH11R79H5EgC0iXZ4ljRU197XvArNXUJANDKBR9PkDjJLHGisIAFA=
-----END PRIVATE KEY-----`;

const CONTROLLER_CA_TEST_X5C = 'MIICQzCCAcqgAwIBAgIUDO7JwdnoN/7sPtXSsYvu3/lsJ/owCgYIKoZIzj0EAwIwWTELMAkGA1UEBhMCRVMxDTALBgNVBAoMBEFjbWUxEzARBgNVBAMMCkNvbnRyb2xsZXIxJjAkBgkqhkiG9w0BCQEWF2l0LWRpcmVjdG9yQGV4YW1wbGUub3JnMB4XDTI2MDMwNzE1NDk1MloXDTM2MDMwNDE1NDk1MlowWTELMAkGA1UEBhMCRVMxDTALBgNVBAoMBEFjbWUxEzARBgNVBAMMCkNvbnRyb2xsZXIxJjAkBgkqhkiG9w0BCQEWF2l0LWRpcmVjdG9yQGV4YW1wbGUub3JnMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuuya3GaE323xjWErDt4DcO4yd/V3enCJvOUz7mAe63Tz0Jeg4tF8ZljjLluXJHdL93iyFwmlTxNZx9dUe/R+RIAtIl2eJY0VNfe17wKzV1CQDQygUfT5A4ySxxorCABQo1MwUTAdBgNVHQ4EFgQUoqHCRVOg4IkdCG+1D24CTJjECVMwHwYDVR0jBBgwFoAUoqHCRVOg4IkdCG+1D24CTJjECVMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNnADBkAjB3vq5C6TgDU/WwV9bsJG+svSuu6d93YQco4z7tMrpzfgZP6emsFyg23lFeY5GzoC4CMA7jgC4UXi2k4UAB6eBePQJVXRS8c2MlwOjiIa+MLDqcvyZcbRaZLBT3JHz09RTRIQ==';

test('VerifyResponseManager failed job returns bundle with resource + outcome', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-failed-001', parsed.context);
  store.markFailed('thid-failed-001', 'Signature verification failed.');

  const manager = new VerifyResponseManager(store);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-failed-001',
  );
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'failed');
  if (outcome.type !== 'failed') return;
  const payload = outcome.payload as {
    jti?: string;
    iss?: string;
    aud?: string;
    thid?: string;
    type?: string;
    body?: {
      data?: Array<{
        resource?: Record<string, unknown>;
        response?: { status?: string; outcome?: { resourceType?: string } };
      }>;
    };
  };
  assert.match(payload.jti || '', /^urn:uuid:/);
  assert.match(payload.iss || '', /^did:web:/);
  assert.match(payload.aud || '', /^did:web:/);
  assert.equal(payload.thid, 'thid-failed-001');
  assert.equal(payload.type, 'application/bundle-api+json');
  assert.equal(Array.isArray(payload.body?.data), true);
  assert.equal(payload.body?.data?.length, 1);
  assert.equal(payload.body?.data?.[0]?.response?.status, '500');
  assert.equal(payload.body?.data?.[0]?.response?.outcome?.resourceType, 'OperationOutcome');
  assert.equal(typeof payload.body?.data?.[0]?.resource?.id, 'string');
});

test('VerifyResponseManager failed job includes revocation debug details when available', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-failed-debug-001', parsed.context);
  const errorDetails: VerificationErrorDetails = {
    revocation: {
      finalStatus: 'unknown',
      checks: [
        {
          phase: 'download',
          status: 'http_error',
          url: 'http://crl.example/1.crl',
          httpStatus: 404,
          message: 'HTTP 404',
        },
        {
          phase: 'download',
          status: 'timeout',
          url: 'http://crl.example/2.crl',
          message: 'The operation was aborted due to timeout',
        },
        {
          phase: 'download',
          status: 'parse_error',
          url: 'http://crl.example/3.crl',
          message: 'unable to load CRL',
        },
      ],
    },
  };
  store.markFailed(
    'thid-failed-debug-001',
    'Revocation check did not pass (status=unknown).',
    errorDetails,
  );

  const manager = new VerifyResponseManager(store);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-failed-debug-001',
  );
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'failed');
  if (outcome.type !== 'failed') return;

  const payload = outcome.payload as {
    body?: {
      issues?: {
        issue?: Array<{ severity?: string; code?: string; diagnostics?: string }>;
      };
      data?: Array<{
        resource?: {
          content?: Array<{
            error?: string;
          }>;
        };
        response?: {
          outcome?: {
            issue?: Array<{ severity?: string; code?: string; diagnostics?: string }>;
          };
        };
      }>;
    };
  };
  const content = payload.body?.data?.[0]?.resource?.content;
  assert.equal(content?.[0]?.error, 'Revocation check did not pass (status=unknown).');
  const issues = payload.body?.issues?.issue || [];
  assert.equal(issues.length >= 4, true);
  assert.equal(issues[1]?.code, 'transient');
  assert.match(issues[1]?.diagnostics || '', /status=http_error/);
  assert.equal(issues[2]?.code, 'timeout');
  assert.match(issues[2]?.diagnostics || '', /status=timeout/);
  assert.equal(issues[3]?.code, 'structure');
  assert.match(issues[3]?.diagnostics || '', /status=parse_error/);

  const entryIssues = payload.body?.data?.[0]?.response?.outcome?.issue || [];
  assert.equal(entryIssues.length, issues.length);
});

test('VerifyResponseManager pending job returns Location with thid query', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-pending-001', parsed.context);

  const manager = new VerifyResponseManager(store);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-pending-001',
  );
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'pending');
  if (outcome.type !== 'pending') return;
  assert.equal(
    outcome.location,
    '/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-pending-001',
  );
  assert.equal(outcome.retryAfter, 5);
});

test('VerifyResponseManager uses issuer DID as aud in local-tenant mode by default', async () => {
  const previousLocalTenantId = process.env.ICA_LOCAL_TENANT_ID;
  const previousExternalDomain = process.env.ICA_EXTERNAL_DOMAIN;
  const previousAudienceDid = process.env.ICA_DIDCOMM_AUDIENCE_DID;
  process.env.ICA_LOCAL_TENANT_ID = 'ica';
  process.env.ICA_EXTERNAL_DOMAIN = 'ica.example.com';
  delete process.env.ICA_DIDCOMM_AUDIENCE_DID;
  try {
    const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
    assert.ok(parsed);
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;

    const store = new InMemoryVerificationJobStore(60);
    store.enqueue('thid-fixed-tenant-001', parsed.context);
    store.markFailed('thid-fixed-tenant-001', 'Signature verification failed.');

    const manager = new VerifyResponseManager(store);
    const requestUrl = new URL(
      'http://localhost/ica/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-fixed-tenant-001',
    );
    const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
    const outcome = await manager.poll(parsed.context, req, requestUrl);
    assert.equal(outcome.type, 'failed');
    if (outcome.type !== 'failed') return;

    const payload = outcome.payload as { iss?: string; aud?: string };
    assert.equal(payload.iss, 'did:web:ica.example.com');
    assert.equal(payload.aud, 'did:web:ica.example.com');
  } finally {
    if (previousLocalTenantId === undefined) {
      delete process.env.ICA_LOCAL_TENANT_ID;
    } else {
      process.env.ICA_LOCAL_TENANT_ID = previousLocalTenantId;
    }
    if (previousExternalDomain === undefined) {
      delete process.env.ICA_EXTERNAL_DOMAIN;
    } else {
      process.env.ICA_EXTERNAL_DOMAIN = previousExternalDomain;
    }
    if (previousAudienceDid === undefined) {
      delete process.env.ICA_DIDCOMM_AUDIENCE_DID;
    } else {
      process.env.ICA_DIDCOMM_AUDIENCE_DID = previousAudienceDid;
    }
  }
});

test('buildIcaVerifyOpenApiSpec exposes verify and polling paths', () => {
  const openApi = buildIcaVerifyOpenApiSpec();
  assert.equal(openApi.openapi, '3.1.0');
  assert.match(openApi.info.description, /alternateName \"ica\"/i);
  assert.ok(openApi.paths['/.well-known/did.json']);
  assert.ok(openApi.paths['/did.json']);
  assert.ok(openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/{membertype}/{role}/{idHash}/did.json']);
  assert.ok(Array.isArray(openApi.tags));
  assert.equal(openApi.tags.some((tag) => tag.name === 'terms/pdf'), true);
  assert.equal(openApi.tags.some((tag) => tag.name === 'network/evidence'), true);
  assert.equal(openApi.tags.some((tag) => tag.name === 'network/policies'), true);
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate'],
  );
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate'],
  );
  assert.ok(openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify']);
  assert.ok(
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response'],
  );
  const activateDidcommExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.examples;
  const activateDidcommSchema =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.schema as any;
  assert.ok(activateDidcommExamples?.activateEs384);
  assert.ok(activateDidcommExamples?.activateMultipleKeys);
  assert.ok(activateDidcommSchema?.properties?.body?.properties?.data);
  assert.equal(Array.isArray(activateDidcommSchema?.properties?.body?.required), true);
  assert.equal(activateDidcommSchema?.properties?.body?.required?.includes('data'), true);
  assert.equal(activateDidcommSchema?.properties?.body?.properties?.key, undefined);

  const addDidcommExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  const addDidcommSchema =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.schema as any;
  assert.ok(addDidcommExamples?.addOfficialRegistryEvidence);
  assert.ok(addDidcommExamples?.addOfficialRegistryEvidenceBatch);
  assert.ok(addDidcommSchema?.properties?.body?.properties?.data);
  assert.equal(Array.isArray(addDidcommSchema?.properties?.body?.required), true);
  assert.equal(addDidcommSchema?.properties?.body?.required?.includes('data'), true);
  assert.ok(addDidcommExamples?.addOfficialRegistryEvidence?.value?.body?.data?.[0]?.resource?.verified_claims);
  const addResourceSchemaOneOf =
    addDidcommSchema?.properties?.body?.properties?.data?.items?.properties?.resource?.oneOf;
  assert.equal(Array.isArray(addResourceSchemaOneOf), true);
  assert.equal(
    addResourceSchemaOneOf?.some((entry: any) => entry?.properties?.verified_claims),
    true,
  );

  const policyDidcommExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  const policyDidcommSchema =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.schema as any;
  assert.ok(policyDidcommExamples?.upsertDelegateInvitationPolicy);
  assert.ok(policyDidcommSchema?.properties?.body?.properties?.data);
  assert.equal(Array.isArray(policyDidcommSchema?.properties?.body?.required), true);
  assert.equal(policyDidcommSchema?.properties?.body?.required?.includes('data'), true);
  assert.equal(
    policyDidcommExamples?.upsertDelegateInvitationPolicy?.value?.body?.data?.[0]?.resource?.permission?.[0]?.['ovc:constraint']?.[0]?.['ovc:leftOperand'],
    '$.credentialSubject.id',
  );

  const verifyErrorSchema =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify']
      ?.post
      ?.responses?.['400']
      ?.content?.['application/didcomm-plain+json']
      ?.schema as any;
  assert.equal(verifyErrorSchema?.properties?.body?.properties?.total?.enum?.[0], 0);
  assert.equal(verifyErrorSchema?.properties?.body?.properties?.data?.maxItems, 0);
  assert.deepEqual(verifyErrorSchema?.properties?.body?.properties?.data?.example, []);
  assert.deepEqual(verifyErrorSchema?.properties?.body?.example?.data, []);
  assert.equal(verifyErrorSchema?.properties?.body?.properties?.result, undefined);

  const verifyPollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  const verifySuccessAttachments =
    verifyPollingExamples?.verificationSucceededWithEvidence?.value?.attachments;
  const verifySuccessData = verifyPollingExamples?.verificationSucceededWithEvidence?.value?.body?.data;
  assert.ok(Array.isArray(verifySuccessAttachments));
  assert.equal(verifySuccessAttachments?.length, 2);
  assert.equal(verifySuccessAttachments?.[0]?.media_type, 'application/vc+jwt');
  assert.ok(Array.isArray(verifySuccessData));
  assert.equal(verifySuccessData?.length, 2);
  assert.ok(Array.isArray(verifySuccessData?.[0]?.resource?.evidence));
  assert.ok(Array.isArray(verifySuccessData?.[1]?.resource?.evidence));
  assert.ok(verifyPollingExamples?.verificationFailed);

  const activatePollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.ok(Array.isArray(activatePollingExamples?.activationCompleted?.value?.body?.data?.[0]?.resource?.content));
  assert.equal(
    activatePollingExamples?.activationCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.alg,
    'ES384',
  );

  const addPollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    addPollingExamples?.addEvidenceCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.evidenceType,
    'official-registry',
  );
  assert.equal(
    addPollingExamples?.addEvidenceCompleted?.value?.body?.issues?.issue?.[0]?.diagnostics,
    'Evidence record(s) stored: 2.',
  );

  const policyPollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/policies/delegations/_upsert-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    policyPollingExamples?.delegationPolicyUpsertCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.roleIdentifier,
    'urn:ilo:ilostat:isco-08:1120',
  );

  const issuePollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    issuePollingExamples?.issueCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.credentialType,
    'member-onboarding',
  );

  const issueDidcommExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  const issueDidcommSchema =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue']
      ?.post
      ?.requestBody
      ?.content?.['application/didcomm-plain+json']
      ?.schema as any;
  assert.equal(
    issueDidcommExamples?.issueCredentialWithEvidence?.value?.body?.data?.[0]?.resource?.credentialSubject?.['@type'],
    'Person',
  );
  const subjectSchema =
    issueDidcommSchema?.properties?.body?.properties?.data?.items?.properties?.resource?.properties?.credentialSubject;
  assert.ok(subjectSchema?.oneOf?.[0]?.required?.includes('@type'));

  const statusPollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    statusPollingExamples?.statusCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.status,
    'good',
  );

  const revokePollingExamples =
    openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response']
      ?.post
      ?.responses?.['200']
      ?.content?.['application/didcomm-plain+json']
      ?.examples as any;
  assert.equal(
    revokePollingExamples?.revokeCompleted?.value?.body?.data?.[0]?.resource?.content?.[0]?.status,
    'revoked',
  );
});

test('buildDidcommMessage defaults to bundle api type and keeps query thid', () => {
  const req = {
    headers: { host: 'localhost:3310' },
    url: '/ica/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-from-query-001',
  } as unknown as IncomingMessage;
  const payload = buildDidcommMessage(req, {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 0,
    data: [],
  });
  assert.equal(payload.type, 'application/bundle-api+json');
  assert.equal(payload.thid, 'thid-from-query-001');
  assert.match(payload.iss || '', /^did:web:/);
  assert.match(payload.aud || '', /^did:web:/);
});

test('buildDidcommMessage supports empty correlation fields for early errors', () => {
  const req = {
    headers: { host: 'localhost:3310' },
    url: '/unknown-endpoint',
  } as unknown as IncomingMessage;
  const payload = buildDidcommMessage(req, {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 0,
    data: [],
  }, {
    thidFallback: 'empty',
    audFallback: 'empty',
  });
  assert.equal(payload.type, 'application/bundle-api+json');
  assert.equal(payload.thid, '');
  assert.equal(payload.aud, '');
  assert.match(payload.iss || '', /^did:web:/);
});

test('VerifyResponseManager succeeded job returns result inside body', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const verifyResult: VerifyResult = {
    ok: true,
    verifiedAt: '2026-03-05T00:00:00.000Z',
    templateUrl: 'https://example.test/template.pdf',
    templateMatch: true,
    signatureValid: true,
    chainValid: true,
    revocationStatus: 'good',
    digest: {
      alg: 'sha3-384',
      signedPdfHex: 'a',
      unsignedPdfHex: 'b',
      templateHex: 'c',
    },
    signerCertificateSerialNumber: '00AA11',
    signerSubject: 'CN=Signer',
    signerIssuer: 'CN=FNMT',
    hashes: {
      signedPdfSha256Hex: 'a',
      unsignedPdfSha256Hex: 'b',
      templateSha256Hex: 'c',
    },
    notes: [],
  };

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-ok-001', parsed.context);
  store.markSucceeded('thid-ok-001', verifyResult);

  const manager = new VerifyResponseManager(store);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-ok-001',
  );
  const req = { method: 'POST', headers: {} } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'succeeded');
  if (outcome.type !== 'succeeded') return;

  const payload = outcome.payload as {
    jti?: string;
    iss?: string;
    aud?: string;
    thid?: string;
    type?: string;
    attachments?: Array<{
      id?: string;
      format?: string;
      media_type?: string;
      data?: { json?: { format?: string; jwt?: string } };
    }>;
    body?: { total?: number; data?: unknown[] };
  };
  assert.match(payload.jti || '', /^urn:uuid:/);
  assert.match(payload.iss || '', /^did:web:/);
  assert.match(payload.aud || '', /^did:web:/);
  assert.equal(payload.thid, 'thid-ok-001');
  assert.equal(payload.type, 'application/bundle-api+json');
  assert.equal(payload.body?.total, 2);
  assert.equal(Array.isArray(payload.body?.data), true);
  assert.equal(Array.isArray(payload.attachments), true);
  assert.equal(payload.attachments?.length, 2);
  assert.equal(payload.attachments?.[0]?.format, 'vc+jwt');
  assert.equal(payload.attachments?.[0]?.media_type, 'application/vc+jwt');
  assert.equal(payload.attachments?.[0]?.data?.json?.format, 'vc+jwt');
  assert.equal((payload.attachments?.[0]?.data?.json?.jwt || '').split('.').length, 3);
  assert.equal(payload.attachments?.[1]?.format, 'vc+jwt');
  assert.equal(payload.attachments?.[1]?.media_type, 'application/vc+jwt');
  assert.equal(payload.attachments?.[1]?.data?.json?.format, 'vc+jwt');
  assert.equal((payload.attachments?.[1]?.data?.json?.jwt || '').split('.').length, 3);
});

test('VerifyResponseManager stores issued credentials and evidence using mem collections adapter', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
    issuedCredentialsCollection: 'issued_credentials',
    evidenceCollection: 'evidence_records',
  });

  const verifyResult: VerifyResult = {
    ok: true,
    verifiedAt: '2026-03-05T00:00:00.000Z',
    templateUrl: 'https://example.test/template.pdf',
    templateMatch: true,
    signatureValid: true,
    chainValid: true,
    revocationStatus: 'good',
    digest: {
      alg: 'sha3-384',
      signedPdfHex: 'deadbeef',
      unsignedPdfHex: 'beadfeed',
      templateHex: 'cafebabe',
    },
    signerCertificateSerialNumber: '00AA11',
    signerSubject: 'CN=Jane Doe,O=Acme Health SL,OID.2.5.4.97=VATES-A12345678,SERIALNUMBER=12345678Z,C=ES',
    signerIssuer: 'CN=FNMT Intermediate',
    hashes: {
      signedPdfSha256Hex: 'deadbeef',
      unsignedPdfSha256Hex: 'beadfeed',
      templateSha256Hex: 'cafebabe',
    },
    notes: [],
  };

  const store = new InMemoryVerificationJobStore(60);
  store.enqueue('thid-persist-001', parsed.context);
  store.markSucceeded('thid-persist-001', verifyResult);

  const manager = new VerifyResponseManager(store, collectionsService);
  const requestUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify-response?thid=thid-persist-001',
  );
  const req = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const outcome = await manager.poll(parsed.context, req, requestUrl);
  assert.equal(outcome.type, 'succeeded');

  const issued = (await collectionsService.listIssuedCredentials())
    .filter((item) => item.thid === 'thid-persist-001');
  const evidence = (await collectionsService.listEvidenceRecords())
    .filter((item) => item.thid === 'thid-persist-001');
  assert.equal(issued.length, 2);
  assert.equal(evidence.length, 4);
  assert.equal(issued.every((item) => item.tenantId === 'acme'), true);
  assert.equal(evidence.every((item) => item.tenantId === 'acme'), true);
});

test('AddEvidence managers persist evidence records using mem collections adapter', async () => {
  const parsed = parseAddEvidenceRoute('/acme/cds-ES/v1/animal-care/network/evidence/official-registry/_add');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
    issuedCredentialsCollection: 'issued_credentials',
    evidenceCollection: 'evidence_records',
  });

  const store = new InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>(60);
  const requestManager = new AddEvidenceRequestManager(store, collectionsService);
  const responseManager = new AddEvidenceResponseManager(store);

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-evidence-add-001',
    thid: 'thid-evidence-add-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
    body: {
      data: [
        {
          issuedCredentialRecordId: 'urn:uuid:issued-existing-001',
          operatorDid: 'did:web:ica.example.com#employee-1',
          resource: {
            verified_claims: {
              verification: {
                trust_framework: null,
                time: '2026-03-06T10:00:00.000Z',
                evidence: [
                  {
                    type: 'electronic_record',
                    time: '2026-03-06T10:00:00.000Z',
                    verifier: {
                      organization: 'did:web:localhost%3A3310',
                    },
                    record: {
                      type: 'official-registry',
                      source: {
                        id: 'did:web:registry.example.org',
                        type: 'PublicRegistry',
                      },
                    },
                    attachments: [
                      {
                        digest: {
                          alg: 'sha3-384',
                          value: 'c2lnbmF0dXJl',
                        },
                        url: 'urn:uuid:evidence-doc-001',
                      },
                    ],
                  },
                ],
              },
              claims: {
                healthcareRegistrationNumber: 'ES-SAN-REG-0001',
                professionalLicenseDid: 'did:web:college.example.org:member:12345',
              },
            },
          },
        },
        {
          issuedCredentialRecordId: 'urn:uuid:issued-existing-001',
          operatorDid: 'did:web:ica.example.com#employee-2',
          evidence: {
            type: 'document',
            method: 'eid',
            time: '2026-03-06T10:05:00.000Z',
            verifier: {
              organization: 'did:web:localhost%3A3310',
            },
            document_details: {
              type: 'official-registry-certificate',
              document_number: 'B-123456',
            },
            attachments: {
              digest: {
                alg: 'sha3-384',
                value: 'ZG9jdW1lbnQ=',
              },
              url: 'urn:uuid:evidence-doc-002',
            },
          },
        },
      ],
    },
  }));

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/evidence/official-registry/_add';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsed.context, req);
  assert.equal(submitOutcome.type, 'accepted');
  if (submitOutcome.type !== 'accepted') return;
  assert.equal(
    submitOutcome.location,
    '/acme/cds-ES/v1/animal-care/network/evidence/official-registry/_add-response',
  );
  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/evidence/official-registry/_add-response?thid=thid-evidence-add-001',
  );
  const pollOutcome = await responseManager.poll(parsed.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');

  const evidence = (await collectionsService.listEvidenceRecords())
    .filter((item) => item.thid === 'thid-evidence-add-001');
  assert.equal(evidence.length, 2);
  assert.equal(evidence[0]?.evidenceType, 'official-registry');
  assert.equal(evidence[0]?.tenantId, 'acme');
  const verifiedClaimsRecord = evidence.find((item) =>
    Boolean((item.evidence as Record<string, unknown>).verified_claims));
  assert.ok(verifiedClaimsRecord);
  const verifiedClaims = (verifiedClaimsRecord?.evidence as Record<string, any>).verified_claims;
  assert.equal(verifiedClaims?.claims?.healthcareRegistrationNumber, 'ES-SAN-REG-0001');
  assert.equal(verifiedClaims?.claims?.professionalLicenseDid, 'did:web:college.example.org:member:12345');
  assert.equal(Array.isArray(verifiedClaims?.verification?.evidence), true);
  if (pollOutcome.type === 'succeeded') {
    const payloadBody = (pollOutcome.payload as any)?.body;
    assert.equal(payloadBody?.data?.[0]?.resource?.content?.length, 2);
  }
});

test('AddEvidence managers reject non-OIDC4IDA evidence payload', async () => {
  const parsed = parseAddEvidenceRoute('/acme/cds-ES/v1/animal-care/network/evidence/address/_add');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const store = new InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>(60);
  const requestManager = new AddEvidenceRequestManager(store);
  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-evidence-add-invalid-001',
    thid: 'thid-evidence-add-invalid-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/evidence/add-request/v1',
    body: {
      evidence: {
        type: 'address',
        checkedAt: '2026-03-06T10:00:00.000Z',
      },
    },
  }));

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/evidence/address/_add';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const outcome = await requestManager.submit(parsed.context, req);
  assert.equal(outcome.type, 'error');
  if (outcome.type !== 'error') return;
  assert.equal(outcome.statusCode, 400);
  assert.match(outcome.message, /Invalid OIDC4IDA evidence payload/i);
  assert.match(outcome.message, /body\.evidence\.type must be one of/i);
});

test('IssueCredential managers persist credential and evidence records using mem collections adapter', async () => {
  const parsed = parseIssueCredentialRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
    issuedCredentialsCollection: 'issued_credentials',
    evidenceCollection: 'evidence_records',
  });

  const store = new InMemoryEntityJobStore<IssueCredentialRouteContext, IssueCredentialResult>(60);
  const requestManager = new IssueCredentialRequestManager(store, collectionsService);
  const responseManager = new IssueCredentialResponseManager(store);

  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-credential-issue-001',
    thid: 'thid-credential-issue-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/issue-request/v1',
    body: {
      credential: {
        id: 'urn:uuid:vc-member-001',
        type: ['VerifiableCredential', 'MemberCredential'],
        issuer: 'did:web:ica.example.com',
        credentialSubject: {
          id: 'mailto:member@example.org',
          '@type': 'Person',
          identifier: 'COL-0001',
        },
        evidence: [
          {
            type: 'official-registry',
            checkedAt: '2026-03-06T10:01:00.000Z',
          },
        ],
      },
      evidence: [
        {
          type: 'qualification',
          checkedAt: '2026-03-06T10:02:00.000Z',
        },
      ],
    },
  }));

  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const submitOutcome = await requestManager.submit(parsed.context, req);
  assert.equal(submitOutcome.type, 'accepted');
  if (submitOutcome.type !== 'accepted') return;
  assert.equal(
    submitOutcome.location,
    '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue-response',
  );
  await new Promise((resolve) => setImmediate(resolve));

  const pollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const pollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue-response?thid=thid-credential-issue-001',
  );
  const pollOutcome = await responseManager.poll(parsed.context, pollReq, pollUrl);
  assert.equal(pollOutcome.type, 'succeeded');

  const issued = (await collectionsService.listIssuedCredentials())
    .filter((item) => item.thid === 'thid-credential-issue-001');
  const evidence = (await collectionsService.listEvidenceRecords())
    .filter((item) => item.thid === 'thid-credential-issue-001');
  assert.equal(issued.length, 1);
  assert.equal(issued[0]?.credentialType, 'member-onboarding');
  assert.equal(issued[0]?.subjectId, 'mailto:member@example.org');
  assert.equal(evidence.length, 2);
});

test('IssueCredential manager rejects credentialSubject without schema.org @type', async () => {
  const parsed = parseIssueCredentialRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const store = new InMemoryEntityJobStore<IssueCredentialRouteContext, IssueCredentialResult>(60);
  const requestManager = new IssueCredentialRequestManager(store);
  const payload = Buffer.from(JSON.stringify({
    jti: 'msg-credential-issue-invalid-001',
    thid: 'thid-credential-issue-invalid-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/issue-request/v1',
    body: {
      credential: {
        id: 'urn:uuid:vc-member-invalid-001',
        type: ['VerifiableCredential', 'MemberCredential'],
        issuer: 'did:web:ica.example.com',
        credentialSubject: {
          id: 'mailto:member-invalid@example.org',
        },
      },
      evidence: [],
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const outcome = await requestManager.submit(parsed.context, req);
  assert.equal(outcome.type, 'error');
  if (outcome.type !== 'error') return;
  assert.equal(outcome.statusCode, 400);
  assert.match(outcome.message, /Invalid credentialSubject schema\.org payload/i);
  assert.match(outcome.message, /credentialSubject\.\@type/i);
});

test('Credential status and revoke managers resolve and update revocation state', async () => {
  const parsedIssue = parseIssueCredentialRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue');
  const parsedStatus = parseCredentialStatusRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status');
  const parsedRevoke = parseCredentialRevokeRoute('/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_revoke');
  assert.ok(parsedIssue && parsedIssue.ok);
  assert.ok(parsedStatus && parsedStatus.ok);
  assert.ok(parsedRevoke && parsedRevoke.ok);
  if (!parsedIssue || !parsedIssue.ok || !parsedStatus || !parsedStatus.ok || !parsedRevoke || !parsedRevoke.ok) return;

  resetVerificationCollectionsMemStateForTests();
  const collectionsService = new VerificationCollectionsService({
    provider: 'mem',
    required: true,
    firestoreCollectionPrefix: 'ica',
    issuedCredentialsCollection: 'issued_credentials',
    evidenceCollection: 'evidence_records',
  });

  const issueStore = new InMemoryEntityJobStore<IssueCredentialRouteContext, IssueCredentialResult>(60);
  const issueRequestManager = new IssueCredentialRequestManager(issueStore, collectionsService);
  const issueResponseManager = new IssueCredentialResponseManager(issueStore);
  const statusStore = new InMemoryEntityJobStore<CredentialStatusRouteContext, CredentialStatusResult>(60);
  const statusRequestManager = new CredentialStatusRequestManager(statusStore, collectionsService);
  const statusResponseManager = new CredentialStatusResponseManager(statusStore);
  const revokeStore = new InMemoryEntityJobStore<CredentialRevokeRouteContext, CredentialRevokeResult>(60);
  const revokeRequestManager = new CredentialRevokeRequestManager(revokeStore, collectionsService);
  const revokeResponseManager = new CredentialRevokeResponseManager(revokeStore);

  const credentialId = 'urn:uuid:vc-member-status-001';
  const issuePayload = Buffer.from(JSON.stringify({
    jti: 'msg-credential-issue-status-001',
    thid: 'thid-credential-issue-status-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/issue-request/v1',
    body: {
      credential: {
        id: credentialId,
        type: ['VerifiableCredential', 'MemberCredential'],
        issuer: 'did:web:ica.example.com',
        credentialSubject: {
          id: 'mailto:member-status@example.org',
          '@type': 'Person',
        },
      },
      evidence: [],
    },
  }));
  const issueReq = Readable.from([issuePayload]) as unknown as IncomingMessage;
  (issueReq as any).method = 'POST';
  (issueReq as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue';
  (issueReq as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(issuePayload.length),
  };
  const issueSubmitOutcome = await issueRequestManager.submit(parsedIssue.context, issueReq);
  assert.equal(issueSubmitOutcome.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const issuePollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const issuePollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_issue-response?thid=thid-credential-issue-status-001',
  );
  const issuePollOutcome = await issueResponseManager.poll(parsedIssue.context, issuePollReq, issuePollUrl);
  assert.equal(issuePollOutcome.type, 'succeeded');

  const statusPayloadBefore = Buffer.from(JSON.stringify({
    jti: 'msg-credential-status-before-001',
    thid: 'thid-credential-status-before-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/status-request/v1',
    body: {
      credentialId,
    },
  }));
  const statusReqBefore = Readable.from([statusPayloadBefore]) as unknown as IncomingMessage;
  (statusReqBefore as any).method = 'POST';
  (statusReqBefore as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status';
  (statusReqBefore as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(statusPayloadBefore.length),
  };
  const statusSubmitBefore = await statusRequestManager.submit(parsedStatus.context, statusReqBefore);
  assert.equal(statusSubmitBefore.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const statusPollReqBefore = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const statusPollUrlBefore = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status-response?thid=thid-credential-status-before-001',
  );
  const statusPollOutcomeBefore = await statusResponseManager.poll(
    parsedStatus.context,
    statusPollReqBefore,
    statusPollUrlBefore,
  );
  assert.equal(statusPollOutcomeBefore.type, 'succeeded');
  if (statusPollOutcomeBefore.type !== 'succeeded') return;
  const statusPayloadResolvedBefore = statusPollOutcomeBefore.payload as {
    body?: { data?: Array<{ resource?: { content?: Array<{ status?: string }> } }> };
  };
  assert.equal(statusPayloadResolvedBefore.body?.data?.[0]?.resource?.content?.[0]?.status, 'good');

  const revokePayload = Buffer.from(JSON.stringify({
    jti: 'msg-credential-revoke-001',
    thid: 'thid-credential-revoke-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/revoke-request/v1',
    body: {
      credentialId,
      reason: 'membership-terminated',
      revokedBy: 'did:web:ica.example.com#employee-07',
    },
  }));
  const revokeReq = Readable.from([revokePayload]) as unknown as IncomingMessage;
  (revokeReq as any).method = 'POST';
  (revokeReq as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_revoke';
  (revokeReq as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(revokePayload.length),
  };
  const revokeSubmitOutcome = await revokeRequestManager.submit(parsedRevoke.context, revokeReq);
  assert.equal(revokeSubmitOutcome.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const revokePollReq = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const revokePollUrl = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_revoke-response?thid=thid-credential-revoke-001',
  );
  const revokePollOutcome = await revokeResponseManager.poll(parsedRevoke.context, revokePollReq, revokePollUrl);
  assert.equal(revokePollOutcome.type, 'succeeded');

  const statusPayloadAfter = Buffer.from(JSON.stringify({
    jti: 'msg-credential-status-after-001',
    thid: 'thid-credential-status-after-001',
    type: 'https://globaldatacare.es/didcomm/ica/network/credentials/status-request/v1',
    body: {
      credentialId,
    },
  }));
  const statusReqAfter = Readable.from([statusPayloadAfter]) as unknown as IncomingMessage;
  (statusReqAfter as any).method = 'POST';
  (statusReqAfter as any).url = '/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status';
  (statusReqAfter as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(statusPayloadAfter.length),
  };
  const statusSubmitAfter = await statusRequestManager.submit(parsedStatus.context, statusReqAfter);
  assert.equal(statusSubmitAfter.type, 'accepted');
  await new Promise((resolve) => setImmediate(resolve));
  const statusPollReqAfter = { method: 'POST', headers: { host: 'localhost:3310' } } as unknown as IncomingMessage;
  const statusPollUrlAfter = new URL(
    'http://localhost/acme/cds-ES/v1/animal-care/network/credentials/member-onboarding/_status-response?thid=thid-credential-status-after-001',
  );
  const statusPollOutcomeAfter = await statusResponseManager.poll(
    parsedStatus.context,
    statusPollReqAfter,
    statusPollUrlAfter,
  );
  assert.equal(statusPollOutcomeAfter.type, 'succeeded');
  if (statusPollOutcomeAfter.type !== 'succeeded') return;
  const statusPayloadResolvedAfter = statusPollOutcomeAfter.payload as {
    body?: {
      data?: Array<{ resource?: { content?: Array<{ status?: string; revokedAt?: string }> } }>;
    };
  };
  assert.equal(statusPayloadResolvedAfter.body?.data?.[0]?.resource?.content?.[0]?.status, 'revoked');
  assert.equal(Boolean(statusPayloadResolvedAfter.body?.data?.[0]?.resource?.content?.[0]?.revokedAt), true);

  const issued = await collectionsService.listIssuedCredentials();
  const updated = issued.find((entry) => entry.credentialId === credentialId);
  assert.ok(updated);
  const credentialStatus = (updated?.credential?.credentialStatus || {}) as Record<string, unknown>;
  assert.equal(credentialStatus.status, 'revoked');
});

function buildTestVerifyResult(label: string): VerifyResult {
  return {
    ok: true,
    verifiedAt: '2026-03-05T00:00:00.000Z',
    templateUrl: `https://example.test/${label}.pdf`,
    templateMatch: true,
    signatureValid: true,
    chainValid: true,
    revocationStatus: 'good',
    digest: {
      alg: 'sha3-384',
      signedPdfHex: 'a',
      unsignedPdfHex: 'b',
      templateHex: 'c',
    },
    signerCertificateSerialNumber: '00AA11',
    signerSubject: 'CN=Signer',
    signerIssuer: 'CN=FNMT',
    hashes: {
      signedPdfSha256Hex: 'a',
      unsignedPdfSha256Hex: 'b',
      templateSha256Hex: 'c',
    },
    notes: [label],
  };
}

function buildAdapter(
  id: string,
  supportsJurisdiction: string,
  calls: string[],
): SignatureVerifierAdapter {
  return {
    id,
    supports: (route) => route.jurisdiction.toLowerCase() === supportsJurisdiction.toLowerCase(),
    verify: async (_route, _submission) => {
      calls.push(id);
      return buildTestVerifyResult(id);
    },
  };
}

function buildMinimalPdf(contentStream: string, pageExtra = '', extraObjects = ''): Buffer {
  const streamBuffer = Buffer.from(contentStream, 'latin1');
  const pageDictionaryExtra = pageExtra ? ` ${pageExtra}` : '';
  const extra = extraObjects ? `\n${extraObjects}\n` : '\n';
  return Buffer.from(
    [
      '%PDF-1.4',
      '1 0 obj',
      '<< /Type /Catalog /Pages 2 0 R >>',
      'endobj',
      '2 0 obj',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      'endobj',
      '3 0 obj',
      `<< /Type /Page /Parent 2 0 R /Contents 4 0 R${pageDictionaryExtra} >>`,
      'endobj',
      '4 0 obj',
      `<< /Length ${streamBuffer.length} >>`,
      'stream',
      contentStream,
      'endstream',
      'endobj',
      extra,
      '%%EOF',
      '',
    ].join('\n'),
    'latin1',
  );
}

test('SignatureVerificationManager uses preferred adapter when supported', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const calls: string[] = [];
  const manager = new SignatureVerificationManager(
    [
      buildAdapter('fnmt-es', 'ES', calls),
      buildAdapter('camerfirma-es', 'ES', calls),
    ],
    {
      preferredAdapterId: 'camerfirma-es',
      strictPreferredAdapter: true,
    },
  );

  const submission: VerifySubmission = {
    thid: 'thid-adapter-1',
    pdfBytes: Buffer.from('pdf'),
    contentType: 'application/pdf',
  };
  const result = await manager.verify(parsed.context, submission);
  assert.deepEqual(calls, ['camerfirma-es']);
  assert.equal(result.notes[0], 'camerfirma-es');
});

test('SignatureVerificationManager falls back when preferred adapter is unsupported and strict=false', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const calls: string[] = [];
  const manager = new SignatureVerificationManager(
    [
      buildAdapter('fnmt-es', 'ES', calls),
      buildAdapter('camerfirma-pt', 'PT', calls),
    ],
    {
      preferredAdapterId: 'camerfirma-pt',
      strictPreferredAdapter: false,
    },
  );

  const submission: VerifySubmission = {
    thid: 'thid-adapter-2',
    pdfBytes: Buffer.from('pdf'),
    contentType: 'application/pdf',
  };
  const result = await manager.verify(parsed.context, submission);
  assert.deepEqual(calls, ['fnmt-es']);
  assert.equal(result.notes[0], 'fnmt-es');
});

test('SignatureVerificationManager fails when no adapter supports the request', async () => {
  const parsed = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/202630011200/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  const manager = new SignatureVerificationManager([
    {
      id: 'camerfirma-pt',
      supports: () => false,
      verify: async () => buildTestVerifyResult('camerfirma-pt'),
    },
  ]);

  const submission: VerifySubmission = {
    thid: 'thid-adapter-3',
    pdfBytes: Buffer.from('pdf'),
    contentType: 'application/pdf',
  };

  await assert.rejects(
    async () => manager.verify(parsed.context, submission),
    /No signature verifier adapter supports jurisdiction/i,
  );
});
