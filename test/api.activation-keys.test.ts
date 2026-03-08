import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import type { IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { InMemoryActivationJobStore } from '../src/api/activation-job-store.ts';
import {
  buildActivateResponseLocation,
  buildRotateResponseLocation,
  parseActivateRoute,
  parseRotateRoute,
} from '../src/api/path.ts';
import { ActivateRequestManager } from '../src/api/managers/activate-request-manager.ts';
import { parseActivateSigningKeySubmission, parseRotateSubmission } from '../src/api/request-parsing.ts';
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
import type { ActivateSigningKeyInput } from '../src/api/types.ts';

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

test('parseActivateRoute accepts valid _activate route', () => {
  const parsed = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.tenantId, 'ica');
  assert.equal(parsed.context.jurisdiction, 'ES');
  assert.equal(parsed.context.sector, 'animal-care');
  assert.equal(parsed.context.action, '_activate');
});

test('buildActivateResponseLocation builds canonical polling path', () => {
  const parsed = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(
    buildActivateResponseLocation(parsed.context),
    '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate-response',
  );
});

test('parseRotateRoute accepts credentials and communications rotate routes', () => {
  const credentials = parseRotateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_rotate');
  assert.ok(credentials);
  assert.equal(credentials?.ok, true);
  if (!credentials || !credentials.ok) return;
  assert.equal(credentials.context.resourceType, 'credentials');
  assert.equal(credentials.context.action, '_rotate');
  assert.equal(
    buildRotateResponseLocation(credentials.context),
    '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_rotate-response',
  );

  const communications = parseRotateRoute('/ica/cds-ES/v1/animal-care/entity/keys/communications/_rotate');
  assert.ok(communications);
  assert.equal(communications?.ok, true);
  if (!communications || !communications.ok) return;
  assert.equal(communications.context.resourceType, 'communications');
  assert.equal(communications.context.action, '_rotate');
  assert.equal(
    buildRotateResponseLocation(communications.context),
    '/ica/cds-ES/v1/animal-care/entity/keys/communications/_rotate-response',
  );
});

test('parseRotateSubmission ignores legacy body.proof', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'rotate-proof-parse-001',
    thid: 'rotate-proof-parse-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/rotate-request/v1',
    body: {
      proof: {
        kid: 'controller-rotate-kid',
        alg: 'ES384',
        jws: 'aaa.bbb.ccc',
      },
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseRotateSubmission(req);
  assert.equal(parsed.jti, 'rotate-proof-parse-001');
  assert.equal(parsed.thid, 'rotate-proof-parse-001');
  assert.equal(parsed.controllerProof, undefined);
});

test('parseRotateSubmission reads controller signature from body.signature', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'rotate-signature-parse-001',
    thid: 'rotate-signature-parse-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/rotate-request/v1',
    body: {
      signature: {
        sigFormat: 'application/jose',
        who: { reference: 'did:web:ica.example.com#controller-rotate-kid' },
        data: 'aaa.bbb.ccc',
      },
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseRotateSubmission(req);
  assert.equal(parsed.jti, 'rotate-signature-parse-001');
  assert.equal(parsed.thid, 'rotate-signature-parse-001');
  assert.equal(parsed.controllerProof?.kid, 'did:web:ica.example.com#controller-rotate-kid');
  assert.equal(parsed.controllerProof?.jws, 'aaa.bbb.ccc');
});

test('validateRotateControllerDidcommProof accepts DIDComm JWS signed with DID controller key', async () => {
  const parsedRoute = parseRotateRoute('/ica/cds-ES/v1/animal-care/entity/keys/communications/_rotate');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousSelfControllerKid = process.env.ICA_SELF_CONTROLLER_KID;
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.ICA_SELF_CONTROLLER_KID = 'controller-rotate-kid';
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    activateSigningKey({
      kid: 'controller-rotate-kid',
      alg: 'ES384',
      privateKeyPem,
    });

    const thid = 'rotate-proof-valid-001';
    const jti = 'rotate-proof-valid-001';
    const jws = buildControllerProofJws({
      kid: 'did:web:ica.example.com#controller-rotate-kid',
      thid,
      jti,
      action: '_rotate',
      resourceType: 'communications',
      privateKeyPem,
    });
    const payload = Buffer.from(JSON.stringify({
      jti,
      thid,
      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/rotate-request/v1',
      body: {
        signature: {
          sigFormat: 'application/jose',
          who: { reference: 'did:web:ica.example.com#controller-rotate-kid' },
          data: jws,
        },
      },
    }));
    const req = Readable.from([payload]) as unknown as IncomingMessage;
    (req as any).method = 'POST';
    (req as any).url = '/ica/cds-ES/v1/animal-care/entity/keys/communications/_rotate';
    (req as any).headers = {
      host: 'localhost:3310',
      'content-type': 'application/didcomm-plain+json',
      'content-length': String(payload.length),
    };

    const submission = await parseRotateSubmission(req);
    const validationReq = {
      headers: { host: 'localhost:3310' },
    } as unknown as IncomingMessage;
    validateRotateControllerDidcommProof(submission, parsedRoute.context, validationReq);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousSelfControllerKid === undefined) delete process.env.ICA_SELF_CONTROLLER_KID;
    else process.env.ICA_SELF_CONTROLLER_KID = previousSelfControllerKid;
  }
});

test('parseActivateSigningKeySubmission supports body.data[] for multiple keys', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'activate-multi-001',
    thid: 'activate-multi-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
    body: {
      data: [
        {
          key: {
            kid: 'ica-es384-001',
            alg: 'ES384',
            privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nES384\\n-----END PRIVATE KEY-----',
          },
        },
        {
          key: {
            kid: 'ica-es256k-001',
            alg: 'ES256K',
            privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nES256K\\n-----END PRIVATE KEY-----',
            x5c: ['MIIBTESTX5C'],
          },
        },
      ],
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseActivateSigningKeySubmission(req);
  assert.equal(parsed.thid, 'activate-multi-001');
  assert.equal(Array.isArray(parsed.keys), true);
  assert.equal(parsed.keys.length, 2);
  assert.equal(parsed.keys[0]?.kid, 'ica-es384-001');
  assert.equal(parsed.keys[0]?.alg, 'ES384');
  assert.equal(parsed.keys[1]?.kid, 'ica-es256k-001');
  assert.equal(parsed.keys[1]?.alg, 'ES256K');
  assert.equal(parsed.keys[1]?.x5c?.[0], 'MIIBTESTX5C');
});

test('parseActivateSigningKeySubmission supports single key via body.data[]', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'activate-single-001',
    thid: 'activate-single-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
    body: {
      data: [
        {
          key: {
            kid: 'ica-es384-legacy',
            alg: 'ES384',
            privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nLEGACY\\n-----END PRIVATE KEY-----',
          },
        },
      ],
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseActivateSigningKeySubmission(req);
  assert.equal(parsed.thid, 'activate-single-001');
  assert.equal(parsed.keys.length, 1);
  assert.equal(parsed.keys[0]?.kid, 'ica-es384-legacy');
  assert.equal(parsed.keys[0]?.alg, 'ES384');
});

test('parseActivateSigningKeySubmission rejects body.key-only payloads', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'activate-key-only-001',
    thid: 'activate-key-only-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
    body: {
      key: {
        kid: 'ica-es384-legacy',
        alg: 'ES384',
        privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nLEGACY\\n-----END PRIVATE KEY-----',
      },
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  await assert.rejects(
    async () => parseActivateSigningKeySubmission(req),
    /body\.data\[\]/i,
  );
});

test('parseActivateSigningKeySubmission ignores legacy body.proof', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'activate-proof-parse-001',
    thid: 'activate-proof-parse-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
    body: {
      data: [
        {
          key: {
            kid: 'controller-es384-kid',
            alg: 'ES384',
            privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nLEGACY\\n-----END PRIVATE KEY-----',
          },
        },
      ],
      proof: {
        kid: 'controller-es384-kid',
        alg: 'ES384',
        jws: 'aaa.bbb.ccc',
      },
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseActivateSigningKeySubmission(req);
  assert.equal(parsed.jti, 'activate-proof-parse-001');
  assert.equal(parsed.thid, 'activate-proof-parse-001');
  assert.equal(parsed.controllerProof, undefined);
});

test('parseActivateSigningKeySubmission reads controller signature from body.signature', async () => {
  const payload = Buffer.from(JSON.stringify({
    jti: 'activate-signature-parse-001',
    thid: 'activate-signature-parse-001',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
    body: {
      data: [
        {
          key: {
            kid: 'controller-es384-kid',
            alg: 'ES384',
            privateKeyPem: '-----BEGIN PRIVATE KEY-----\\nLEGACY\\n-----END PRIVATE KEY-----',
          },
        },
      ],
      signature: {
        sigFormat: 'application/jose',
        who: { reference: 'did:web:ica.example.com#controller-es384-kid' },
        data: 'aaa.bbb.ccc',
      },
    },
  }));
  const req = Readable.from([payload]) as unknown as IncomingMessage;
  (req as any).method = 'POST';
  (req as any).headers = {
    host: 'localhost:3310',
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(payload.length),
  };

  const parsed = await parseActivateSigningKeySubmission(req);
  assert.equal(parsed.jti, 'activate-signature-parse-001');
  assert.equal(parsed.thid, 'activate-signature-parse-001');
  assert.equal(parsed.controllerProof?.kid, 'did:web:ica.example.com#controller-es384-kid');
  assert.equal(parsed.controllerProof?.jws, 'aaa.bbb.ccc');
  assert.equal(Boolean(parsed.controllerAuthorizationPayloadBase64Url), true);
});

test('ActivateRequestManager requires controller authorization signature for activation requests', async () => {
  const parsedRoute = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const previousSelfControllerKid = process.env.ICA_SELF_CONTROLLER_KID;
  process.env.ICA_SELF_CONTROLLER_KID = 'controller-bootstrap-kid';
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const payload = Buffer.from(JSON.stringify({
      jti: 'activate-missing-proof-001',
      thid: 'activate-missing-proof-001',
      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
      body: {
        data: [
          {
            key: {
              kid: 'controller-bootstrap-kid',
              alg: 'ES384',
              privateKeyPem,
            },
          },
        ],
      },
    }));
    const req = Readable.from([payload]) as unknown as IncomingMessage;
    (req as any).method = 'POST';
    (req as any).url = '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate';
    (req as any).headers = {
      host: 'localhost:3310',
      'content-type': 'application/didcomm-plain+json',
      'content-length': String(payload.length),
    };

    const manager = new ActivateRequestManager(new InMemoryActivationJobStore(60));
    const outcome = await manager.submit(parsedRoute.context, req);
    assert.equal(outcome.type, 'error');
    if (outcome.type !== 'error') return;
    assert.equal(outcome.statusCode, 400);
    assert.match(outcome.message, /signature|controllerproof/i);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousSelfControllerKid === undefined) delete process.env.ICA_SELF_CONTROLLER_KID;
    else process.env.ICA_SELF_CONTROLLER_KID = previousSelfControllerKid;
  }
});

test('ActivateRequestManager rejects non-detached controller proof payload for _activate', async () => {
  const parsedRoute = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const previousSelfControllerKid = process.env.ICA_SELF_CONTROLLER_KID;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousDisableCaValidation = process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
  process.env.ICA_SELF_CONTROLLER_KID = 'controller-es384-kid';
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION = 'true';
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const thid = 'activate-proof-non-detached-001';
    const jti = 'activate-proof-non-detached-001';
    const activateKeys: ActivateSigningKeyInput[] = [
      {
        kid: 'controller-es384-kid',
        alg: 'ES384',
        privateKeyPem,
      },
    ];
    const jws = buildNonDetachedActivateProofJws({
      kid: 'did:web:ica.example.com#controller-es384-kid',
      thid,
      jti,
      privateKeyPem,
    });

    const payload = Buffer.from(JSON.stringify({
      jti,
      thid,
      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
      body: {
        data: activateKeys.map((key) => ({ key })),
        signature: {
          sigFormat: 'application/jose',
          who: { reference: 'did:web:ica.example.com#controller-es384-kid' },
          data: jws,
        },
      },
    }));
    const req = Readable.from([payload]) as unknown as IncomingMessage;
    (req as any).method = 'POST';
    (req as any).url = '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate';
    (req as any).headers = {
      host: 'localhost:3310',
      'content-type': 'application/didcomm-plain+json',
      'content-length': String(payload.length),
    };

    const manager = new ActivateRequestManager(new InMemoryActivationJobStore(60));
    const outcome = await manager.submit(parsedRoute.context, req);
    assert.equal(outcome.type, 'error');
    if (outcome.type !== 'error') return;
    assert.equal(outcome.statusCode, 400);
    assert.match(outcome.message, /detached/i);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousSelfControllerKid === undefined) delete process.env.ICA_SELF_CONTROLLER_KID;
    else process.env.ICA_SELF_CONTROLLER_KID = previousSelfControllerKid;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousDisableCaValidation === undefined) delete process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
    else process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION = previousDisableCaValidation;
  }
});

test('ActivateRequestManager rejects activation keys without x509 CA credential chain by default', async () => {
  const parsedRoute = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const previousSelfControllerKid = process.env.ICA_SELF_CONTROLLER_KID;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousDisableCaValidation = process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
  process.env.ICA_SELF_CONTROLLER_KID = 'controller-es384-kid';
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  delete process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const thid = 'activate-missing-ca-chain-001';
    const jti = 'activate-missing-ca-chain-001';
    const activateKeys: ActivateSigningKeyInput[] = [
      {
        kid: 'controller-es384-kid',
        alg: 'ES384',
        privateKeyPem,
      },
    ];
    const jws = buildControllerProofJws({
      kid: 'did:web:ica.example.com#controller-es384-kid',
      thid,
      action: '_activate',
      jti,
      privateKeyPem,
      activateKeys,
    });

    const payload = Buffer.from(JSON.stringify({
      jti,
      thid,
      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
      body: {
        data: activateKeys.map((key) => ({ key })),
        signature: {
          sigFormat: 'application/jose',
          who: { reference: 'did:web:ica.example.com#controller-es384-kid' },
          data: jws,
        },
      },
    }));
    const req = Readable.from([payload]) as unknown as IncomingMessage;
    (req as any).method = 'POST';
    (req as any).url = '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate';
    (req as any).headers = {
      host: 'localhost:3310',
      'content-type': 'application/didcomm-plain+json',
      'content-length': String(payload.length),
    };

    const manager = new ActivateRequestManager(new InMemoryActivationJobStore(60));
    const outcome = await manager.submit(parsedRoute.context, req);
    assert.equal(outcome.type, 'error');
    if (outcome.type !== 'error') return;
    assert.equal(outcome.statusCode, 400);
    assert.match(outcome.message, /ca credential chain|x5c|certificatechainpem/i);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousSelfControllerKid === undefined) delete process.env.ICA_SELF_CONTROLLER_KID;
    else process.env.ICA_SELF_CONTROLLER_KID = previousSelfControllerKid;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousDisableCaValidation === undefined) delete process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
    else process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION = previousDisableCaValidation;
  }
});

test('ActivateRequestManager accepts activation key when CA x509 chain is present and valid', async () => {
  const parsedRoute = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const previousSelfControllerKid = process.env.ICA_SELF_CONTROLLER_KID;
  const previousSelfControllerEmail = process.env.ICA_SELF_CONTROLLER_EMAIL;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousDisableCaValidation = process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
  process.env.ICA_SELF_CONTROLLER_KID = 'controller-ca-es384-kid';
  process.env.ICA_SELF_CONTROLLER_EMAIL = 'it-director@example.org';
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  delete process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
  resetActiveSigningKeysStateForTests();

  try {
    const thid = 'activate-with-ca-chain-001';
    const jti = 'activate-with-ca-chain-001';
    const activateKeys: ActivateSigningKeyInput[] = [
      {
        kid: 'controller-ca-es384-kid',
        alg: 'ES384',
        privateKeyPem: CONTROLLER_CA_TEST_PRIVATE_KEY_PEM,
        x5c: [CONTROLLER_CA_TEST_X5C],
      },
    ];
    const jws = buildControllerProofJws({
      kid: 'did:web:ica.example.com#controller-ca-es384-kid',
      thid,
      action: '_activate',
      jti,
      privateKeyPem: CONTROLLER_CA_TEST_PRIVATE_KEY_PEM,
      activateKeys,
    });

    const payload = Buffer.from(JSON.stringify({
      jti,
      thid,
      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
      body: {
        data: activateKeys.map((key) => ({ key })),
        signature: {
          sigFormat: 'application/jose',
          who: { reference: 'did:web:ica.example.com#controller-ca-es384-kid' },
          data: jws,
        },
      },
    }));
    const req = Readable.from([payload]) as unknown as IncomingMessage;
    (req as any).method = 'POST';
    (req as any).url = '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate';
    (req as any).headers = {
      host: 'localhost:3310',
      'content-type': 'application/didcomm-plain+json',
      'content-length': String(payload.length),
    };

    const jobStore = new InMemoryActivationJobStore(60);
    const manager = new ActivateRequestManager(jobStore);
    const outcome = await manager.submit(parsedRoute.context, req);
    assert.equal(outcome.type, 'accepted');
    if (outcome.type !== 'accepted') return;
    await new Promise((resolve) => setImmediate(resolve));
    const job = jobStore.get(thid);
    assert.ok(job);
    assert.equal(job?.status, 'succeeded');
    assert.equal(job?.result?.activated?.[0]?.kid, 'controller-ca-es384-kid');
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousSelfControllerKid === undefined) delete process.env.ICA_SELF_CONTROLLER_KID;
    else process.env.ICA_SELF_CONTROLLER_KID = previousSelfControllerKid;
    if (previousSelfControllerEmail === undefined) delete process.env.ICA_SELF_CONTROLLER_EMAIL;
    else process.env.ICA_SELF_CONTROLLER_EMAIL = previousSelfControllerEmail;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousDisableCaValidation === undefined) delete process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
    else process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION = previousDisableCaValidation;
  }
});

test('ActivateRequestManager accepts controller signature from body.signature', async () => {
  const parsedRoute = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const previousSelfControllerKid = process.env.ICA_SELF_CONTROLLER_KID;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousDisableCaValidation = process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
  process.env.ICA_SELF_CONTROLLER_KID = 'controller-es384-kid';
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION = 'true';
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const thid = 'activate-proof-valid-001';
    const jti = 'activate-proof-valid-001';
    const activateKeys: ActivateSigningKeyInput[] = [
      {
        kid: 'controller-es384-kid',
        alg: 'ES384',
        privateKeyPem,
      },
    ];
    const jws = buildControllerProofJws({
      kid: 'did:web:ica.example.com#controller-es384-kid',
      thid,
      action: '_activate',
      jti,
      privateKeyPem,
      activateKeys,
    });

    const payload = Buffer.from(JSON.stringify({
      jti,
      thid,
      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
      body: {
        data: activateKeys.map((key) => ({ key })),
        signature: {
          sigFormat: 'application/jose',
          who: { reference: 'did:web:ica.example.com#controller-es384-kid' },
          data: jws,
        },
      },
    }));
    const req = Readable.from([payload]) as unknown as IncomingMessage;
    (req as any).method = 'POST';
    (req as any).url = '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate';
    (req as any).headers = {
      host: 'localhost:3310',
      'content-type': 'application/didcomm-plain+json',
      'content-length': String(payload.length),
    };

    const jobStore = new InMemoryActivationJobStore(60);
    const manager = new ActivateRequestManager(jobStore);
    const outcome = await manager.submit(parsedRoute.context, req);
    assert.equal(outcome.type, 'accepted');
    if (outcome.type !== 'accepted') return;
    await new Promise((resolve) => setImmediate(resolve));
    const job = jobStore.get(thid);
    assert.ok(job);
    assert.equal(job?.status, 'succeeded');
    assert.equal(job?.result?.activated?.[0]?.kid, 'controller-es384-kid');
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousSelfControllerKid === undefined) delete process.env.ICA_SELF_CONTROLLER_KID;
    else process.env.ICA_SELF_CONTROLLER_KID = previousSelfControllerKid;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousDisableCaValidation === undefined) delete process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
    else process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION = previousDisableCaValidation;
  }
});

test('ActivateRequestManager imports deterministic ES384 and ES256K keys using RFC7638 thumbprint as kid', async () => {
  const parsedRoute = parseActivateRoute('/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
  assert.ok(parsedRoute);
  assert.equal(parsedRoute?.ok, true);
  if (!parsedRoute || !parsedRoute.ok) return;

  const previousActiveKeysFile = process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousDisableCaValidation = process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-activate-deterministic-test-'));
  process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = path.join(tempDir, 'active-signing-keys.json');
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION = 'true';
  resetActiveSigningKeysStateForTests();

  try {
    const es384 = deriveDeterministicEcPrivateKeyPem('ica-seed-es384', 'P-384');
    const es256k = deriveDeterministicEcPrivateKeyPem('ica-seed-es256k', 'secp256k1');
    const expectedKidEs384 = computeRfc7638JwkThumbprint(es384.publicJwk);
    const expectedKidEs256k = computeRfc7638JwkThumbprint(es256k.publicJwk);
    const activateKeys: ActivateSigningKeyInput[] = [
      {
        alg: 'ES384',
        privateKeyPem: es384.privateKeyPem,
      },
      {
        alg: 'ES256K',
        privateKeyPem: es256k.privateKeyPem,
      },
    ];
    const proofJws = buildControllerProofJws({
      kid: expectedKidEs384,
      thid: 'activate-deterministic-001',
      action: '_activate',
      jti: 'activate-deterministic-001',
      privateKeyPem: es384.privateKeyPem,
      activateKeys,
    });

    const payload = Buffer.from(JSON.stringify({
      jti: 'activate-deterministic-001',
      thid: 'activate-deterministic-001',
      type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
      body: {
        signature: {
          sigFormat: 'application/jose',
          who: { reference: expectedKidEs384 },
          data: proofJws,
        },
        data: activateKeys.map((key) => ({ key })),
      },
    }));
    const req = Readable.from([payload]) as unknown as IncomingMessage;
    (req as any).method = 'POST';
    (req as any).url = '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate';
    (req as any).headers = {
      host: 'localhost:3310',
      'content-type': 'application/didcomm-plain+json',
      'content-length': String(payload.length),
    };

    const jobStore = new InMemoryActivationJobStore(60);
    const manager = new ActivateRequestManager(jobStore);
    const outcome = await manager.submit(parsedRoute.context, req);
    assert.equal(outcome.type, 'accepted');
    if (outcome.type !== 'accepted') return;
    assert.equal(
      outcome.location,
      '/ica/cds-ES/v1/animal-care/entity/keys/credentials/_activate-response',
    );
    await new Promise((resolve) => setImmediate(resolve));
    const job = jobStore.get('activate-deterministic-001');
    assert.ok(job);
    assert.equal(job?.status, 'succeeded');
    assert.equal(job?.result?.issuerDid, 'did:web:ica.example.com');
    assert.equal(job?.result?.activated?.length, 2);
    assert.equal(job?.result?.activated?.[0]?.kid, expectedKidEs384);
    assert.equal(job?.result?.activated?.[0]?.alg, 'ES384');
    assert.equal(job?.result?.activated?.[1]?.kid, expectedKidEs256k);
    assert.equal(job?.result?.activated?.[1]?.alg, 'ES256K');
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(tempDir, { recursive: true, force: true });
    if (previousActiveKeysFile === undefined) delete process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
    else process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = previousActiveKeysFile;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousDisableCaValidation === undefined) delete process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION;
    else process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION = previousDisableCaValidation;
  }
});
