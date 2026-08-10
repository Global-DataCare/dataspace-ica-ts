import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createIcaApiServer } from '../src/api/server.ts';
import { buildIcaDidDocument, buildIcaJwks } from '../src/api/tools/ica-identity.ts';

/**
 * Flow contract: ICA serves an operator-provided DID, JWKS and exact public
 * X.509 chain without regenerating or rewriting trust material. The lightweight
 * request/response harness mirrors the other ICA API unit tests.
 */
function buildMockRequest(url: string, method = 'GET', headers: Record<string, string> = {}): IncomingMessage {
  const req = Readable.from([]) as IncomingMessage & Readable;
  req.method = method;
  req.url = url;
  req.headers = headers;
  return req;
}

function buildMockResponse() {
  const headers = new Map<string, string | number | readonly string[]>();
  const chunks: Buffer[] = [];
  return {
    res: {
      statusCode: 200,
      setHeader(name: string, value: string | number | readonly string[]) {
        headers.set(name.toLowerCase(), value);
      },
      end(chunk?: string | Buffer) {
        if (chunk) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
      },
    } as unknown as ServerResponse,
    headers,
    getBodyBuffer() {
      return Buffer.concat(chunks);
    },
    getBodyText() {
      return this.getBodyBuffer().toString('utf8');
    },
  };
}

test('ICA well-known endpoints can be served directly from generated public artifacts', async () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'ica-public-artifacts-'));
  const previousArtifactsDir = process.env.ICA_PUBLIC_ARTIFACTS_DIR;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;

  try {
    const did = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:web:ica.test.example.org',
      verificationMethod: [
        {
          id: 'did:web:ica.test.example.org#sig-1',
          type: 'JsonWebKey2020',
          controller: 'did:web:ica.test.example.org',
          publicKeyJwk: {
            kty: 'EC',
            crv: 'P-384',
            x: 'abc',
            y: 'def',
            kid: 'sig-1',
            alg: 'ES384',
            use: 'sig',
            x5c: ['leaf', 'root'],
          },
        },
      ],
      service: [
        {
          id: 'did:web:ica.test.example.org#jwks',
          type: 'JsonWebKeyService2020',
          serviceEndpoint: 'https://ica.test.example.org/.well-known/jwks.json',
        },
      ],
    };
    const jwks = {
      keys: [
        {
          kty: 'EC',
          crv: 'P-384',
          x: 'abc',
          y: 'def',
          kid: 'sig-1',
          alg: 'ES384',
          use: 'sig',
          x5c: ['leaf', 'root'],
        },
      ],
    };
    const x509 = Buffer.from('0123456789abcdef', 'hex');
    const x509Pem = '-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----';

    writeFileSync(path.join(tempDir, 'did-ica.test.example.org.json'), JSON.stringify(did, null, 2));
    writeFileSync(path.join(tempDir, 'jwks-ica.test.example.org.json'), JSON.stringify(jwks, null, 2));
    writeFileSync(path.join(tempDir, 'x509.der'), x509);
    writeFileSync(path.join(tempDir, 'x509.pem'), x509Pem);

    // The runtime should behave as a thin publisher over the generated files, not as a second source of truth.
    process.env.ICA_PUBLIC_ARTIFACTS_DIR = tempDir;
    delete process.env.ICA_DIDCOMM_ISSUER_DID;

    const server = createIcaApiServer();
    const handler = server.listeners('request')[0] as ((req: IncomingMessage, res: ServerResponse) => Promise<void> | void);

    const didReq = buildMockRequest('/.well-known/did.json');
    const didRes = buildMockResponse();
    await handler(didReq, didRes.res);
    assert.equal(didRes.res.statusCode, 200);
    const didPayload = JSON.parse(didRes.getBodyText()) as Record<string, unknown>;
    assert.equal(didPayload.id, 'did:web:ica.test.example.org');

    const jwksReq = buildMockRequest('/.well-known/jwks.json');
    const jwksRes = buildMockResponse();
    await handler(jwksReq, jwksRes.res);
    assert.equal(jwksRes.res.statusCode, 200);
    assert.deepEqual(JSON.parse(jwksRes.getBodyText()), jwks);

    const x509Req = buildMockRequest('/.well-known/x509.der');
    const x509Res = buildMockResponse();
    await handler(x509Req, x509Res.res);
    assert.equal(x509Res.res.statusCode, 200);
    assert.equal(x509Res.getBodyBuffer().equals(x509), true);

    const x509PemReq = buildMockRequest('/.well-known/x509.pem');
    const x509PemRes = buildMockResponse();
    await handler(x509PemReq, x509PemRes.res);
    assert.equal(x509PemRes.res.statusCode, 200);
    assert.equal(x509PemRes.getBodyText(), x509Pem);

    const builtDid = buildIcaDidDocument();
    assert.equal(builtDid.id, 'did:web:ica.test.example.org');
    assert.equal(
      Array.isArray(builtDid.verificationMethod)
        && (builtDid.verificationMethod as Array<Record<string, unknown>>)[0]?.publicKeyJwk
        && ((builtDid.verificationMethod as Array<Record<string, unknown>>)[0]?.publicKeyJwk as Record<string, unknown>).kid,
      'sig-1',
    );
  } finally {
    if (previousArtifactsDir === undefined) {
      delete process.env.ICA_PUBLIC_ARTIFACTS_DIR;
    } else {
      process.env.ICA_PUBLIC_ARTIFACTS_DIR = previousArtifactsDir;
    }
    if (previousIssuerDid === undefined) {
      delete process.env.ICA_DIDCOMM_ISSUER_DID;
    } else {
      process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ICA publishes ML-DSA and ML-KEM separately from VC assertion methods', async () => {
  const previousCommunicationJwks = process.env.ICA_COMMUNICATION_JWKS_JSON;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousArtifactsDir = process.env.ICA_PUBLIC_ARTIFACTS_DIR;
  try {
    delete process.env.ICA_PUBLIC_ARTIFACTS_DIR;
    process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
    process.env.ICA_COMMUNICATION_JWKS_JSON = JSON.stringify({
      keys: [
        { kid: 'ica-comm-sign-1', kty: 'AKP', alg: 'ML-DSA-44', pub: 'mldsa-public' },
        { kid: 'ica-comm-enc-1', kty: 'OKP', crv: 'ML-KEM-768', x: 'mlkem-public' },
      ],
    });

    const server = createIcaApiServer();
    const handler = server.listeners('request')[0] as ((req: IncomingMessage, res: ServerResponse) => Promise<void> | void);
    const didRes = buildMockResponse();
    await handler(buildMockRequest('/.well-known/did.json'), didRes.res);
    const did = JSON.parse(didRes.getBodyText()) as Record<string, any>;

    assert.ok(did.verificationMethod.some((method: Record<string, any>) =>
      method.id === 'did:web:ica.example.com#ica-comm-sign-1'
      && method.publicKeyJwk.alg === 'ML-DSA-44'
      && method.publicKeyJwk.use === 'sig'));
    assert.ok(did.verificationMethod.some((method: Record<string, any>) =>
      method.id === 'did:web:ica.example.com#ica-comm-enc-1'
      && method.publicKeyJwk.crv === 'ML-KEM-768'
      && method.publicKeyJwk.use === 'enc'));
    assert.ok(did.authentication.includes('did:web:ica.example.com#ica-comm-sign-1'));
    assert.ok(did.keyAgreement.includes('did:web:ica.example.com#ica-comm-enc-1'));
    assert.ok(!(did.assertionMethod || []).includes('did:web:ica.example.com#ica-comm-sign-1'));
    assert.ok(did.service.some((service: Record<string, unknown>) =>
      service.id === 'did:web:ica.example.com#jwks'
      && service.serviceEndpoint === 'https://ica.example.com/.well-known/jwks.json'));

    const jwksRes = buildMockResponse();
    await handler(buildMockRequest('/.well-known/jwks.json'), jwksRes.res);
    const jwks = JSON.parse(jwksRes.getBodyText()) as Record<string, any>;
    assert.ok(jwks.keys.some((key: Record<string, unknown>) => key.kid === 'ica-comm-sign-1'));
    assert.ok(jwks.keys.some((key: Record<string, unknown>) => key.kid === 'ica-comm-enc-1'));
  } finally {
    if (previousCommunicationJwks === undefined) delete process.env.ICA_COMMUNICATION_JWKS_JSON;
    else process.env.ICA_COMMUNICATION_JWKS_JSON = previousCommunicationJwks;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousArtifactsDir === undefined) delete process.env.ICA_PUBLIC_ARTIFACTS_DIR;
    else process.env.ICA_PUBLIC_ARTIFACTS_DIR = previousArtifactsDir;
  }
});

test('ICA rejects private or unsupported communication key material', () => {
  const previousCommunicationJwks = process.env.ICA_COMMUNICATION_JWKS_JSON;
  try {
    process.env.ICA_COMMUNICATION_JWKS_JSON = JSON.stringify({
      keys: [{ kid: 'leaked', kty: 'OKP', crv: 'ML-KEM-768', x: 'public', d: 'private' }],
    });
    assert.throws(() => buildIcaDidDocument(), /must be public-only/);

    process.env.ICA_COMMUNICATION_JWKS_JSON = JSON.stringify({
      keys: [{ kid: 'legacy', kty: 'EC', crv: 'P-384', x: 'x', y: 'y' }],
    });
    assert.throws(() => buildIcaDidDocument(), /must use ML-DSA-44 or ML-KEM-768/);
  } finally {
    if (previousCommunicationJwks === undefined) delete process.env.ICA_COMMUNICATION_JWKS_JSON;
    else process.env.ICA_COMMUNICATION_JWKS_JSON = previousCommunicationJwks;
  }
});

test('ICA publishes x5u only on the legacy ES384 key before certificate provisioning', () => {
  const previousDocument = process.env.ICA_DID_DOCUMENT_JSON;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousCommunicationJwks = process.env.ICA_COMMUNICATION_JWKS_JSON;
  const previousX5u = process.env.ICA_VC_SIGNING_X5U;
  const previousArtifactsDir = process.env.ICA_PUBLIC_ARTIFACTS_DIR;
  try {
    delete process.env.ICA_PUBLIC_ARTIFACTS_DIR;
    delete process.env.ICA_VC_SIGNING_X5U;
    process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
    process.env.ICA_DID_DOCUMENT_JSON = JSON.stringify({
      id: 'did:web:ica.example.com',
      verificationMethod: [{
        id: 'did:web:ica.example.com#legacy',
        controller: 'did:web:ica.example.com',
        type: 'JsonWebKey2020',
        publicKeyJwk: {
          kid: 'legacy',
          kty: 'EC',
          crv: 'P-384',
          alg: 'ES384',
          use: 'sig',
          x: 'legacy-x',
          y: 'legacy-y',
        },
      }],
      assertionMethod: ['did:web:ica.example.com#legacy'],
    });
    process.env.ICA_COMMUNICATION_JWKS_JSON = JSON.stringify({
      keys: [
        { kid: 'pqc-sign', kty: 'AKP', alg: 'ML-DSA-44', pub: 'pqc-sign-public' },
        { kid: 'pqc-enc', kty: 'OKP', crv: 'ML-KEM-768', x: 'pqc-enc-public' },
      ],
    });

    const did = buildIcaDidDocument() as Record<string, any>;
    const keys = did.verificationMethod.map((method: Record<string, any>) => method.publicKeyJwk);
    assert.equal(
      keys.find((key: Record<string, unknown>) => key.alg === 'ES384')?.x5u,
      'https://ica.example.com/.well-known/x509.pem',
    );
    assert.equal(keys.find((key: Record<string, unknown>) => key.alg === 'ML-DSA-44')?.x5u, undefined);
    assert.equal(keys.find((key: Record<string, unknown>) => key.alg === 'ML-KEM-768')?.x5u, undefined);

    const jwks = buildIcaJwks() as Record<string, any>;
    assert.equal(jwks.keys.find((key: Record<string, unknown>) => key.alg === 'ES384')?.x5u,
      'https://ica.example.com/.well-known/x509.pem');
    assert.equal(jwks.keys.find((key: Record<string, unknown>) => key.alg === 'ML-DSA-44')?.x5u, undefined);
    assert.equal(jwks.keys.find((key: Record<string, unknown>) => key.alg === 'ML-KEM-768')?.x5u, undefined);
  } finally {
    if (previousDocument === undefined) delete process.env.ICA_DID_DOCUMENT_JSON;
    else process.env.ICA_DID_DOCUMENT_JSON = previousDocument;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousCommunicationJwks === undefined) delete process.env.ICA_COMMUNICATION_JWKS_JSON;
    else process.env.ICA_COMMUNICATION_JWKS_JSON = previousCommunicationJwks;
    if (previousX5u === undefined) delete process.env.ICA_VC_SIGNING_X5U;
    else process.env.ICA_VC_SIGNING_X5U = previousX5u;
    if (previousArtifactsDir === undefined) delete process.env.ICA_PUBLIC_ARTIFACTS_DIR;
    else process.env.ICA_PUBLIC_ARTIFACTS_DIR = previousArtifactsDir;
  }
});
