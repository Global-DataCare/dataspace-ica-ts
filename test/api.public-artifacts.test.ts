import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createIcaApiServer } from '../src/api/server.ts';
import { buildIcaDidDocument } from '../src/api/tools/ica-identity.ts';

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
      id: 'did:web:test-eur-ica.member.example',
      verificationMethod: [
        {
          id: 'did:web:test-eur-ica.member.example#sig-1',
          type: 'JsonWebKey2020',
          controller: 'did:web:test-eur-ica.member.example',
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
          id: 'did:web:test-eur-ica.member.example#jwks',
          type: 'JsonWebKeyService2020',
          serviceEndpoint: 'https://test-eur-ica.member.example/.well-known/jwks.json',
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

    writeFileSync(path.join(tempDir, 'did-test-eur-ica.member.example.json'), JSON.stringify(did, null, 2));
    writeFileSync(path.join(tempDir, 'jwks-test-eur-ica.member.example.json'), JSON.stringify(jwks, null, 2));
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
    assert.equal(didPayload.id, 'did:web:test-eur-ica.member.example');

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
    assert.equal(builtDid.id, 'did:web:test-eur-ica.member.example');
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
