import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  certificatePemToX5c,
  validateIcaSigningTrustFromEnv,
} from '../src/api/tools/ica-root-trust.ts';
import { buildIcaDidDocument } from '../src/api/tools/ica-identity.ts';
import {
  getPreferredSigningKey,
  resetActiveSigningKeysStateForTests,
} from '../src/api/tools/active-signing-keys.ts';
import { loadPublishedX509Pem } from '../src/api/tools/public-artifacts.ts';
import { bootstrapSelfSigningKey } from '../src/api/tools/self-signing.ts';

/**
 * Flow contract: ICA may start in the required trust profile only when its
 * synthetic leaf private key, complete X.509 chain, terminal Root pin and
 * Root did:web verification method describe the same keys. No real
 * organization identifier, certificate or private key is used.
 */

type Fixture = {
  privateKeyPem: string;
  chainPem: string;
  rootDid: string;
  rootPin: string;
  rootDidDocumentJson: string;
};

function runOpenSsl(args: string[]): void {
  execFileSync('openssl', args, { stdio: 'pipe' });
}

function thumbprint(jwk: Record<string, unknown>): string {
  return createHash('sha256')
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
    .digest('base64url');
}

function createFixture(): Fixture {
  const workspace = mkdtempSync(path.join(tmpdir(), 'ica-root-trust-test-'));
  const rootKey = path.join(workspace, 'root-key.pem');
  const rootCert = path.join(workspace, 'root-cert.pem');
  const leafKey = path.join(workspace, 'leaf-key.pem');
  const leafCsr = path.join(workspace, 'leaf.csr.pem');
  const leafCert = path.join(workspace, 'leaf-cert.pem');
  const extensions = path.join(workspace, 'leaf-ext.cnf');
  writeFileSync(extensions, [
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=clientAuth,serverAuth',
  ].join('\n'));

  runOpenSsl(['ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', rootKey]);
  runOpenSsl([
    'req', '-x509', '-new', '-sha384', '-key', rootKey, '-out', rootCert,
    '-days', '365', '-subj', '/CN=Synthetic Dataspace Root/C=ZZ',
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:1',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
  ]);
  runOpenSsl(['ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', leafKey]);
  runOpenSsl([
    'req', '-new', '-sha384', '-key', leafKey, '-out', leafCsr,
    '-subj', '/CN=Synthetic ICA Signing/C=ZZ',
  ]);
  runOpenSsl([
    'x509', '-req', '-sha384', '-in', leafCsr, '-CA', rootCert, '-CAkey', rootKey,
    '-CAcreateserial', '-days', '365', '-extfile', extensions, '-out', leafCert,
  ]);

  const root = new X509Certificate(readFileSync(rootCert, 'utf8'));
  const rootJwk = root.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  const kid = thumbprint(rootJwk);
  const rootDid = 'did:web:ca.synthetic.example';
  return {
    privateKeyPem: readFileSync(leafKey, 'utf8'),
    chainPem: `${readFileSync(leafCert, 'utf8')}\n${readFileSync(rootCert, 'utf8')}`,
    rootDid,
    rootPin: root.fingerprint256,
    rootDidDocumentJson: JSON.stringify({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: rootDid,
      verificationMethod: [{
        id: `${rootDid}#${kid}`,
        type: 'JsonWebKey2020',
        controller: rootDid,
        publicKeyJwk: {
          ...rootJwk,
          kid,
          x5c: [certificatePemToX5c(readFileSync(rootCert, 'utf8'))],
          x5u: 'https://ca.synthetic.example/pki/root-ca.pem',
        },
      }],
      assertionMethod: [`${rootDid}#${kid}`],
    }),
  };
}

function trustedEnvironment(fixture: Fixture): Record<string, string> {
  return {
    ICA_VC_SIGNING_TRUST_REQUIRED: 'true',
    ICA_VC_SIGNING_PRIVATE_KEY_PEM: fixture.privateKeyPem,
    ICA_VC_SIGNING_CERTIFICATE_CHAIN_PEM: fixture.chainPem,
    ICA_ROOT_CA_DID: fixture.rootDid,
    ICA_ROOT_CA_CERT_SHA256: fixture.rootPin,
    ICA_ROOT_CA_DID_DOCUMENT_JSON: fixture.rootDidDocumentJson,
    ICA_VC_SIGNING_X5U: 'https://ica.synthetic.example/.well-known/x509.pem',
  };
}

test('required ICA signing trust validates key, chain, Root pin and Root DID', async () => {
  const fixture = createFixture();
  const result = await validateIcaSigningTrustFromEnv(trustedEnvironment(fixture));
  assert.equal(result.validated, true);
  assert.equal(result.chainLength, 2);
  assert.equal(result.rootDid, fixture.rootDid);
  assert.equal(result.rootDidDocumentUrl, 'https://ca.synthetic.example/.well-known/did.json');
});

test('required ICA signing trust rejects a chain whose terminal Root pin differs', async () => {
  const fixture = createFixture();
  await assert.rejects(
    () => validateIcaSigningTrustFromEnv({
      ...trustedEnvironment(fixture),
      ICA_ROOT_CA_CERT_SHA256: '00'.repeat(32),
    }),
    /does not terminate in ICA_ROOT_CA_CERT_SHA256/,
  );
});

test('required ICA signing trust rejects a Root DID document with another id', async () => {
  const fixture = createFixture();
  const document = JSON.parse(fixture.rootDidDocumentJson) as Record<string, unknown>;
  document.id = 'did:web:other.synthetic.example';
  await assert.rejects(
    () => validateIcaSigningTrustFromEnv({
      ...trustedEnvironment(fixture),
      ICA_ROOT_CA_DID_DOCUMENT_JSON: JSON.stringify(document),
    }),
    /id must equal ICA_ROOT_CA_DID/,
  );
});

test('legacy profile remains disabled when no chain is configured', async () => {
  const result = await validateIcaSigningTrustFromEnv({
    ICA_VC_SIGNING_TRUST_REQUIRED: 'false',
  });
  assert.deepEqual(result, {
    required: false,
    validated: false,
    chainLength: 0,
  });
});

test('offline-issued chain is reused by active DID, JWKS source and x5u publication', async () => {
  const fixture = createFixture();
  const names = [
    'ICA_VC_SIGNING_PRIVATE_KEY_PEM',
    'ICA_VC_SIGNING_CERTIFICATE_CHAIN_PEM',
    'ICA_VC_SIGNING_ALG',
    'ICA_VC_SIGNING_KEY_ID',
    'ICA_VC_SIGNING_X5U',
    'ICA_DIDCOMM_ISSUER_DID',
  ] as const;
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = fixture.privateKeyPem;
  process.env.ICA_VC_SIGNING_CERTIFICATE_CHAIN_PEM = fixture.chainPem;
  process.env.ICA_VC_SIGNING_ALG = 'ES384';
  delete process.env.ICA_VC_SIGNING_KEY_ID;
  process.env.ICA_VC_SIGNING_X5U = 'https://ica.synthetic.example/.well-known/x509.pem';
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.synthetic.example';
  resetActiveSigningKeysStateForTests();

  try {
    await bootstrapSelfSigningKey();
    const active = getPreferredSigningKey(undefined);
    assert.equal(active?.x5c?.length, 2);
    assert.equal(active?.x5u, process.env.ICA_VC_SIGNING_X5U);
    const did = buildIcaDidDocument();
    const methods = did.verificationMethod as Array<Record<string, unknown>>;
    const signingJwk = methods.find((method) => String(method.controller) === did.id)?.publicKeyJwk as Record<string, unknown>;
    assert.equal((signingJwk.x5c as string[]).length, 2);
    assert.equal(signingJwk.x5u, process.env.ICA_VC_SIGNING_X5U);
    assert.match(loadPublishedX509Pem() || '', /BEGIN CERTIFICATE/);
  } finally {
    resetActiveSigningKeysStateForTests();
    names.forEach((name) => {
      const value = previous[name];
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    });
  }
});
