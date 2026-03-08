import { spawnSync } from 'node:child_process';
import { createSign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deriveDeterministicEcPrivateKeyPem } from '../tools/deterministic-key-material.ts';
import { computeControllerAuthorizationPayloadBase64Url } from '../tools/controller-authorization-payload.ts';
import type { ActivateSigningKeyInput } from '../types.ts';

const tenantId = process.env.ICA_LOCAL_TENANT_ID || 'ica';
const jurisdiction = process.env.ICA_EXAMPLE_JURISDICTION || 'ES';
const sector = process.env.ICA_EXAMPLE_SECTOR || 'animal-care';
const baseUrl = process.env.ICA_EXAMPLE_BASE_URL || 'http://localhost:3310';
const thid = process.env.ICA_EXAMPLE_THID || 'activate-deterministic-001';

const es384 = deriveDeterministicEcPrivateKeyPem('ica-seed-es384', 'P-384');
const es256k = deriveDeterministicEcPrivateKeyPem('ica-seed-es256k', 'secp256k1');

const activatePath = `/${tenantId}/cds-${jurisdiction}/v1/${sector}/entity/keys/credentials/_activate`;
const activateResponsePath = `/${tenantId}/cds-${jurisdiction}/v1/${sector}/entity/keys/credentials/_activate-response`;
const controllerKid = es384.kidRfc7638;
const controllerEmail = (process.env.ICA_SELF_CONTROLLER_EMAIL || 'it-director@example.org').trim();

function base64UrlEncodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function buildControllerProofJws(unsignedBody: Record<string, unknown>): string {
  const protectedHeader = {
    alg: 'ES384',
    kid: controllerKid,
  };
  const protectedEncoded = base64UrlEncodeJson(protectedHeader);
  const payloadEncoded = computeControllerAuthorizationPayloadBase64Url(unsignedBody);
  const signingInput = `${protectedEncoded}.${payloadEncoded}`;
  const signer = createSign('sha384');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign({
    key: es384.privateKeyPem,
    dsaEncoding: 'ieee-p1363',
  });
  return `${protectedEncoded}..${signature.toString('base64url')}`;
}

function pemToX5c(pem: string): string {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '')
    .trim();
}

function createSelfSignedCertificatePem(privateKeyPem: string, commonName: string, email: string): string {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'ica-activate-example-'));
  const keyPath = path.join(tempDir, 'key.pem');
  const certPath = path.join(tempDir, 'cert.pem');
  try {
    writeFileSync(keyPath, privateKeyPem, 'utf8');
    const subject = `/C=ES/O=ICA/CN=${commonName}/emailAddress=${email}`;
    const result = spawnSync(
      'openssl',
      ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '3650', '-subj', subject],
      { encoding: 'utf8' },
    );
    if (result.status !== 0) {
      throw new Error((result.stderr || result.stdout || 'unknown openssl error').trim());
    }
    return readFileSync(certPath, 'utf8');
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

const es384CertPem = createSelfSignedCertificatePem(es384.privateKeyPem, 'Controller-ES384', controllerEmail);
const es256kCertPem = createSelfSignedCertificatePem(es256k.privateKeyPem, 'Controller-ES256K', controllerEmail);

const activateKeys: ActivateSigningKeyInput[] = [
  {
    kid: es384.kidRfc7638,
    alg: 'ES384',
    privateKeyPem: es384.privateKeyPem,
    x5c: [pemToX5c(es384CertPem)],
  },
  {
    kid: es256k.kidRfc7638,
    alg: 'ES256K',
    privateKeyPem: es256k.privateKeyPem,
    x5c: [pemToX5c(es256kCertPem)],
  },
];

const unsignedBody = {
  data: activateKeys.map((key) => ({ key })),
};

const payload = {
  jti: `msg-${thid}`,
  thid,
  type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
  body: {
    ...unsignedBody,
    signature: {
      sigFormat: 'application/jose',
      who: { reference: `did:web:localhost%3A3310#${controllerKid}` },
      data: buildControllerProofJws(unsignedBody),
    },
  },
};

const output = {
  note: 'TEST ONLY. Never use these deterministic keys/certs in production.',
  endpoint: `${baseUrl}${activatePath}`,
  pollEndpoint: `${baseUrl}${activateResponsePath}?thid=${encodeURIComponent(thid)}`,
  kids: {
    controller: controllerKid,
    es384: es384.kidRfc7638,
    es256k: es256k.kidRfc7638,
  },
  didcommPayload: payload,
  curl: {
    activate: `curl -i -X POST "${baseUrl}${activatePath}" -H "Content-Type: application/didcomm-plain+json" --data @/tmp/activate-payload.json`,
    poll: `curl -sS -X POST "${baseUrl}${activateResponsePath}?thid=${encodeURIComponent(thid)}" | jq .`,
  },
};

process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
