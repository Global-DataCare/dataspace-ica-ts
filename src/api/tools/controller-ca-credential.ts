import {
  createPrivateKey,
  createPublicKey,
  X509Certificate,
} from 'node:crypto';
import type { ActivateSigningKeyInput, ActivateSigningKeySubmission, SupportedSigningAlgorithm } from '../types.ts';
import { deriveControllerEmailHashFromEmail, resolveConfiguredControllerEmailHash } from './controller-identity.ts';

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function normalizeHexLikeFingerprint(raw: string): string {
  return raw.trim().toUpperCase().replace(/[^0-9A-F]/g, '');
}

function parseCsvList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function asPemFromX5c(base64Der: string): string {
  const normalized = base64Der.trim();
  if (!normalized) {
    throw new Error('x5c entry cannot be empty.');
  }
  const wrapped = normalized.match(/.{1,64}/g)?.join('\n') || normalized;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
}

function splitPemCertificates(pemText: string): string[] {
  const output: string[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(pemText)) !== null) {
    const certificatePem = match[0].trim();
    if (certificatePem) output.push(certificatePem);
  }
  return output;
}

function normalizedCertificateChain(input: ActivateSigningKeyInput): string[] {
  const pemFromX5c = (input.x5c || [])
    .map((entry) => asPemFromX5c(entry));
  const pemFromChain = (input.certificateChainPem || [])
    .flatMap((entry) => splitPemCertificates(entry));
  const chain = [...pemFromX5c, ...pemFromChain];
  const unique = Array.from(new Set(chain.map((entry) => entry.trim()).filter(Boolean)));
  return unique;
}

function extractEmailsFromCertificate(cert: X509Certificate): string[] {
  const output = new Set<string>();
  const subject = cert.subject || '';
  const subjectEmailMatches = subject.matchAll(/(?:^|\n)\s*(?:emailAddress|E)\s*=\s*([^\n]+)/gim);
  for (const match of subjectEmailMatches) {
    const value = (match[1] || '').trim().toLowerCase();
    if (value) output.add(value);
  }

  const san = cert.subjectAltName || '';
  const sanMatches = san.matchAll(/email:([^,\n]+)/gim);
  for (const match of sanMatches) {
    const value = (match[1] || '').trim().toLowerCase();
    if (value) output.add(value);
  }

  return Array.from(output);
}

function assertCertificateValidityNow(cert: X509Certificate, indexLabel: string): void {
  const now = Date.now();
  const notBefore = Date.parse(cert.validFrom);
  const notAfter = Date.parse(cert.validTo);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
    throw new Error(`Invalid certificate validity range at ${indexLabel}.`);
  }
  if (now < notBefore) {
    throw new Error(`Certificate at ${indexLabel} is not valid yet (validFrom=${cert.validFrom}).`);
  }
  if (now > notAfter) {
    throw new Error(`Certificate at ${indexLabel} is expired (validTo=${cert.validTo}).`);
  }
}

function assertAlgorithmMatchesCertificatePublicKey(
  alg: SupportedSigningAlgorithm,
  cert: X509Certificate,
  indexLabel: string,
): void {
  const publicJwk = cert.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  const kty = String(publicJwk.kty || '');
  const crv = String(publicJwk.crv || '');

  if (alg === 'ES384' && (kty !== 'EC' || crv !== 'P-384')) {
    throw new Error(`Activation key at ${indexLabel} requires x509 leaf with EC P-384 public key for alg=ES384.`);
  }
  if (alg === 'ES256K' && (kty !== 'EC' || crv !== 'secp256k1')) {
    throw new Error(`Activation key at ${indexLabel} requires x509 leaf with EC secp256k1 public key for alg=ES256K.`);
  }
  if ((alg === 'RS256' || alg === 'PS256') && kty !== 'RSA') {
    throw new Error(`Activation key at ${indexLabel} requires x509 leaf with RSA public key for alg=${alg}.`);
  }
  if (alg === 'EdDSA' && (kty !== 'OKP' || (crv !== 'Ed25519' && crv !== 'Ed448'))) {
    throw new Error(`Activation key at ${indexLabel} requires x509 leaf with Ed25519/Ed448 public key for alg=EdDSA.`);
  }
}

function assertPrivateKeyMatchesLeafCertificate(
  privateKeyPem: string,
  leaf: X509Certificate,
  indexLabel: string,
): void {
  const privateKey = createPrivateKey(privateKeyPem);
  if (!leaf.checkPrivateKey(privateKey)) {
    throw new Error(`Activation key at ${indexLabel} does not match x509 leaf certificate public key.`);
  }

  const keySpkiPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  const certSpkiPem = leaf.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  if (keySpkiPem !== certSpkiPem) {
    throw new Error(`Activation key at ${indexLabel} does not match x509 leaf certificate (SPKI mismatch).`);
  }
}

function assertCertificateChainIntegrity(chain: X509Certificate[], indexLabel: string): void {
  for (let i = 0; i < chain.length - 1; i += 1) {
    const child = chain[i];
    const issuer = chain[i + 1];
    if (!child.checkIssued(issuer)) {
      throw new Error(`x509 chain at ${indexLabel} is not properly ordered at position ${i} -> ${i + 1}.`);
    }
    if (!child.verify(issuer.publicKey)) {
      throw new Error(`x509 chain signature invalid at ${indexLabel}, position ${i}.`);
    }
  }
}

function assertTrustAnchorPins(chain: X509Certificate[], indexLabel: string): void {
  const requiredPins = parseCsvList(process.env.ICA_CONTROLLER_CA_TRUST_ANCHOR_PINS_SHA256)
    .map((entry) => normalizeHexLikeFingerprint(entry))
    .filter(Boolean);
  if (!requiredPins.length) return;

  const certPins = new Set(
    chain.map((cert) => normalizeHexLikeFingerprint(cert.fingerprint256 || '')),
  );
  const anyMatch = requiredPins.some((pin) => certPins.has(pin));
  if (!anyMatch) {
    throw new Error(`x509 chain at ${indexLabel} does not include a trusted anchor pin from ICA_CONTROLLER_CA_TRUST_ANCHOR_PINS_SHA256.`);
  }
}

function assertAllowedIssuerFilter(chain: X509Certificate[], indexLabel: string): void {
  const filters = parseCsvList(process.env.ICA_CONTROLLER_CA_ALLOWED_ISSUER_SUBSTRINGS)
    .map((entry) => entry.toLowerCase());
  if (!filters.length) return;

  const issuerTexts = chain.map((cert) => (cert.issuer || '').toLowerCase());
  const matched = filters.some((filter) => issuerTexts.some((issuer) => issuer.includes(filter)));
  if (!matched) {
    throw new Error(
      `x509 chain at ${indexLabel} does not match ICA_CONTROLLER_CA_ALLOWED_ISSUER_SUBSTRINGS.`,
    );
  }
}

function assertControllerIdentityWhenConfigured(leaf: X509Certificate, indexLabel: string): void {
  const configuredEmail = (process.env.ICA_SELF_CONTROLLER_EMAIL || '').trim().toLowerCase();
  const configuredIdHash = resolveConfiguredControllerEmailHash();
  if (!configuredEmail && !configuredIdHash) return;
  const emails = extractEmailsFromCertificate(leaf);

  if (configuredEmail && !emails.includes(configuredEmail)) {
    throw new Error(
      `x509 leaf at ${indexLabel} does not include ICA_SELF_CONTROLLER_EMAIL="${configuredEmail}".`,
    );
  }

  if (configuredIdHash) {
    if (!emails.length) {
      throw new Error(
        `x509 leaf at ${indexLabel} has no email SAN/subject values to verify ICA_SELF_CONTROLLER_EMAIL_HASH.`,
      );
    }
    const matchedByHash = emails.some((email) => {
      try {
        return deriveControllerEmailHashFromEmail(email) === configuredIdHash;
      } catch {
        return false;
      }
    });
    if (!matchedByHash) {
      throw new Error(
        `x509 leaf at ${indexLabel} email hashes do not match ICA_SELF_CONTROLLER_EMAIL_HASH.`,
      );
    }
  }
}

function isControllerCaValidationEnabled(): boolean {
  const disable = parseBoolean(process.env.DISABLE_CONTROLLER_CA_CREDENTIAL_VALIDATION, false);
  return !disable;
}

export function validateActivateControllerCaCredential(submission: ActivateSigningKeySubmission): void {
  if (!isControllerCaValidationEnabled()) return;

  submission.keys.forEach((keyInput, index) => {
    const indexLabel = `body.data[${index}]`;
    const chainPem = normalizedCertificateChain(keyInput);
    if (!chainPem.length) {
      throw new Error(
        `Activation key at ${indexLabel} requires CA credential chain (x5c or certificateChainPem).`,
      );
    }

    const certificates = chainPem.map((pem, certIndex) => {
      try {
        return new X509Certificate(pem);
      } catch (error: unknown) {
        throw new Error(
          `Invalid x509 certificate at ${indexLabel}, chain position ${certIndex}: ${(error as Error).message}`,
        );
      }
    });

    const leaf = certificates[0];
    assertCertificateValidityNow(leaf, `${indexLabel}.x5c[0]`);
    assertPrivateKeyMatchesLeafCertificate(keyInput.privateKeyPem, leaf, indexLabel);
    assertAlgorithmMatchesCertificatePublicKey(keyInput.alg, leaf, indexLabel);
    assertControllerIdentityWhenConfigured(leaf, indexLabel);
    assertCertificateChainIntegrity(certificates, indexLabel);
    assertTrustAnchorPins(certificates, indexLabel);
    assertAllowedIssuerFilter(certificates, indexLabel);
  });
}
