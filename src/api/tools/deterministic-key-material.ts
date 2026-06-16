import { createECDH, createHash, createPrivateKey } from 'node:crypto';
import { computeRfc7638JwkThumbprint } from 'gdc-common-utils-ts/utils/jwk-thumbprint';

export type DeterministicEcCurve = 'P-384' | 'secp256k1';

export type DeterministicEcKeyMaterial = {
  privateKeyPem: string;
  publicJwk: {
    kty: 'EC';
    crv: DeterministicEcCurve;
    x: string;
    y: string;
  };
  kidRfc7638: string;
};

export function deriveDeterministicEcPrivateKeyPem(
  seed: string,
  curve: DeterministicEcCurve,
): DeterministicEcKeyMaterial {
  const curveName = curve === 'P-384' ? 'secp384r1' : 'secp256k1';
  const keyLength = curve === 'P-384' ? 48 : 32;
  for (let counter = 0; counter < 256; counter += 1) {
    const material = createHash('sha512').update(`${seed}:${curve}:${counter}`).digest();
    const candidate = material.subarray(0, keyLength);
    try {
      const ecdh = createECDH(curveName);
      ecdh.setPrivateKey(candidate);
      const privateBytes = ecdh.getPrivateKey();
      const publicBytes = ecdh.getPublicKey(undefined, 'uncompressed');
      const x = publicBytes.subarray(1, 1 + keyLength).toString('base64url');
      const y = publicBytes.subarray(1 + keyLength, 1 + (2 * keyLength)).toString('base64url');
      const d = privateBytes.toString('base64url');

      const privateKey = createPrivateKey({
        key: {
          kty: 'EC',
          crv: curve,
          x,
          y,
          d,
        },
        format: 'jwk',
      });
      const publicJwk = {
        kty: 'EC' as const,
        crv: curve,
        x,
        y,
      };
      return {
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        publicJwk,
        kidRfc7638: computeRfc7638JwkThumbprint(publicJwk),
      };
    } catch {
      // Retry with next candidate until a valid scalar is produced for the curve.
    }
  }
  throw new Error(`Unable to derive deterministic ${curve} key from seed.`);
}
