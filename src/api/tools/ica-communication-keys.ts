import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { CryptographyService } from 'gdc-common-utils-ts/CryptographyService';
import type { ICryptoHelper } from 'gdc-common-utils-ts/interfaces/ICryptoHelper';
import {
  initializeCommunicationIdentity,
  type CommunicationIdentityBootstrapResult,
} from 'gdc-common-utils-ts/utils/communication-identity';

type BootstrapResult = {
  enabled: boolean;
  source?: 'configured-public-jwks' | 'communication-seed' | 'vc-seed';
  signingKid?: string;
  encryptionKid?: string;
};

let communicationIdentity: CommunicationIdentityBootstrapResult | null = null;

const cryptoHelper: ICryptoHelper = {
  async getRandomBytes(byteCount: number): Promise<Uint8Array> {
    return randomBytes(byteCount);
  },
  async digestString(data: string, algorithm: string): Promise<string> {
    const normalized = algorithm.replace(/-/g, '').toLowerCase();
    return createHash(normalized).update(data).digest('hex');
  },
  randomUUID(): string {
    return randomUUID();
  },
};

/**
 * Derives the ICA transport identity once at startup. Communication signing
 * and encryption keys use independent domain-separated derivations inside the
 * shared GDC helper; the private bytes stay only in the runtime identity.
 */
export async function bootstrapIcaCommunicationKeys(): Promise<BootstrapResult> {
  if ((process.env.ICA_COMMUNICATION_JWKS_JSON || '').trim()) {
    return { enabled: true, source: 'configured-public-jwks' };
  }
  const dedicatedSeed = (process.env.ICA_COMMUNICATION_KEY_SEED_PASSPHRASE || '').trim();
  const vcSeed = (process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE || '').trim();
  const seedMaterial = dedicatedSeed || vcSeed;
  if (!seedMaterial) return { enabled: false };

  communicationIdentity = await initializeCommunicationIdentity({
    entityId: 'ica-communication-runtime',
    seedMaterial,
    mode: 'deterministic',
    cryptography: new CryptographyService(cryptoHelper),
    communicationSigningAlg: 'ML-DSA-44',
    encryptionCurve: 'ML-KEM-768',
  });
  const signingJwk = {
    ...communicationIdentity.commSigningKeyPair.publicJWKey,
    purposes: ['didcomm-sign'],
  };
  const encryptionJwk = {
    ...communicationIdentity.commEncryptionKeyPair.publicJWKey,
    alg: 'ML-KEM-768',
    purposes: ['didcomm-enc'],
  };
  process.env.ICA_COMMUNICATION_JWKS_JSON = JSON.stringify({ keys: [signingJwk, encryptionJwk] });
  return {
    enabled: true,
    source: dedicatedSeed ? 'communication-seed' : 'vc-seed',
    signingKid: signingJwk.kid,
    encryptionKid: encryptionJwk.kid,
  };
}

export function getIcaCommunicationIdentity(): CommunicationIdentityBootstrapResult | null {
  return communicationIdentity;
}

export function resetIcaCommunicationKeysForTests(): void {
  communicationIdentity = null;
}
