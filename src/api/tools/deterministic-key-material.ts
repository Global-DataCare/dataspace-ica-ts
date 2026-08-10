import {
  deriveDeterministicEcPemKeyPair,
  type DeterministicEcPemKeyMaterial,
  type DeterministicSeedEcCurve,
} from 'gdc-common-utils-ts/utils/deterministic-seed-key';

export type DeterministicEcCurve = DeterministicSeedEcCurve;

export type DeterministicEcKeyMaterial = DeterministicEcPemKeyMaterial;

export function deriveDeterministicEcPrivateKeyPem(
  seed: string,
  curve: DeterministicEcCurve,
): DeterministicEcKeyMaterial {
  return deriveDeterministicEcPemKeyPair(seed, curve);
}
