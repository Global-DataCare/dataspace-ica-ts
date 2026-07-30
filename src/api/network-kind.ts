export const ICA_NETWORK_KINDS = [
  'test',
  'local-network',
  'test-network',
  'network',
] as const;

export type IcaNetworkKind = typeof ICA_NETWORK_KINDS[number];
export type IcaNetworkKindPathSegment = IcaNetworkKind | 'terms';

/**
 * Resolves the canonical cryptographic and registration context carried by an
 * ICA PDF route. `terms` is retained only as the backwards-compatible alias
 * for the no-Fabric `test` context.
 */
export function parseIcaNetworkKind(value: string): IcaNetworkKind | undefined {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'terms') return 'test';
  return ICA_NETWORK_KINDS.includes(normalized as IcaNetworkKind)
    ? normalized as IcaNetworkKind
    : undefined;
}

/**
 * Reports whether a route context requires credential anchoring in Fabric.
 * This decision is independent from the validation of signatures in the PDF.
 */
export function isFabricNetworkKind(value: IcaNetworkKind): boolean {
  return value !== 'test';
}
