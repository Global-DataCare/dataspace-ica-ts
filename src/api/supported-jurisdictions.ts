export const DEFAULT_ICA_SUPPORTED_JURISDICTIONS = ['ES'] as const;

function parseCsvList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim().toUpperCase())
    .filter(Boolean);
}

function dedupe(values: string[]): string[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}

export function getConfiguredSupportedJurisdictionIds(
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const configured = dedupe(parseCsvList(env.ICA_SUPPORTED_JURISDICTIONS));
  if (configured.length) {
    return configured;
  }
  return [...DEFAULT_ICA_SUPPORTED_JURISDICTIONS];
}

export function isSupportedJurisdiction(
  rawJurisdiction: string,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const normalized = rawJurisdiction.trim().toUpperCase();
  if (!normalized) return false;
  return getConfiguredSupportedJurisdictionIds(env).includes(normalized);
}

export function getSupportedJurisdictionErrorMessage(
  env: NodeJS.ProcessEnv = process.env,
): string {
  return `jurisdiction must be one of: ${getConfiguredSupportedJurisdictionIds(env).join(', ')}.`;
}
