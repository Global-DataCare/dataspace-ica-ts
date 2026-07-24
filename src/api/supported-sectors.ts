import type { AllowedSector } from './types.ts';

export const DEFAULT_ICA_SUPPORTED_SECTORS_LANGUAGE = 'es-ES';

export const DEFAULT_ICA_SUPPORTED_SECTORS = [
  'animal-care',
  'animal-tech',
  'animal-research',
  'animal-insurance',
  'health-care',
  'health-tech',
  'health-research',
  'health-insurance',
] as const satisfies readonly AllowedSector[];

const DEFAULT_SECTOR_LABELS: Record<string, string> = {
  'animal-care': 'Salud animal',
  'animal-tech': 'Tecnología para salud animal',
  'animal-research': 'Investigación en salud animal',
  'animal-insurance': 'Seguros de salud animal',
  'health-care': 'Salud humana',
  'health-tech': 'Tecnología para salud humana',
  'health-research': 'Investigación en salud humana',
  'health-insurance': 'Seguros de salud humana',
  'onehealth-care': 'Salud del entorno (One Health)',
  'onehealth-research': 'Investigación en salud (One Health)',
  'onehealth-insurance': 'Seguros de salud y entorno (One Health)',
};

export type SupportedSectorCoding = {
  code: AllowedSector;
  display: string;
};

export const ICA_SUPPORTED_SECTORS_WILDCARD = '*';

function parseCsvList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
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

function buildSectorDisplay(sectorId: string): string {
  const knownLabel = DEFAULT_SECTOR_LABELS[sectorId];
  if (knownLabel) return knownLabel;
  return sectorId
    .split('-')
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(' ');
}

export function getConfiguredSupportedSectorIds(
  env: NodeJS.ProcessEnv = process.env,
): AllowedSector[] {
  const configured = dedupe(parseCsvList(env.ICA_SUPPORTED_SECTORS));
  if (configured.length) {
    return configured as AllowedSector[];
  }
  return [...DEFAULT_ICA_SUPPORTED_SECTORS];
}

export function hasWildcardSupportedSector(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return getConfiguredSupportedSectorIds(env).includes(ICA_SUPPORTED_SECTORS_WILDCARD);
}

export function getSupportedSectorsLanguage(): string {
  return DEFAULT_ICA_SUPPORTED_SECTORS_LANGUAGE;
}

export function getSupportedSectorCodings(
  env: NodeJS.ProcessEnv = process.env,
): SupportedSectorCoding[] {
  return getConfiguredSupportedSectorIds(env).map((code) => ({
    code,
    display: buildSectorDisplay(code),
  }));
}

export function isSupportedSector(
  rawSector: string,
  env: NodeJS.ProcessEnv = process.env,
): rawSector is AllowedSector {
  const normalized = rawSector.trim().toLowerCase();
  if (!normalized) return false;
  if (hasWildcardSupportedSector(env)) return true;
  return getConfiguredSupportedSectorIds(env).includes(normalized as AllowedSector);
}

export function getSupportedSectorErrorMessage(
  env: NodeJS.ProcessEnv = process.env,
): string {
  if (hasWildcardSupportedSector(env)) {
    return 'sector must be a non-empty string.';
  }
  return `sector must be one of: ${getConfiguredSupportedSectorIds(env).join(', ')}.`;
}
