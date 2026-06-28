import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

type JsonObject = Record<string, unknown>;

/**
 * Optional bridge from gwtemplate-generated trust artifacts into the ICA runtime.
 */
function resolvePublicArtifactsDir(): string {
  return String(process.env.ICA_PUBLIC_ARTIFACTS_DIR || '').trim();
}

/**
 * Supports either exact filenames or the generated `did-<domain>.json` / `jwks-<domain>.json` pattern.
 */
function findArtifactFile(explicitPath: string | undefined, baseDir: string, candidates: string[]): string | null {
  const configured = String(explicitPath || '').trim();
  if (configured) {
    const absolute = path.isAbsolute(configured) ? configured : path.resolve(configured);
    return existsSync(absolute) ? absolute : null;
  }

  for (const candidate of candidates) {
    const candidatePath = path.join(baseDir, candidate);
    if (existsSync(candidatePath)) return candidatePath;
  }

  for (const entry of readdirSync(baseDir)) {
    if (candidates.some((candidate) => candidate.includes('*') && matchWildcard(entry, candidate))) {
      return path.join(baseDir, entry);
    }
  }

  return null;
}

function matchWildcard(value: string, pattern: string): boolean {
  if (!pattern.includes('*')) return value === pattern;
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(value);
}

/**
 * Returns a cloned object so callers can safely enrich the published document in memory.
 */
function loadJsonArtifact(filePath: string | null): JsonObject | null {
  if (!filePath) return null;
  const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  return structuredClone(parsed as JsonObject);
}

/**
 * Loads the published ICA DID document, if the runtime was configured to serve generated artifacts.
 */
export function loadPublishedDidDocument(): JsonObject | null {
  const baseDir = resolvePublicArtifactsDir();
  if (!baseDir || !existsSync(baseDir)) return null;
  return loadJsonArtifact(findArtifactFile(process.env.ICA_PUBLIC_DID_DOCUMENT_FILE, baseDir, [
    'did.json',
    'did-*.json',
  ]));
}

/**
 * Loads the published ICA JWKS, preserving the embedded `x5c` chain generated upstream.
 */
export function loadPublishedJwks(): JsonObject | null {
  const baseDir = resolvePublicArtifactsDir();
  if (!baseDir || !existsSync(baseDir)) return null;
  return loadJsonArtifact(findArtifactFile(process.env.ICA_PUBLIC_JWKS_FILE, baseDir, [
    'jwks.json',
    'jwks-*.json',
  ]));
}

/**
 * Loads the concatenated DER chain served at `/.well-known/x509.der`.
 */
export function loadPublishedX509Der(): Buffer | null {
  const baseDir = resolvePublicArtifactsDir();
  if (!baseDir || !existsSync(baseDir)) return null;
  const filePath = findArtifactFile(process.env.ICA_PUBLIC_X509_DER_FILE, baseDir, [
    'x509.der',
    'x509-chain.der',
  ]);
  if (!filePath) return null;
  return readFileSync(filePath);
}
