import { createHash, X509Certificate } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { inflateSync } from 'node:zlib';
import type {
  AllowedSector,
  PdfVerificationService,
  RevocationDebugCheck,
  RevocationDebugInfo,
  RevocationStatus,
  VerificationErrorDetails,
  VerifyResult,
  VerifyRouteContext,
  VerifySubmission,
} from './types.ts';

const execFileAsync = promisify(execFile);
const DEFAULT_FNMT_ROOT_CERT_URL = 'https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_Raiz_FNMT-RCM_SHA256.cer';
const DEFAULT_FNMT_INTERMEDIATE_CERT_URLS = [
  'https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_Representacion.cer',
  'https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_Sector_Publico.cer',
  'https://www.sede.fnmt.gob.es/documents/10445900/10526749/AC_FNMT_Usuarios.cer',
];

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function parseUnifiedTestTermsPrefixFlag(): boolean | undefined {
  if (process.env.ICA_ENABLE_TEST_TERMS_PREFIX === undefined) return undefined;
  return parseBoolean(process.env.ICA_ENABLE_TEST_TERMS_PREFIX, false);
}

function parsePositiveInteger(value: string | undefined, fallback: number, minimum = 1): number {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value.trim(), 10);
  if (!Number.isFinite(parsed) || parsed < minimum) return fallback;
  return parsed;
}

function parseDigestAlgorithm(value: string | undefined, fallback: string): string {
  const normalized = (value || fallback).trim().toLowerCase();
  if (!normalized) return fallback;
  try {
    createHash(normalized).update('').digest();
  } catch {
    throw new Error(
      `Unsupported ICA_VERIFY_DIGEST_ALGORITHM="${normalized}". Check Node/OpenSSL supported digest names.`,
    );
  }
  return normalized;
}

type TemplateMatchMode = 'strict-bytes' | 'logical-content';

function parseTemplateMatchMode(value: string | undefined, fallback: TemplateMatchMode): TemplateMatchMode {
  const normalized = (value || fallback).trim().toLowerCase();
  if (normalized === 'strict-bytes' || normalized === 'logical-content') {
    return normalized;
  }
  throw new Error(
    `Unsupported ICA_VERIFY_TEMPLATE_MATCH_MODE="${normalized}". Use "strict-bytes" or "logical-content".`,
  );
}

function parseOptionalString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function parseCsvList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseAllowedSectorsList(value: string | undefined, fallback: AllowedSector[]): AllowedSector[] {
  const source = parseCsvList(value);
  if (!source.length) return fallback;
  const allowed = new Set<AllowedSector>(['animal-care', 'health-care']);
  return source
    .map((entry) => entry.toLowerCase() as AllowedSector)
    .filter((entry) => allowed.has(entry));
}

function validateTemplateUrlPattern(pattern: string): void {
  const normalized = pattern.trim();
  if (!normalized) {
    throw new Error('ICA_TERMS_TEMPLATE_URL_PATTERN cannot be empty.');
  }
  if (normalized.includes('raw.githubusercontent.com') && normalized.includes('/tree/')) {
    throw new Error(
      'ICA_TERMS_TEMPLATE_URL_PATTERN is invalid for raw GitHub URLs (contains /tree/). Use /main/... or /refs/heads/main/... instead.',
    );
  }
}

function normalizePem(rawPem: string): string {
  const withNewlines = rawPem.includes('\\n') ? rawPem.replace(/\\n/g, '\n') : rawPem;
  return `${withNewlines.trim()}\n`;
}

function parseFingerprintPin(value: string | undefined, expectedHexLength: number, label: string): string | undefined {
  const pin = parseOptionalString(value);
  if (!pin) return undefined;
  const normalized = pin.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
  if (normalized.length !== expectedHexLength) {
    throw new Error(`Invalid ${label} pin format: "${pin}"`);
  }
  return normalized;
}

function parseFingerprintPinList(value: string | undefined): string[] {
  if (!value) return [];
  return parseCsvList(value)
    .map((entry) => parseFingerprintPin(entry, 64, 'SHA-256'))
    .filter((entry): entry is string => Boolean(entry));
}

function parseFingerprintPinListSha1(value: string | undefined): string[] {
  if (!value) return [];
  return parseCsvList(value)
    .map((entry) => parseFingerprintPin(entry, 40, 'SHA-1'))
    .filter((entry): entry is string => Boolean(entry));
}

function dedupeStrings(values: string[]): string[] {
  return [...new Set(values)];
}

type OpenSslOutput = { stdout: string; stderr: string };

async function runOpenSsl(args: string[]): Promise<OpenSslOutput> {
  const { stdout, stderr } = await execFileAsync('openssl', args, {
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024,
  });
  return { stdout, stderr };
}

async function runOpenSslSafe(args: string[]): Promise<{ ok: true; value: OpenSslOutput } | { ok: false; error: Error }> {
  try {
    return { ok: true, value: await runOpenSsl(args) };
  } catch (error: unknown) {
    return { ok: false, error: error as Error };
  }
}

function hashHex(input: Buffer, algorithm: string): string {
  return createHash(algorithm).update(input).digest('hex');
}

type ParsedPdfObject = {
  dict: string;
  streamRaw: Buffer<ArrayBufferLike> | null;
};

type PdfLogicalFingerprint = {
  hash: string;
  pageCount: number;
  pageContentCount: number;
};

function parsePdfObjects(pdfBytes: Buffer): Map<number, ParsedPdfObject> {
  const objects = new Map<number, ParsedPdfObject>();
  const text = pdfBytes.toString('latin1');
  const objectRegex = /^(\d+)\s+(\d+)\s+obj\s*([\s\S]*?)\s*endobj\s*$/gm;
  let match: RegExpExecArray | null;
  while (true) {
    match = objectRegex.exec(text);
    if (!match) break;
    const objectId = Number.parseInt(match[1], 10);
    const body = match[3];
    const streamLfIndex = body.indexOf('stream\n');
    const streamCrlfIndex = body.indexOf('stream\r\n');
    let streamIndex = -1;
    let separatorLength = 0;
    if (streamCrlfIndex !== -1 && (streamLfIndex === -1 || streamCrlfIndex < streamLfIndex)) {
      streamIndex = streamCrlfIndex;
      separatorLength = 'stream\r\n'.length;
    } else if (streamLfIndex !== -1) {
      streamIndex = streamLfIndex;
      separatorLength = 'stream\n'.length;
    }

    if (streamIndex !== -1) {
      const endStreamIndex = body.lastIndexOf('endstream');
      if (endStreamIndex !== -1 && endStreamIndex > streamIndex) {
        objects.set(objectId, {
          dict: body.slice(0, streamIndex).trim(),
          streamRaw: Buffer.from(body.slice(streamIndex + separatorLength, endStreamIndex), 'latin1'),
        });
        continue;
      }
    }

    objects.set(objectId, {
      dict: body.trim(),
      streamRaw: null,
    });
  }
  return objects;
}

function extractReferencedObjectIds(raw: string): number[] {
  const ids: number[] = [];
  for (const match of raw.matchAll(/(\d+)\s+0\s+R/g)) {
    ids.push(Number.parseInt(match[1], 10));
  }
  return ids;
}

function decodePdfStream(parsedObject: ParsedPdfObject | undefined): Buffer<ArrayBufferLike> | null {
  if (!parsedObject?.streamRaw) return null;
  const usesFlate = /\/Filter\b[\s\S]*?\/FlateDecode\b/.test(parsedObject.dict);
  if (!usesFlate) return parsedObject.streamRaw;
  try {
    return Buffer.from(parsedObject.streamRaw);
  } catch {
    return null;
  }
}

function inflateIfNeeded(parsedObject: ParsedPdfObject | undefined): Buffer<ArrayBufferLike> | null {
  const stream = decodePdfStream(parsedObject);
  if (!stream || !parsedObject) return stream;
  const usesFlate = /\/Filter\b[\s\S]*?\/FlateDecode\b/.test(parsedObject.dict);
  if (!usesFlate) return stream;
  try {
    return Buffer.from(inflateSync(stream));
  } catch {
    return null;
  }
}

export function computePdfLogicalFingerprint(pdfBytes: Buffer): PdfLogicalFingerprint | null {
  const objects = parsePdfObjects(pdfBytes);
  if (!objects.size) return null;

  const pageContentHashes: string[] = [];
  let pageCount = 0;

  for (const parsedObject of objects.values()) {
    if (!/\/Type\s*\/Page\b/.test(parsedObject.dict) || /\/Type\s*\/Pages\b/.test(parsedObject.dict)) {
      continue;
    }
    pageCount += 1;

    const arrayContents = parsedObject.dict.match(/\/Contents\s*\[(.*?)\]/s);
    const singleContent = parsedObject.dict.match(/\/Contents\s+(\d+)\s+0\s+R/);
    const contentObjectIds = arrayContents
      ? extractReferencedObjectIds(arrayContents[1])
      : singleContent
        ? [Number.parseInt(singleContent[1], 10)]
        : [];

    const normalizedParts: string[] = [];
    for (const contentObjectId of contentObjectIds) {
      const inflated = inflateIfNeeded(objects.get(contentObjectId));
      if (!inflated) continue;
      const normalized = inflated.toString('latin1').replace(/\s+/g, ' ').trim();
      if (normalized) {
        normalizedParts.push(normalized);
      }
    }

    if (normalizedParts.length) {
      const pageNormalized = normalizedParts.join('\n--CONTENT-STREAM--\n');
      const pageHash = createHash('sha256').update(pageNormalized).digest('hex');
      pageContentHashes.push(pageHash);
    }
  }

  if (!pageCount || !pageContentHashes.length) {
    return null;
  }

  pageContentHashes.sort();
  const joined = `pages=${pageCount};content=${pageContentHashes.length};${pageContentHashes.join(';')}`;
  return {
    hash: createHash('sha256').update(joined).digest('hex'),
    pageCount,
    pageContentCount: pageContentHashes.length,
  };
}

function splitPemCertificates(rawPem: string): string[] {
  const matches = rawPem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (!matches) return [];
  return matches.map((entry) => entry.trim());
}

function extractFirstPemCertificate(rawPem: string): string | undefined {
  const certs = splitPemCertificates(rawPem);
  if (!certs.length) return undefined;
  return `${certs[0]}\n`;
}

function extractSinglePemCertificate(rawPem: string, label: string): string {
  const certs = splitPemCertificates(rawPem);
  if (!certs.length) {
    throw new Error(`No PEM certificate found for ${label}.`);
  }
  if (certs.length > 1) {
    throw new Error(`Expected a single PEM certificate for ${label}, got ${certs.length}.`);
  }
  return `${certs[0]}\n`;
}

function certificateFingerprintHex(certPem: string, algorithm: 'sha256' | 'sha1'): string {
  const cert = new X509Certificate(certPem);
  const value = algorithm === 'sha256' ? cert.fingerprint256 : cert.fingerprint;
  return value.replace(/:/g, '').toLowerCase();
}

function ensurePinnedFingerprint(
  label: string,
  certPem: string,
  expectedPinSha256: string | undefined,
  expectedPinSha1: string | undefined,
  source: string,
): void {
  if (expectedPinSha256) {
    const actual = certificateFingerprintHex(certPem, 'sha256');
    if (actual !== expectedPinSha256) {
      throw new Error(
        `${label} certificate SHA-256 pin mismatch from ${source}. expected=${expectedPinSha256} actual=${actual}`,
      );
    }
  }
  if (expectedPinSha1) {
    const actual = certificateFingerprintHex(certPem, 'sha1');
    if (actual !== expectedPinSha1) {
      throw new Error(
        `${label} certificate SHA-1 pin mismatch from ${source}. expected=${expectedPinSha1} actual=${actual}`,
      );
    }
  }
}

function ensurePinnedFingerprintSet(
  label: string,
  certPems: string[],
  expectedPinsSha256: string[],
  expectedPinsSha1: string[],
  source: string,
): void {
  const pinSetSha256 = new Set(expectedPinsSha256);
  const pinSetSha1 = new Set(expectedPinsSha1);
  if (!pinSetSha256.size && !pinSetSha1.size) return;

  for (const certPem of certPems) {
    if (pinSetSha256.size) {
      const actual = certificateFingerprintHex(certPem, 'sha256');
      if (!pinSetSha256.has(actual)) {
        throw new Error(
          `${label} certificate SHA-256 pin mismatch from ${source}. fingerprint ${actual} not present in configured pins.`,
        );
      }
    }
    if (pinSetSha1.size) {
      const actual = certificateFingerprintHex(certPem, 'sha1');
      if (!pinSetSha1.has(actual)) {
        throw new Error(
          `${label} certificate SHA-1 pin mismatch from ${source}. fingerprint ${actual} not present in configured pins.`,
        );
      }
    }
  }
}

function dedupePemCertificates(pems: string[]): string[] {
  const seen = new Set<string>();
  const deduped: string[] = [];
  for (const pem of pems) {
    try {
      const cert = new X509Certificate(pem);
      const key = cert.fingerprint256;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(pem);
    } catch {
      const key = pem.trim();
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(pem);
    }
  }
  return deduped;
}

function selectSignerCertificate(certs: string[]): string {
  for (const certPem of certs) {
    try {
      const cert = new X509Certificate(certPem);
      if (!cert.ca) return certPem;
    } catch {
      continue;
    }
  }
  return certs[0];
}

type ExtractedPdfSignature = {
  signatureIndex: number;
  signatureDer: Buffer;
  signedData: Buffer;
};

type VerifiedPdfSignature = {
  signatureIndex: number;
  signerCert: X509Certificate;
  signerVatId?: string;
  revocationStatus: RevocationStatus;
  revocationDebug: RevocationDebugInfo;
  notes: string[];
  signedData: Buffer;
};

function normalizeVatId(value: string | undefined): string | undefined {
  const normalized = value?.trim().replace(/\s+/g, '').toUpperCase();
  return normalized || undefined;
}

export function parseVatIdFromSubjectDn(subjectDn: string): string | undefined {
  const match = /\bVATES-[A-Z0-9]+\b/i.exec(subjectDn);
  return normalizeVatId(match?.[0]);
}

export function selectPrimaryCredentialSignature<T extends { signerVatId?: string }>(
  signatures: T[],
  verifierVatList: string[],
): T | undefined {
  const verifierVatSet = new Set(
    verifierVatList
      .map((value) => normalizeVatId(value))
      .filter((value): value is string => Boolean(value)),
  );
  for (let index = signatures.length - 1; index >= 0; index -= 1) {
    const signature = signatures[index];
    const signerVatId = normalizeVatId(signature.signerVatId);
    if (signerVatId && verifierVatSet.has(signerVatId)) {
      continue;
    }
    return signature;
  }
  return undefined;
}

function extractPdfSignatures(pdfBytes: Buffer): ExtractedPdfSignature[] {
  const pdfAsLatin1 = pdfBytes.toString('latin1');
  const byteRangeRegex = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  let match: RegExpExecArray | null;
  const signatures: ExtractedPdfSignature[] = [];
  let signatureIndex = 0;

  while (true) {
    match = byteRangeRegex.exec(pdfAsLatin1);
    if (!match) break;
    const start1 = Number.parseInt(match[1], 10);
    const length1 = Number.parseInt(match[2], 10);
    const start2 = Number.parseInt(match[3], 10);
    const length2 = Number.parseInt(match[4], 10);

    if (!Number.isFinite(start1) || !Number.isFinite(length1) || !Number.isFinite(start2) || !Number.isFinite(length2)) {
      throw new Error('Invalid PDF ByteRange values.');
    }

    if (start1 < 0 || length1 <= 0 || start2 <= 0 || length2 <= 0 || start2 <= start1 + length1) {
      throw new Error('Invalid PDF ByteRange ordering.');
    }

    const signedData = Buffer.concat([
      pdfBytes.subarray(start1, start1 + length1),
      pdfBytes.subarray(start2, start2 + length2),
    ]);

    const signatureWindow = pdfBytes.subarray(start1 + length1, start2);
    const lt = signatureWindow.indexOf(0x3c); // <
    const gt = signatureWindow.lastIndexOf(0x3e); // >
    if (lt === -1 || gt === -1 || gt <= lt) {
      throw new Error('Unable to extract CMS signature bytes from PDF.');
    }

    let hex = signatureWindow.subarray(lt + 1, gt).toString('latin1').replace(/[^0-9a-fA-F]/g, '');
    while (hex.endsWith('00')) {
      hex = hex.slice(0, -2);
    }
    if (!hex.length || hex.length % 2 !== 0) {
      throw new Error('Malformed CMS signature payload inside PDF.');
    }

    signatures.push({
      signatureIndex,
      signatureDer: Buffer.from(hex, 'hex'),
      signedData,
    });
    signatureIndex += 1;
  }

  if (!signatures.length) {
    throw new Error('PDF is missing ByteRange, no digital signature found.');
  }

  return signatures;
}

async function extractCrlUrls(certPemPath: string): Promise<string[]> {
  const output = await runOpenSsl(['x509', '-in', certPemPath, '-noout', '-text']);
  const urls = new Set<string>();
  const crlSectionMatch =
    output.stdout.match(/X509v3 CRL Distribution Points:[\s\S]*?(?:X509v3 [^\n]+:|Signature Algorithm:|$)/);
  const section = crlSectionMatch ? crlSectionMatch[0] : output.stdout;
  const regex = /URI:([^\s,\n]+)/g;
  let match: RegExpExecArray | null;
  while (true) {
    match = regex.exec(section);
    if (!match) break;
    const value = match[1]?.trim();
    if (value && (value.startsWith('http://') || value.startsWith('https://'))) {
      urls.add(value);
    }
  }
  return [...urls];
}

async function crlBufferToPem(crlBuffer: Buffer, tmpDir: string, label: string): Promise<string> {
  const maybePem = crlBuffer.toString('utf8');
  if (maybePem.includes('-----BEGIN X509 CRL-----')) {
    return maybePem;
  }

  const derPath = path.join(tmpDir, `${label}.crl.der`);
  const pemPath = path.join(tmpDir, `${label}.crl.pem`);
  await writeFile(derPath, crlBuffer);
  await runOpenSsl(['crl', '-inform', 'DER', '-in', derPath, '-out', pemPath]);
  return readFile(pemPath, 'utf8');
}

function asSingleLineError(error: unknown): string {
  const message = (error as Error)?.message || String(error);
  return message.replace(/\s+/g, ' ').trim();
}

function isTimeoutLikeError(error: unknown): boolean {
  const stack: unknown[] = [error];
  const visited = new Set<unknown>();
  while (stack.length) {
    const current = stack.pop();
    if (!current || typeof current !== 'object' || visited.has(current)) continue;
    visited.add(current);
    const value = current as { name?: string; code?: string; message?: string; cause?: unknown };
    const text = `${value.name || ''} ${value.code || ''} ${value.message || ''}`.toLowerCase();
    if (text.includes('timeout') || text.includes('timed out') || text.includes('etimedout')) {
      return true;
    }
    if (value.cause) {
      stack.push(value.cause);
    }
  }
  return false;
}

function isDifferentCrlScopeError(error: unknown): boolean {
  return asSingleLineError(error).toLowerCase().includes('different crl scope');
}

class VerificationDiagnosticError extends Error {
  readonly errorDetails: VerificationErrorDetails;

  constructor(message: string, errorDetails: VerificationErrorDetails) {
    super(message);
    this.name = 'VerificationDiagnosticError';
    this.errorDetails = errorDetails;
  }
}

export function resolveTemplateResourceVersion(
  resourceType: string,
  templateUseTestPrefix: boolean,
): string {
  const normalized = resourceType.trim();
  if (!templateUseTestPrefix) return normalized;
  if (normalized.toLowerCase().startsWith('test-')) return normalized;
  return `test-${normalized}`;
}

function resolveTemplateUrl(
  pattern: string,
  route: VerifyRouteContext,
  templateUseTestPrefix: boolean,
): string {
  const jurisdiction = route.jurisdiction.trim();
  const sector = route.sector.trim();
  const resourceVersion = resolveTemplateResourceVersion(route.resourceType, templateUseTestPrefix);
  const replacements: Record<string, string> = {
    tenantId: route.tenantId,
    jurisdiction,
    jurisdictionLower: jurisdiction.toLowerCase(),
    jurisdictionUpper: jurisdiction.toUpperCase(),
    sector,
    sectorLower: sector.toLowerCase(),
    sectorUpper: sector.toUpperCase(),
    section: route.section,
    format: route.format,
    resourceType: route.resourceType,
    resourceVersion,
  };

  let resolved = pattern;
  for (const [key, value] of Object.entries(replacements)) {
    resolved = resolved.replaceAll(`{${key}}`, value);
  }

  if (resolved.includes('{') || resolved.includes('}')) {
    throw new Error('ICA_TERMS_TEMPLATE_URL_PATTERN contains unresolved placeholders.');
  }
  return resolved;
}

async function downloadPemCertificate(url: string, label: string): Promise<string> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid ${label} certificate URL: ${url}`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`Unsupported ${label} certificate URL protocol: ${parsed.protocol}`);
  }

  const response = await fetch(parsed.toString(), { signal: AbortSignal.timeout(15000) });
  if (!response.ok) {
    throw new Error(`${label} certificate download failed (${response.status}) from ${parsed.toString()}`);
  }
  const rawBytes = Buffer.from(await response.arrayBuffer());
  const maybeText = rawBytes.toString('utf8');
  if (maybeText.includes('-----BEGIN CERTIFICATE-----')) {
    return extractSinglePemCertificate(maybeText, label);
  }

  try {
    const cert = new X509Certificate(rawBytes);
    return `${cert.toString().trim()}\n`;
  } catch {
    throw new Error(`${label} certificate from ${parsed.toString()} is not valid PEM/DER.`);
  }
}

export type FnmtVerifierConfig = {
  fnmtRootCertPath: string;
  fnmtIntermediateCertPath: string;
  fnmtRootCertPem?: string;
  fnmtIntermediateCertPem?: string;
  fnmtRootCertUrl?: string;
  fnmtIntermediateCertUrl?: string;
  fnmtIntermediateCertUrls: string[];
  fnmtRootCertPinSha256?: string;
  fnmtRootCertPinSha1?: string;
  fnmtIntermediateCertPinSha256?: string;
  fnmtIntermediateCertPinSha1?: string;
  fnmtIntermediateCertPinsSha256: string[];
  fnmtIntermediateCertPinsSha1: string[];
  fnmtAutoDownload: boolean;
  templateUrlPattern: string;
  strictRevocation: boolean;
  strictTemplateMatch: boolean;
  templateMatchMode: TemplateMatchMode;
  verifierVatList: string[];
  digestAlgorithm: string;
  templateCacheTtlSeconds: number;
  templateCacheMaxEntries: number;
  templatePreloadEnabled: boolean;
  templatePreloadTenantId: string;
  templatePreloadJurisdictions: string[];
  templatePreloadSectors: AllowedSector[];
  templatePreloadResourceTypes: string[];
  templateUseTestPrefix: boolean;
};

export function loadFnmtVerifierConfigFromEnv(): FnmtVerifierConfig {
  const fnmtAutoDownload = parseBoolean(process.env.ICA_FNMT_AUTO_DOWNLOAD, false);
  const intermediateUrlsFromList = parseCsvList(process.env.ICA_FNMT_INTERMEDIATE_CERT_URLS);
  const legacyIntermediateUrl = parseOptionalString(process.env.ICA_FNMT_INTERMEDIATE_CERT_URL);
  const fnmtIntermediateCertUrls = fnmtAutoDownload
    ? dedupeStrings([
      ...(intermediateUrlsFromList.length ? intermediateUrlsFromList : DEFAULT_FNMT_INTERMEDIATE_CERT_URLS),
      ...(legacyIntermediateUrl ? [legacyIntermediateUrl] : []),
    ])
    : dedupeStrings([
      ...intermediateUrlsFromList,
      ...(legacyIntermediateUrl ? [legacyIntermediateUrl] : []),
    ]);
  const fnmtRootCertPinSha256 = parseFingerprintPin(process.env.ICA_FNMT_ROOT_CERT_PIN_SHA256, 64, 'SHA-256');
  const fnmtRootCertPinSha1 = parseFingerprintPin(process.env.ICA_FNMT_ROOT_CERT_PIN_SHA1, 40, 'SHA-1');
  const legacyIntermediatePin = parseFingerprintPin(process.env.ICA_FNMT_INTERMEDIATE_CERT_PIN_SHA256, 64, 'SHA-256');
  const legacyIntermediatePinSha1 = parseFingerprintPin(process.env.ICA_FNMT_INTERMEDIATE_CERT_PIN_SHA1, 40, 'SHA-1');
  const intermediatePinsFromList = parseFingerprintPinList(process.env.ICA_FNMT_INTERMEDIATE_CERT_PINS_SHA256);
  const intermediatePinsFromListSha1 = parseFingerprintPinListSha1(process.env.ICA_FNMT_INTERMEDIATE_CERT_PINS_SHA1);
  const templatePreloadResourceTypes = parseCsvList(process.env.ICA_TERMS_TEMPLATE_PRELOAD_RESOURCE_TYPES);
  const templatePreloadSectors = parseAllowedSectorsList(
    process.env.ICA_TERMS_TEMPLATE_PRELOAD_SECTORS,
    ['animal-care', 'health-care'],
  );
  const templatePreloadJurisdictions = parseCsvList(process.env.ICA_TERMS_TEMPLATE_PRELOAD_JURISDICTIONS);
  const templatePreloadEnabled = parseBoolean(
    process.env.ICA_TERMS_TEMPLATE_PRELOAD_ENABLED,
    templatePreloadResourceTypes.length > 0,
  );
  const unifiedTestTermsPrefix = parseUnifiedTestTermsPrefixFlag();
  const templateUseTestPrefix = unifiedTestTermsPrefix !== undefined
    ? unifiedTestTermsPrefix
    : parseBoolean(process.env.ICA_TERMS_TEMPLATE_USE_TEST_PREFIX, false);
  const templateUrlPattern =
    process.env.ICA_TERMS_TEMPLATE_URL_PATTERN ||
    'https://raw.githubusercontent.com/gdc-ecosystem/gwtemplate-nodejs/main/terms/dataspace/{sector}/{jurisdiction}/{resourceVersion}/terms.pdf';
  validateTemplateUrlPattern(templateUrlPattern);

  return {
    fnmtRootCertPath: path.resolve(process.env.ICA_FNMT_ROOT_CERT_PATH || path.join('certs', 'fnmt', 'fnmt-root.pem')),
    fnmtIntermediateCertPath: path.resolve(
      process.env.ICA_FNMT_INTERMEDIATE_CERT_PATH || path.join('certs', 'fnmt', 'fnmt-intermediate.pem'),
    ),
    fnmtRootCertPem: parseOptionalString(process.env.ICA_FNMT_ROOT_CERT_PEM),
    fnmtIntermediateCertPem: parseOptionalString(process.env.ICA_FNMT_INTERMEDIATE_CERT_PEM),
    fnmtRootCertUrl: parseOptionalString(process.env.ICA_FNMT_ROOT_CERT_URL)
      || (fnmtAutoDownload ? DEFAULT_FNMT_ROOT_CERT_URL : undefined),
    fnmtIntermediateCertUrl: legacyIntermediateUrl,
    fnmtIntermediateCertUrls,
    fnmtRootCertPinSha256,
    fnmtRootCertPinSha1,
    fnmtIntermediateCertPinSha256: legacyIntermediatePin,
    fnmtIntermediateCertPinSha1: legacyIntermediatePinSha1,
    fnmtIntermediateCertPinsSha256: dedupeStrings([
      ...intermediatePinsFromList,
      ...(legacyIntermediatePin ? [legacyIntermediatePin] : []),
    ]),
    fnmtIntermediateCertPinsSha1: dedupeStrings([
      ...intermediatePinsFromListSha1,
      ...(legacyIntermediatePinSha1 ? [legacyIntermediatePinSha1] : []),
    ]),
    fnmtAutoDownload,
    templateUrlPattern,
    strictRevocation: parseBoolean(process.env.ICA_VERIFY_STRICT_REVOCATION, true),
    strictTemplateMatch: parseBoolean(process.env.ICA_VERIFY_STRICT_TEMPLATE_MATCH, true),
    templateMatchMode: parseTemplateMatchMode(process.env.ICA_VERIFY_TEMPLATE_MATCH_MODE, 'strict-bytes'),
    verifierVatList: parseCsvList(process.env.VERIFIERS_VAT_LIST)
      .map((value) => normalizeVatId(value))
      .filter((value): value is string => Boolean(value)),
    digestAlgorithm: parseDigestAlgorithm(process.env.ICA_VERIFY_DIGEST_ALGORITHM, 'sha3-384'),
    templateCacheTtlSeconds: parsePositiveInteger(process.env.ICA_TERMS_TEMPLATE_CACHE_TTL_SECONDS, 900),
    templateCacheMaxEntries: parsePositiveInteger(process.env.ICA_TERMS_TEMPLATE_CACHE_MAX_ENTRIES, 64),
    templatePreloadEnabled,
    templatePreloadTenantId: (process.env.ICA_TERMS_TEMPLATE_PRELOAD_TENANT_ID || process.env.ICA_LOCAL_TENANT_ID || 'ica').trim(),
    templatePreloadJurisdictions: templatePreloadJurisdictions.length
      ? templatePreloadJurisdictions
      : ['ES'],
    templatePreloadSectors,
    templatePreloadResourceTypes,
    templateUseTestPrefix,
  };
}

export class FnmtPdfVerificationService implements PdfVerificationService {
  private readonly config: FnmtVerifierConfig;
  private trustAnchorsLoadError: Error | null = null;
  private readonly trustAnchorsPromise: Promise<{
    rootPem: string;
    intermediatePems: string[];
    rootSource: string;
    intermediateSources: string[];
  } | null>;
  private readonly templateCache = new Map<string, { bytes: Buffer; fetchedAtMs: number }>();
  private readonly templateFetchInFlight = new Map<string, Promise<Buffer>>();

  constructor(config: FnmtVerifierConfig = loadFnmtVerifierConfigFromEnv()) {
    this.config = config;
    console.log(`Template URL pattern active: ${this.config.templateUrlPattern}`);
    console.log(`Template test-mode prefix active: ${this.config.templateUseTestPrefix}`);
    this.trustAnchorsPromise = this.loadTrustAnchors().catch((error: unknown) => {
      const normalized = error instanceof Error ? error : new Error(String(error));
      this.trustAnchorsLoadError = normalized;
      console.error(`FNMT trust anchors preload failed: ${normalized.message}`);
      return null;
    });
    this.preloadTemplates().catch((error: unknown) => {
      console.error(`Template preload failed: ${asSingleLineError(error)}`);
    });
  }

  private shouldUseTemplateCache(): boolean {
    return this.config.templateCacheTtlSeconds > 0 && this.config.templateCacheMaxEntries > 0;
  }

  private pruneTemplateCache(): void {
    if (!this.shouldUseTemplateCache()) {
      this.templateCache.clear();
      return;
    }

    while (this.templateCache.size > this.config.templateCacheMaxEntries) {
      const oldestKey = this.templateCache.keys().next().value as string | undefined;
      if (!oldestKey) break;
      this.templateCache.delete(oldestKey);
    }
  }

  private async downloadTemplateBytes(url: string): Promise<Buffer> {
    const response = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!response.ok) {
      throw new Error(`Template download failed (${response.status}) from ${url}`);
    }
    return Buffer.from(await response.arrayBuffer());
  }

  private async loadTemplateBytes(templateUrl: string): Promise<{ bytes: Buffer; source: 'cache' | 'network' }> {
    if (!this.shouldUseTemplateCache()) {
      return {
        bytes: await this.downloadTemplateBytes(templateUrl),
        source: 'network',
      };
    }

    const now = Date.now();
    const ttlMs = this.config.templateCacheTtlSeconds * 1000;
    const cached = this.templateCache.get(templateUrl);
    if (cached && now - cached.fetchedAtMs <= ttlMs) {
      // Refresh insertion order to keep a lightweight LRU behavior.
      this.templateCache.delete(templateUrl);
      this.templateCache.set(templateUrl, cached);
      return { bytes: cached.bytes, source: 'cache' };
    }

    if (cached) {
      this.templateCache.delete(templateUrl);
    }

    const inFlight = this.templateFetchInFlight.get(templateUrl);
    if (inFlight) {
      return { bytes: await inFlight, source: 'network' };
    }

    const pending = this.downloadTemplateBytes(templateUrl)
      .then((bytes) => {
        this.templateCache.set(templateUrl, { bytes, fetchedAtMs: Date.now() });
        this.pruneTemplateCache();
        return bytes;
      })
      .finally(() => {
        this.templateFetchInFlight.delete(templateUrl);
      });
    this.templateFetchInFlight.set(templateUrl, pending);
    return { bytes: await pending, source: 'network' };
  }

  private async preloadTemplates(): Promise<void> {
    if (!this.config.templatePreloadEnabled) return;
    if (!this.config.templatePreloadResourceTypes.length) return;

    const preloadRequests: Array<Promise<void>> = [];
    for (const resourceType of this.config.templatePreloadResourceTypes) {
      for (const sector of this.config.templatePreloadSectors) {
        for (const jurisdiction of this.config.templatePreloadJurisdictions) {
          const route: VerifyRouteContext = {
            tenantId: this.config.templatePreloadTenantId,
            jurisdiction,
            sector,
            section: 'terms',
            format: 'pdf',
            resourceType,
            action: '_verify',
          };
          const templateUrl = resolveTemplateUrl(
            this.config.templateUrlPattern,
            route,
            this.config.templateUseTestPrefix,
          );
          preloadRequests.push(
            this.loadTemplateBytes(templateUrl)
              .then(() => {
                console.log(`Template preloaded: ${templateUrl}`);
              })
              .catch((error: unknown) => {
                console.warn(`Template preload skipped for ${templateUrl}: ${asSingleLineError(error)}`);
              }),
          );
        }
      }
    }

    await Promise.all(preloadRequests);
  }

  private async verifyPdfSignature(
    signature: ExtractedPdfSignature,
    workspace: string,
    rootPem: string,
    intermediatePems: string[],
  ): Promise<VerifiedPdfSignature> {
    const notes: string[] = [];
    const signatureWorkspace = path.join(workspace, `signature-${signature.signatureIndex}`);
    await mkdir(signatureWorkspace, { recursive: true });

    const signatureDerPath = path.join(signatureWorkspace, 'signature.der');
    const signedDataPath = path.join(signatureWorkspace, 'signed-data.bin');
    const signerFromCmsPath = path.join(signatureWorkspace, 'signer-from-cms.pem');
    await writeFile(signatureDerPath, signature.signatureDer);
    await writeFile(signedDataPath, signature.signedData);

    await runOpenSsl([
      'cms',
      '-verify',
      '-binary',
      '-inform',
      'DER',
      '-in',
      signatureDerPath,
      '-content',
      signedDataPath,
      '-noverify',
      '-signer',
      signerFromCmsPath,
      '-out',
      path.join(signatureWorkspace, 'verified.bin'),
    ]);
    notes.push('CMS signature and authenticated attributes validated.');

    const p7CertsPath = path.join(signatureWorkspace, 'pkcs7-certs.pem');
    await runOpenSsl(['pkcs7', '-inform', 'DER', '-in', signatureDerPath, '-print_certs', '-out', p7CertsPath]);
    const embeddedCerts = dedupePemCertificates(splitPemCertificates(await readFile(p7CertsPath, 'utf8')));
    if (!embeddedCerts.length) {
      throw new Error('No embedded certificates found in PDF signature.');
    }

    const signerPemFromCms = extractFirstPemCertificate(await readFile(signerFromCmsPath, 'utf8'));
    const signerPem = signerPemFromCms || selectSignerCertificate(embeddedCerts);
    const signerCert = new X509Certificate(signerPem);
    const signerVatId = parseVatIdFromSubjectDn(signerCert.subject);
    const untrustedPem = dedupePemCertificates([
      ...intermediatePems,
      ...embeddedCerts.filter((pem) => pem !== signerPem),
    ]);

    const signerPath = path.join(signatureWorkspace, 'signer.pem');
    const rootPath = path.join(signatureWorkspace, 'fnmt-root.pem');
    const untrustedPath = path.join(signatureWorkspace, 'untrusted-chain.pem');
    await writeFile(signerPath, signerPem);
    await writeFile(rootPath, rootPem);
    await writeFile(untrustedPath, `${untrustedPem.join('\n')}\n`);

    const chainCheck = await runOpenSslSafe(['verify', '-CAfile', rootPath, '-untrusted', untrustedPath, signerPath]);
    if (!chainCheck.ok) {
      throw new Error(`Certificate chain validation failed: ${asSingleLineError(chainCheck.error)}`);
    }
    notes.push('Signer chain validated against FNMT root/intermediate.');

    const revocationChecks: RevocationDebugCheck[] = [];
    let signerCrlUrls: string[] = [];
    try {
      signerCrlUrls = await extractCrlUrls(signerPath);
    } catch (error: unknown) {
      const message = `Signer CRL distribution parse failed: ${asSingleLineError(error)}`;
      revocationChecks.push({
        phase: 'discovery',
        status: 'parse_error',
        message,
      });
      notes.push(message);
    }
    const caCrlUrls = new Set<string>();
    for (let index = 0; index < untrustedPem.length; index += 1) {
      const certPem = untrustedPem[index];
      let cert: X509Certificate;
      try {
        cert = new X509Certificate(certPem);
      } catch {
        continue;
      }
      if (!cert.ca) continue;
      const certPath = path.join(signatureWorkspace, `ca-chain-${index}.pem`);
      await writeFile(certPath, certPem);
      try {
        const urls = await extractCrlUrls(certPath);
        for (const url of urls) caCrlUrls.add(url);
      } catch (error: unknown) {
        const message = `CA CRL distribution parse failed for chain cert ${index}: ${asSingleLineError(error)}`;
        revocationChecks.push({
          phase: 'discovery',
          status: 'parse_error',
          message,
        });
        notes.push(message);
      }
    }
    const crlUrls = [...new Set([...signerCrlUrls, ...caCrlUrls])];

    let revocationStatus: RevocationStatus = 'unknown';
    if (!crlUrls.length) {
      const message = 'No CRL URLs found in signer/intermediate certificates.';
      revocationChecks.push({
        phase: 'discovery',
        status: 'no_urls',
        message,
      });
      notes.push(message);
    } else {
      revocationChecks.push({
        phase: 'discovery',
        status: 'ok',
        message: `Discovered ${crlUrls.length} CRL URL(s).`,
      });
      const crlPemList: string[] = [];
      for (let index = 0; index < crlUrls.length; index += 1) {
        const crlUrl = crlUrls[index];
        try {
          const response = await fetch(crlUrl, { signal: AbortSignal.timeout(15000) });
          if (!response.ok) {
            notes.push(`CRL download failed (${response.status}) for ${crlUrl}`);
            revocationChecks.push({
              url: crlUrl,
              phase: 'download',
              status: 'http_error',
              httpStatus: response.status,
              message: `HTTP ${response.status}`,
            });
            continue;
          }
          const crlBuffer = Buffer.from(await response.arrayBuffer());
          try {
            const crlPem = await crlBufferToPem(crlBuffer, signatureWorkspace, `crl-${index}`);
            crlPemList.push(crlPem);
            notes.push(`CRL loaded from ${crlUrl}`);
            revocationChecks.push({
              url: crlUrl,
              phase: 'download',
              status: 'ok',
              httpStatus: response.status,
              message: 'CRL downloaded and parsed.',
            });
          } catch (error: unknown) {
            const message = asSingleLineError(error);
            notes.push(`CRL parse error for ${crlUrl}: ${message}`);
            revocationChecks.push({
              url: crlUrl,
              phase: 'download',
              status: 'parse_error',
              httpStatus: response.status,
              message,
            });
          }
        } catch (error: unknown) {
          const message = asSingleLineError(error);
          const status = isTimeoutLikeError(error) ? 'timeout' : 'download_error';
          notes.push(`CRL download error for ${crlUrl}: ${message}`);
          revocationChecks.push({
            url: crlUrl,
            phase: 'download',
            status,
            message,
          });
        }
      }

      if (crlPemList.length) {
        const crlFilePath = path.join(signatureWorkspace, 'all.crl.pem');
        await writeFile(crlFilePath, `${crlPemList.join('\n')}\n`);
        const verifyWithMode = async (mode: '-crl_check_all' | '-crl_check') => runOpenSslSafe([
          'verify',
          mode,
          '-CAfile',
          rootPath,
          '-untrusted',
          untrustedPath,
          '-CRLfile',
          crlFilePath,
          signerPath,
        ]);

        const revocationCheckAll = await verifyWithMode('-crl_check_all');
        if (revocationCheckAll.ok) {
          revocationStatus = 'good';
          notes.push('Revocation check passed.');
          revocationChecks.push({
            phase: 'verify',
            status: 'ok',
            message: 'OpenSSL CRL verification passed (mode=-crl_check_all).',
          });
        } else if (isDifferentCrlScopeError(revocationCheckAll.error)) {
          const scopeErrorMessage = asSingleLineError(revocationCheckAll.error);
          notes.push(`Chain CRL check scope mismatch: ${scopeErrorMessage}`);
          revocationChecks.push({
            phase: 'verify',
            status: 'verify_error',
            message: `mode=-crl_check_all ${scopeErrorMessage}`,
          });

          const revocationCheckLeaf = await verifyWithMode('-crl_check');
          if (revocationCheckLeaf.ok) {
            revocationStatus = 'good';
            notes.push('Leaf revocation check passed after chain scope mismatch.');
            revocationChecks.push({
              phase: 'verify',
              status: 'ok',
              message: 'OpenSSL CRL verification passed (mode=-crl_check fallback).',
            });
          } else {
            const lowerError = asSingleLineError(revocationCheckLeaf.error).toLowerCase();
            if (lowerError.includes('certificate revoked')) {
              revocationStatus = 'revoked';
              notes.push('Certificate is revoked according to CRL.');
              revocationChecks.push({
                phase: 'verify',
                status: 'revoked',
                message: `mode=-crl_check ${lowerError}`,
              });
            } else {
              revocationStatus = 'unknown';
              notes.push(`Revocation check inconclusive: ${lowerError}`);
              revocationChecks.push({
                phase: 'verify',
                status: 'verify_error',
                message: `mode=-crl_check ${lowerError}`,
              });
            }
          }
        } else {
          const lowerError = asSingleLineError(revocationCheckAll.error).toLowerCase();
          if (lowerError.includes('certificate revoked')) {
            revocationStatus = 'revoked';
            notes.push('Certificate is revoked according to CRL.');
            revocationChecks.push({
              phase: 'verify',
              status: 'revoked',
              message: `mode=-crl_check_all ${lowerError}`,
            });
          } else {
            revocationStatus = 'unknown';
            notes.push(`Revocation check inconclusive: ${lowerError}`);
            revocationChecks.push({
              phase: 'verify',
              status: 'verify_error',
              message: `mode=-crl_check_all ${lowerError}`,
            });
          }
        }
      } else {
        notes.push('No CRL was successfully downloaded.');
        revocationChecks.push({
          phase: 'verify',
          status: 'verify_error',
          message: 'No CRL was successfully downloaded and parsed.',
        });
      }
    }

    const revocationDebug: RevocationDebugInfo = {
      finalStatus: revocationStatus,
      checks: revocationChecks,
    };

    if (this.config.strictRevocation && revocationStatus !== 'good') {
      const revocationNotes = notes
        .filter((note) =>
          note.startsWith('CRL ')
          || note.startsWith('No CRL')
          || note.toLowerCase().includes('revocation'),
        );
      const detail = revocationNotes.length ? ` details: ${revocationNotes.join(' | ')}` : '';
      throw new VerificationDiagnosticError(
        `Revocation check did not pass (status=${revocationStatus}).${detail}`,
        { revocation: revocationDebug },
      );
    }

    return {
      signatureIndex: signature.signatureIndex,
      signerCert,
      signerVatId,
      revocationStatus,
      revocationDebug,
      notes,
      signedData: signature.signedData,
    };
  }

  private async resolveCert(
    label: string,
    pemFromEnv: string | undefined,
    certUrl: string | undefined,
    certPath: string,
    pinSha256: string | undefined,
    pinSha1: string | undefined,
  ): Promise<{ pem: string; source: string }> {
    const normalizedPemEnv = parseOptionalString(pemFromEnv);
    if (normalizedPemEnv) {
      const pem = extractSinglePemCertificate(normalizePem(normalizedPemEnv), `${label} env`);
      ensurePinnedFingerprint(label, pem, pinSha256, pinSha1, `env:${label}`);
      return { pem, source: `env:${label}` };
    }

    if (this.config.fnmtAutoDownload) {
      if (!certUrl) {
        throw new Error(
          `ICA_FNMT_AUTO_DOWNLOAD=true requires URL for ${label} certificate when PEM env is not provided.`,
        );
      }
      const pem = await downloadPemCertificate(certUrl, label);
      ensurePinnedFingerprint(label, pem, pinSha256, pinSha1, certUrl);
      return { pem, source: certUrl };
    }

    const pem = extractSinglePemCertificate(await readFile(certPath, 'utf8'), `${label} file`);
    ensurePinnedFingerprint(label, pem, pinSha256, pinSha1, certPath);
    return { pem, source: certPath };
  }

  private parseIntermediatePemBundle(rawPem: string, source: string): string[] {
    const normalized = normalizePem(rawPem);
    const certs = splitPemCertificates(normalized);
    if (!certs.length) {
      throw new Error(`No PEM certificates found for FNMT intermediate source ${source}.`);
    }
    return certs.map((cert) => `${cert}\n`);
  }

  private async resolveIntermediateCerts(): Promise<{ pems: string[]; sources: string[] }> {
    const normalizedPemEnv = parseOptionalString(this.config.fnmtIntermediateCertPem);
    if (normalizedPemEnv) {
      const pems = this.parseIntermediatePemBundle(normalizedPemEnv, 'env:FNMT intermediate');
      ensurePinnedFingerprintSet(
        'FNMT intermediate',
        pems,
        this.config.fnmtIntermediateCertPinsSha256,
        this.config.fnmtIntermediateCertPinsSha1,
        'env',
      );
      return { pems, sources: ['env:FNMT intermediate'] };
    }

    if (this.config.fnmtAutoDownload) {
      if (!this.config.fnmtIntermediateCertUrls.length) {
        throw new Error(
          'ICA_FNMT_AUTO_DOWNLOAD=true requires intermediate certificate URLs when no intermediate PEM env is provided.',
        );
      }

      const entries = await Promise.all(
        this.config.fnmtIntermediateCertUrls.map(async (url) => ({
          pem: await downloadPemCertificate(url, 'FNMT intermediate'),
          source: url,
        })),
      );
      const pems = entries.map((entry) => entry.pem);
      ensurePinnedFingerprintSet(
        'FNMT intermediate',
        pems,
        this.config.fnmtIntermediateCertPinsSha256,
        this.config.fnmtIntermediateCertPinsSha1,
        'download URLs',
      );
      return { pems, sources: entries.map((entry) => entry.source) };
    }

    const pems = this.parseIntermediatePemBundle(
      await readFile(this.config.fnmtIntermediateCertPath, 'utf8'),
      this.config.fnmtIntermediateCertPath,
    );
    ensurePinnedFingerprintSet(
      'FNMT intermediate',
      pems,
      this.config.fnmtIntermediateCertPinsSha256,
      this.config.fnmtIntermediateCertPinsSha1,
      this.config.fnmtIntermediateCertPath,
    );
    return { pems, sources: [this.config.fnmtIntermediateCertPath] };
  }

  private async loadTrustAnchors() {
    const [root, intermediates] = await Promise.all([
      this.resolveCert(
        'FNMT root',
        this.config.fnmtRootCertPem,
        this.config.fnmtRootCertUrl,
        this.config.fnmtRootCertPath,
        this.config.fnmtRootCertPinSha256,
        this.config.fnmtRootCertPinSha1,
      ),
      this.resolveIntermediateCerts(),
    ]);

    return {
      rootPem: root.pem,
      intermediatePems: dedupePemCertificates(intermediates.pems),
      rootSource: root.source,
      intermediateSources: dedupeStrings(intermediates.sources),
    };
  }

  async verify(route: VerifyRouteContext, submission: VerifySubmission): Promise<VerifyResult> {
    const notes: string[] = [];
    const workspace = await mkdtemp(path.join(tmpdir(), 'ica-pdf-verify-'));

    try {
      const trustAnchors = await this.trustAnchorsPromise;
      if (!trustAnchors) {
        throw this.trustAnchorsLoadError || new Error('FNMT trust anchors are unavailable.');
      }
      const rootPem = trustAnchors.rootPem;
      const intermediatePems = trustAnchors.intermediatePems;
      notes.push(`FNMT root loaded from ${trustAnchors.rootSource}`);
      notes.push(`FNMT intermediate loaded from ${trustAnchors.intermediateSources.join(', ')}`);
      const extractedSignatures = extractPdfSignatures(submission.pdfBytes);
      notes.push(`Detected ${extractedSignatures.length} PDF signature(s).`);

      const verifiedSignatures: VerifiedPdfSignature[] = [];
      for (const signature of extractedSignatures) {
        let verifiedSignature: VerifiedPdfSignature;
        try {
          verifiedSignature = await this.verifyPdfSignature(signature, workspace, rootPem, intermediatePems);
        } catch (error: unknown) {
          const label = `Signature ${signature.signatureIndex + 1}`;
          if (error instanceof VerificationDiagnosticError) {
            throw new VerificationDiagnosticError(`${label} failed: ${error.message}`, error.errorDetails);
          }
          throw new Error(`${label} failed: ${asSingleLineError(error)}`);
        }
        verifiedSignatures.push(verifiedSignature);
        const label = `Signature ${signature.signatureIndex + 1}`;
        if (verifiedSignature.signerVatId) {
          notes.push(`${label} signer VAT: ${verifiedSignature.signerVatId}`);
        } else {
          notes.push(`${label} signer VAT: not present in certificate subject.`);
        }
        notes.push(...verifiedSignature.notes.map((note) => `${label}: ${note}`));
      }

      const primarySignature = selectPrimaryCredentialSignature(verifiedSignatures, this.config.verifierVatList);
      if (!primarySignature) {
        throw new Error('All PDF signatures belong to verifier organizations listed in VERIFIERS_VAT_LIST.');
      }

      for (const signature of verifiedSignatures) {
        if (signature.signatureIndex === primarySignature.signatureIndex) continue;
        if (signature.signerVatId && this.config.verifierVatList.includes(signature.signerVatId)) {
          notes.push(
            `Signature ${signature.signatureIndex + 1} ignored for credential extraction because signer VAT ` +
            `${signature.signerVatId} is listed in VERIFIERS_VAT_LIST.`,
          );
        }
      }
      notes.push(`Credential extraction uses signature ${primarySignature.signatureIndex + 1}.`);

      const skipTemplateValidation = route.resourceType === 'contract';
      let templateUrl = '';
      let templateMatch = true;
      let templateDigestHex = '';
      let templateSha256Hex = '';
      if (skipTemplateValidation) {
        notes.push('Content/template validation skipped because resourceType=contract.');
      } else {
        templateUrl = resolveTemplateUrl(
          this.config.templateUrlPattern,
          route,
          this.config.templateUseTestPrefix,
        );
        const { bytes: templateBytes, source: templateSource } = await this.loadTemplateBytes(templateUrl);
        notes.push(
          templateSource === 'cache'
            ? `Template loaded from cache: ${templateUrl}`
            : `Template downloaded: ${templateUrl}`,
        );

        const signedPdfDigestHex = hashHex(submission.pdfBytes, this.config.digestAlgorithm);
        const unsignedPdfDigestHex = hashHex(primarySignature.signedData, this.config.digestAlgorithm);
        templateDigestHex = hashHex(templateBytes, this.config.digestAlgorithm);
        const strictBytesTemplateMatch =
          templateDigestHex === signedPdfDigestHex || templateDigestHex === unsignedPdfDigestHex;

        templateMatch = strictBytesTemplateMatch;
        if (this.config.templateMatchMode === 'logical-content') {
          const templateLogical = computePdfLogicalFingerprint(templateBytes);
          const uploadedLogical = computePdfLogicalFingerprint(primarySignature.signedData);
          templateMatch = Boolean(
            templateLogical
            && uploadedLogical
            && templateLogical.hash === uploadedLogical.hash,
          );
          notes.push('Template match mode: logical-content');
          if (templateLogical && uploadedLogical) {
            notes.push(
              `Logical content hashes template=${templateLogical.hash} uploaded=${uploadedLogical.hash} ` +
              `(pages template/uploaded=${templateLogical.pageCount}/${uploadedLogical.pageCount}, ` +
              `content-streams=${templateLogical.pageContentCount}/${uploadedLogical.pageContentCount}).`,
            );
          } else {
            notes.push('Logical content fingerprint unavailable for template and/or uploaded PDF.');
          }
        } else {
          notes.push('Template match mode: strict-bytes');
        }

        if (!templateMatch) {
          notes.push(
            `Template hash (${this.config.digestAlgorithm}) did not match uploaded PDF hash or unsigned PDF hash.`,
          );
        }
        if (this.config.strictTemplateMatch && !templateMatch) {
          throw new Error('Uploaded PDF does not match the expected template version.');
        }

        templateSha256Hex = hashHex(templateBytes, 'sha256');
      }

      const signedPdfDigestHex = hashHex(submission.pdfBytes, this.config.digestAlgorithm);
      const unsignedPdfDigestHex = hashHex(primarySignature.signedData, this.config.digestAlgorithm);

      // Legacy sha256 block kept for compatibility in result payload.
      const signedPdfSha256Hex = hashHex(submission.pdfBytes, 'sha256');
      const unsignedPdfSha256Hex = hashHex(primarySignature.signedData, 'sha256');

      return {
        ok: true,
        verifiedAt: new Date().toISOString(),
        templateUrl,
        templateMatch,
        signatureValid: true,
        chainValid: true,
        revocationStatus: primarySignature.revocationStatus,
        digest: {
          alg: this.config.digestAlgorithm,
          signedPdfHex: signedPdfDigestHex,
          unsignedPdfHex: unsignedPdfDigestHex,
          templateHex: templateDigestHex,
        },
        signerCertificateSerialNumber: primarySignature.signerCert.serialNumber,
        signerSubject: primarySignature.signerCert.subject,
        signerIssuer: primarySignature.signerCert.issuer,
        hashes: {
          signedPdfSha256Hex,
          unsignedPdfSha256Hex,
          templateSha256Hex,
        },
        notes,
        revocationDebug: primarySignature.revocationDebug,
      };
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  }
}
