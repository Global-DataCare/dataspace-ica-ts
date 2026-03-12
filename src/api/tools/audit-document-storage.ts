import { createHash, randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Storage } from '@google-cloud/storage';
import type {
  AuditDocumentReference,
  VerifyResult,
  VerifyRouteContext,
  VerifySubmission,
} from '../types.ts';

export type AuditStorageMode = 'none' | 'filesystem' | 'gcs';

export type AuditDocumentStorageConfig = {
  mode: AuditStorageMode;
  required: boolean;
  attachmentUrlPattern: string;
  filesystemDirectory: string;
  gcsBucketName?: string;
  gcsObjectPrefix: string;
};

type AuditStoreInput = {
  route: VerifyRouteContext;
  submission: VerifySubmission;
  result: VerifyResult;
  objectId: string;
  objectKey: string;
};

interface AuditStorageAdapter {
  store(input: AuditStoreInput): Promise<Pick<AuditDocumentReference, 'provider' | 'objectKey' | 'objectId' | 'bucket' | 'contentType' | 'sizeBytes' | 'storedAt'>>;
}

function parseAuditStorageMode(value: string | undefined, fallback: AuditStorageMode): AuditStorageMode {
  const normalized = (value || fallback).trim().toLowerCase();
  if (normalized === 'mem') {
    return 'none';
  }
  if (normalized === 'none' || normalized === 'filesystem' || normalized === 'gcs') {
    return normalized;
  }
  throw new Error(
    `Unsupported STORAGE_PROVIDER="${normalized}". Use "mem", "filesystem" or "gcs".`,
  );
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function sanitizePathSegment(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    || 'unknown';
}

function resolveAttachmentUrl(pattern: string, reference: AuditDocumentReference): string {
  const replacements: Record<string, string> = {
    provider: reference.provider,
    objectId: reference.objectId,
    objectKey: reference.objectKey,
    bucket: reference.bucket || '',
  };
  let output = pattern;
  for (const [key, value] of Object.entries(replacements)) {
    output = output.replaceAll(`{${key}}`, value);
  }
  if (!output.trim()) {
    return `urn:uuid:${reference.objectId}`;
  }
  return output;
}

function buildObjectKey(
  route: VerifyRouteContext,
  result: VerifyResult,
  objectId: string,
  prefix: string,
): string {
  const verifiedDay = sanitizePathSegment(result.verifiedAt.slice(0, 10));
  const digest = sanitizePathSegment((result.digest?.signedPdfHex || '').slice(0, 24));
  const fileName = digest
    ? `${objectId}-${digest}.pdf`
    : `${objectId}.pdf`;
  return [
    sanitizePathSegment(prefix),
    sanitizePathSegment(route.sector),
    sanitizePathSegment(route.jurisdiction),
    sanitizePathSegment(route.resourceType),
    verifiedDay,
    fileName,
  ].join('/');
}

class FileSystemAuditStorageAdapter implements AuditStorageAdapter {
  private readonly baseDirectory: string;

  constructor(baseDirectory: string) {
    this.baseDirectory = baseDirectory;
  }

  async store(input: AuditStoreInput): Promise<Pick<AuditDocumentReference, 'provider' | 'objectKey' | 'objectId' | 'bucket' | 'contentType' | 'sizeBytes' | 'storedAt'>> {
    const fullPath = path.join(this.baseDirectory, input.objectKey);
    await mkdir(path.dirname(fullPath), { recursive: true });
    await writeFile(fullPath, input.submission.pdfBytes, { mode: 0o600 });

    return {
      provider: 'filesystem',
      objectId: input.objectId,
      objectKey: input.objectKey,
      contentType: input.submission.contentType || 'application/pdf',
      sizeBytes: input.submission.pdfBytes.length,
      storedAt: new Date().toISOString(),
    };
  }
}

class GcsAuditStorageAdapter implements AuditStorageAdapter {
  private readonly storage: Storage;
  private readonly bucketName: string;

  constructor(bucketName: string) {
    this.storage = new Storage();
    this.bucketName = bucketName;
  }

  async store(input: AuditStoreInput): Promise<Pick<AuditDocumentReference, 'provider' | 'objectKey' | 'objectId' | 'bucket' | 'contentType' | 'sizeBytes' | 'storedAt'>> {
    const file = this.storage.bucket(this.bucketName).file(input.objectKey);
    await file.save(input.submission.pdfBytes, {
      resumable: false,
      contentType: input.submission.contentType || 'application/pdf',
      metadata: {
        metadata: {
          thid: input.submission.thid,
          resourceType: input.route.resourceType,
          jurisdiction: input.route.jurisdiction,
          sector: input.route.sector,
          digestSha3_384: input.result.digest?.signedPdfHex || '',
          digestSha256: input.result.hashes?.signedPdfSha256Hex || createHash('sha256').update(input.submission.pdfBytes).digest('hex'),
        },
      },
    });

    return {
      provider: 'gcs',
      bucket: this.bucketName,
      objectId: input.objectId,
      objectKey: input.objectKey,
      contentType: input.submission.contentType || 'application/pdf',
      sizeBytes: input.submission.pdfBytes.length,
      storedAt: new Date().toISOString(),
    };
  }
}

class NoopAuditStorageAdapter implements AuditStorageAdapter {
  async store(input: AuditStoreInput): Promise<Pick<AuditDocumentReference, 'provider' | 'objectKey' | 'objectId' | 'bucket' | 'contentType' | 'sizeBytes' | 'storedAt'>> {
    return {
      provider: 'filesystem',
      objectId: input.objectId,
      objectKey: input.objectKey,
      contentType: input.submission.contentType || 'application/pdf',
      sizeBytes: input.submission.pdfBytes.length,
      storedAt: new Date().toISOString(),
    };
  }
}

function createAuditStorageAdapter(config: AuditDocumentStorageConfig): AuditStorageAdapter {
  switch (config.mode) {
    case 'filesystem':
      return new FileSystemAuditStorageAdapter(config.filesystemDirectory);
    case 'gcs':
      if (!config.gcsBucketName) {
        throw new Error('STORAGE_PROVIDER=gcs requires GCS_BUCKET_NAME.');
      }
      return new GcsAuditStorageAdapter(config.gcsBucketName);
    case 'none':
    default:
      return new NoopAuditStorageAdapter();
  }
}

export function loadAuditDocumentStorageConfigFromEnv(): AuditDocumentStorageConfig {
  const mode = parseAuditStorageMode(process.env.STORAGE_PROVIDER, 'none');
  const requiredByDefault = mode !== 'none';
  const required = parseBoolean(process.env.ICA_AUDIT_STORAGE_REQUIRED, requiredByDefault);

  return {
    mode,
    required,
    attachmentUrlPattern: (process.env.ICA_AUDIT_ATTACHMENT_URL_PATTERN || 'urn:uuid:{objectId}').trim(),
    filesystemDirectory: path.resolve(process.env.ICA_AUDIT_STORAGE_FS_DIR || path.join('data', 'audit-pdf')),
    gcsBucketName: (process.env.GCS_BUCKET_NAME || '').trim() || undefined,
    gcsObjectPrefix: (process.env.ICA_AUDIT_STORAGE_GCS_PREFIX || 'ica-audit').trim(),
  };
}

export class AuditDocumentStorageService {
  private readonly config: AuditDocumentStorageConfig;
  private readonly adapter: AuditStorageAdapter;

  constructor(config: AuditDocumentStorageConfig = loadAuditDocumentStorageConfigFromEnv()) {
    this.config = config;
    this.adapter = createAuditStorageAdapter(config);
  }

  async persistVerifiedPdf(
    route: VerifyRouteContext,
    submission: VerifySubmission,
    result: VerifyResult,
  ): Promise<VerifyResult> {
    if (!result.ok || this.config.mode === 'none') {
      return result;
    }

    const objectId = randomUUID();
    const objectKey = buildObjectKey(route, result, objectId, this.config.gcsObjectPrefix);

    try {
      const stored = await this.adapter.store({
        route,
        submission,
        result,
        objectId,
        objectKey,
      });

      const referenceBase: AuditDocumentReference = {
        ...stored,
        attachmentUrl: '',
      };
      const reference: AuditDocumentReference = {
        ...referenceBase,
        attachmentUrl: resolveAttachmentUrl(this.config.attachmentUrlPattern, referenceBase),
      };

      return {
        ...result,
        auditDocument: reference,
        notes: [
          ...result.notes,
          `Audit document stored (${reference.provider}) as ${reference.objectKey}.`,
        ],
      };
    } catch (error: unknown) {
      const message = `Audit document storage failed: ${(error as Error)?.message || String(error)}`;
      if (this.config.required) {
        throw new Error(message);
      }
      return {
        ...result,
        notes: [...result.notes, message],
      };
    }
  }
}

export function createAuditDocumentStorageServiceFromEnv(): AuditDocumentStorageService {
  return new AuditDocumentStorageService(loadAuditDocumentStorageConfigFromEnv());
}
