import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { Storage } from '@google-cloud/storage';
import { ConfidentialStorageService } from './confidential-storage.ts';
import type {
  AuditDocumentReference,
  VerifyResult,
  VerifyRouteContext,
  VerifySubmission,
} from '../types.ts';

export type AuditStorageMode = 'none' | 'gcs' | 'ipfs';

export type AuditDocumentStorageConfig = {
  mode: AuditStorageMode;
  required: boolean;
  confidentialStorageEnabled: boolean;
  attachmentUrlPattern: string;
  gcsBucketName?: string;
  gcsObjectPrefix: string;
  ipfsApiUrl?: string;
  ipfsGatewayUrl?: string;
  ipfsMfsRoot?: string;
};

type AuditStoreInput = {
  route: VerifyRouteContext;
  submission: VerifySubmission;
  result: VerifyResult;
  objectId: string;
  objectKey: string;
  payloadBytes: Buffer<ArrayBufferLike>;
  payloadContentType: string;
  encryptionKeyId?: string;
};

interface AuditStorageAdapter {
  store(input: AuditStoreInput): Promise<Pick<AuditDocumentReference, 'provider' | 'objectKey' | 'objectId' | 'bucket' | 'contentType' | 'sizeBytes' | 'storedAt'>>;
}

function parseAuditStorageMode(value: string | undefined, fallback: AuditStorageMode): AuditStorageMode {
  const normalized = (value || fallback).trim().toLowerCase();
  if (normalized === 'mem') {
    return 'none';
  }
  if (normalized === 'none' || normalized === 'gcs' || normalized === 'ipfs') {
    return normalized;
  }
  throw new Error(
    `Unsupported STORAGE_PROVIDER="${normalized}". Use "mem", "gcs" or "ipfs".`,
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

class GcsAuditStorageAdapter implements AuditStorageAdapter {
  private readonly storage: Storage;
  private readonly bucketName: string;

  constructor(bucketName: string) {
    this.storage = new Storage();
    this.bucketName = bucketName;
  }

  async store(input: AuditStoreInput): Promise<Pick<AuditDocumentReference, 'provider' | 'objectKey' | 'objectId' | 'bucket' | 'contentType' | 'sizeBytes' | 'storedAt'>> {
    const file = this.storage.bucket(this.bucketName).file(input.objectKey);
    await file.save(input.payloadBytes, {
      resumable: false,
      contentType: input.payloadContentType,
      metadata: {
        metadata: {
          thid: input.submission.thid,
          resourceType: input.route.resourceType,
          jurisdiction: input.route.jurisdiction,
          sector: input.route.sector,
          digestSha3_384: input.result.digest?.signedPdfHex || '',
          digestSha256: input.result.hashes?.signedPdfSha256Hex || createHash('sha256').update(input.submission.pdfBytes).digest('hex'),
          ...(input.encryptionKeyId ? { encryptionKeyId: input.encryptionKeyId } : {}),
        },
      },
    });

    return {
      provider: 'gcs',
      bucket: this.bucketName,
      objectId: input.objectId,
      objectKey: input.objectKey,
      contentType: input.payloadContentType,
      sizeBytes: input.payloadBytes.length,
      storedAt: new Date().toISOString(),
      ...(input.encryptionKeyId ? { encryptionKeyId: input.encryptionKeyId } : {}),
    };
  }
}

class IpfsAuditStorageAdapter implements AuditStorageAdapter {
  private readonly apiUrl: string;
  private readonly mfsRoot: string;

  constructor(apiUrl: string, mfsRoot: string) {
    this.apiUrl = apiUrl.replace(/\/$/, '');
    this.mfsRoot = mfsRoot.replace(/\/$/, '');
  }

  async store(input: AuditStoreInput): Promise<Pick<AuditDocumentReference, 'provider' | 'objectKey' | 'objectId' | 'bucket' | 'contentType' | 'sizeBytes' | 'storedAt'>> {
    const fullPath = `${this.mfsRoot}/${input.objectKey}`;
    const dirPath = path.posix.dirname(fullPath);
    
    await fetch(`${this.apiUrl}/api/v0/files/mkdir?arg=${encodeURIComponent(dirPath)}&parents=true`, { method: 'POST' });
    
    const formData = new FormData();
    const blob = new Blob([new Uint8Array(input.payloadBytes)], { type: input.payloadContentType });
    formData.append('file', blob);
    
    const writeRes = await fetch(`${this.apiUrl}/api/v0/files/write?arg=${encodeURIComponent(fullPath)}&create=true&truncate=true`, {
      method: 'POST',
      body: formData,
    });
    if (!writeRes.ok) {
      throw new Error(`IPFS write failed: ${writeRes.statusText}`);
    }
    
    const statRes = await fetch(`${this.apiUrl}/api/v0/files/stat?arg=${encodeURIComponent(fullPath)}`, { method: 'POST' });
    if (!statRes.ok) {
      throw new Error(`IPFS stat failed: ${statRes.statusText}`);
    }
    const statData = (await statRes.json()) as { Hash: string };
    const cid = statData.Hash;
    const objectKey = `ipfs://${cid}`;

    return {
      provider: 'ipfs',
      objectId: input.objectId,
      objectKey,
      contentType: input.payloadContentType,
      sizeBytes: input.payloadBytes.length,
      storedAt: new Date().toISOString(),
      ...(input.encryptionKeyId ? { encryptionKeyId: input.encryptionKeyId } : {}),
    };
  }
}

function createAuditStorageAdapter(config: AuditDocumentStorageConfig): AuditStorageAdapter | undefined {
  switch (config.mode) {
    case 'gcs':
      if (!config.gcsBucketName) {
        throw new Error('STORAGE_PROVIDER=gcs requires GCS_BUCKET_NAME.');
      }
      return new GcsAuditStorageAdapter(config.gcsBucketName);
    case 'ipfs':
      if (!config.ipfsApiUrl) {
        throw new Error('STORAGE_PROVIDER=ipfs requires IPFS_API_URL.');
      }
      return new IpfsAuditStorageAdapter(config.ipfsApiUrl, config.ipfsMfsRoot || '/ica-audit');
    case 'none':
    default:
      return undefined;
  }
}

export function loadAuditDocumentStorageConfigFromEnv(): AuditDocumentStorageConfig {
  const mode = parseAuditStorageMode(process.env.STORAGE_PROVIDER, 'none');
  const requiredByDefault = mode !== 'none';
  const required = parseBoolean(process.env.ICA_AUDIT_STORAGE_REQUIRED, requiredByDefault);

  return {
    mode,
    required,
    confidentialStorageEnabled: parseBoolean(process.env.ICA_CONFIDENTIAL_STORAGE_ENABLED, false),
    attachmentUrlPattern: (process.env.ICA_AUDIT_ATTACHMENT_URL_PATTERN || 'urn:uuid:{objectId}').trim(),
    gcsBucketName: (process.env.GCS_BUCKET_NAME || '').trim() || undefined,
    gcsObjectPrefix: (process.env.ICA_AUDIT_STORAGE_GCS_PREFIX || 'ica-audit').trim(),
    ipfsApiUrl: (process.env.IPFS_API_URL || 'http://127.0.0.1:5001').trim(),
    ipfsGatewayUrl: (process.env.IPFS_GATEWAY_URL || 'http://127.0.0.1:8080').trim(),
    ipfsMfsRoot: (process.env.IPFS_MFS_ROOT || '/ica-audit').trim(),
  };
}

export class AuditDocumentStorageService {
  private readonly config: AuditDocumentStorageConfig;
  private readonly adapter?: AuditStorageAdapter;
  private readonly confidentialStorage: ConfidentialStorageService;

  constructor(config: AuditDocumentStorageConfig = loadAuditDocumentStorageConfigFromEnv()) {
    this.config = config;
    this.adapter = createAuditStorageAdapter(config);
    this.confidentialStorage = new ConfidentialStorageService({
      enabled: config.confidentialStorageEnabled,
      keyVersion: (process.env.ICA_CONFIDENTIAL_STORAGE_KEY_VERSION || 'v1').trim() || 'v1',
    });
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
    const protectedPayload = await this.confidentialStorage.protectBinary(
      route.tenantId,
      'audit-pdf',
      submission.pdfBytes,
    );
    const objectKeyBase = buildObjectKey(route, result, objectId, this.config.gcsObjectPrefix);
    const objectKey = this.confidentialStorage.isEnabled() ? `${objectKeyBase}.enc` : objectKeyBase;

    try {
      if (!this.adapter) {
        throw new Error(`No audit storage adapter configured for mode "${this.config.mode}".`);
      }
      const stored = await this.adapter.store({
        route,
        submission,
        result,
        objectId,
        objectKey,
        payloadBytes: protectedPayload.ciphertext,
        payloadContentType: protectedPayload.contentType,
        ...(protectedPayload.keyId ? { encryptionKeyId: protectedPayload.keyId } : {}),
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
          `Audit document stored (${reference.provider}) as ${reference.objectKey}${protectedPayload.keyId ? ` [encrypted kid=${protectedPayload.keyId}]` : ''}.`,
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
