import { createHash, randomBytes } from 'node:crypto';
import type { IcaNetworkKind } from './network-kind.ts';

export type HostActivationStatus = 'available' | 'consumed';

export type HostActivationApproval = {
  jurisdiction: string;
  sector: string;
  legalName: string;
  addressCountry: string;
  controllerEmail: string;
  serviceUrl: string;
  taxId?: string;
  identifierType?: string;
  identifierValue?: string;
};

export type HostActivationRecord = {
  id: string;
  codeHash: string;
  domain: string;
  networkKind: IcaNetworkKind;
  status: HostActivationStatus;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  approval: HostActivationApproval;
  consumedAt?: string;
  consumedByThid?: string;
};

export type HostActivationStorageConfig = {
  provider: 'mem' | 'firestore' | 'postgres';
  postgresUrl?: string;
  firestoreProjectId?: string;
  collectionPrefix?: string;
};

const HOST_ACTIVATION_MIN_TTL_SECONDS = 60;
const HOST_ACTIVATION_MAX_TTL_SECONDS = 72 * 60 * 60;
const hostActivationMemRecords = new Map<string, HostActivationRecord>();

function hashActivationCode(code: string): string {
  return createHash('sha256').update(code, 'utf8').digest('hex');
}

function activationRecordId(codeHash: string): string {
  return `sha256-${codeHash}`;
}

function normalizeDomain(value: string): string {
  const domain = String(value || '').trim().toLowerCase();
  if (!domain || !/^[a-z0-9.-]+$/.test(domain) || domain.startsWith('.') || domain.endsWith('.')) {
    throw new Error('Host activation domain must be one DNS hostname without scheme or path.');
  }
  return domain;
}

function normalizeNetworkKind(value: string): IcaNetworkKind {
  const networkKind = String(value || '').trim().toLowerCase();
  if (networkKind !== 'local-network' && networkKind !== 'test-network' && networkKind !== 'network') {
    throw new Error('Host activation network must be local-network, test-network or network.');
  }
  return networkKind;
}

function requiredText(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`Host activation ${label} is required.`);
  return normalized;
}

function normalizeApproval(value: HostActivationApproval, domain: string): HostActivationApproval {
  const serviceUrl = new URL(requiredText(value?.serviceUrl, 'serviceUrl'));
  if (serviceUrl.protocol !== 'https:' || serviceUrl.hostname.toLowerCase() !== domain) {
    throw new Error('Host activation serviceUrl must use HTTPS and the exact approved domain.');
  }
  const taxId = String(value?.taxId || '').trim();
  const identifierType = String(value?.identifierType || '').trim();
  const identifierValue = String(value?.identifierValue || '').trim();
  if (Boolean(taxId) === Boolean(identifierType && identifierValue)) {
    throw new Error('Host activation requires either taxId or identifierType plus identifierValue.');
  }
  return {
    jurisdiction: requiredText(value?.jurisdiction, 'jurisdiction').toUpperCase(),
    sector: requiredText(value?.sector, 'sector').toLowerCase(),
    legalName: requiredText(value?.legalName, 'legalName'),
    addressCountry: requiredText(value?.addressCountry, 'addressCountry').toUpperCase(),
    controllerEmail: requiredText(value?.controllerEmail, 'controllerEmail').toLowerCase(),
    serviceUrl: serviceUrl.toString().replace(/\/$/, ''),
    ...(taxId ? { taxId } : { identifierType, identifierValue }),
  };
}

function normalizeCollectionPrefix(value: string | undefined): string {
  return String(value || 'ica').trim().toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'ica';
}

function collectionName(config: HostActivationStorageConfig): string {
  return `${normalizeCollectionPrefix(config.collectionPrefix)}_host_activations`;
}

async function importModule(modulePath: string): Promise<any> {
  const dynamicImport = new Function('path', 'return import(path)') as (path: string) => Promise<any>;
  return dynamicImport(modulePath);
}

/**
 * Persists and atomically consumes short-lived host bootstrap activations.
 * Raw activation codes are returned once to the operator and never persisted.
 */
export class HostActivationService {
  private readonly config: HostActivationStorageConfig;
  private readonly now: () => Date;

  constructor(config: HostActivationStorageConfig, now: () => Date = () => new Date()) {
    this.config = config;
    this.now = now;
  }

  /** Creates one activation bound to one exact, governance-approved host profile. */
  async create(input: {
    domain: string;
    networkKind: string;
    expiresInSeconds: number;
    createdBy: string;
    approval: HostActivationApproval;
  }): Promise<{ activationCode: string; record: HostActivationRecord }> {
    const expiresInSeconds = Math.trunc(Number(input.expiresInSeconds));
    if (expiresInSeconds < HOST_ACTIVATION_MIN_TTL_SECONDS || expiresInSeconds > HOST_ACTIVATION_MAX_TTL_SECONDS) {
      throw new Error('Host activation expiry must be between 60 seconds and 72 hours.');
    }
    const createdBy = String(input.createdBy || '').trim();
    if (!createdBy) throw new Error('Host activation createdBy is required.');
    const activationCode = `ica_host_${randomBytes(32).toString('base64url')}`;
    const codeHash = hashActivationCode(activationCode);
    const createdAt = this.now();
    const record: HostActivationRecord = {
      id: activationRecordId(codeHash),
      codeHash,
      domain: normalizeDomain(input.domain),
      networkKind: normalizeNetworkKind(input.networkKind),
      status: 'available',
      createdAt: createdAt.toISOString(),
      createdBy,
      expiresAt: new Date(createdAt.getTime() + expiresInSeconds * 1000).toISOString(),
      approval: normalizeApproval(input.approval, normalizeDomain(input.domain)),
    };
    await this.store(record);
    return { activationCode, record };
  }

  /** Atomically consumes an activation for the signed request thread. */
  async consume(input: {
    activationCode: string;
    domain: string;
    networkKind: string;
    thid: string;
    approval: HostActivationApproval;
  }): Promise<HostActivationRecord> {
    const code = String(input.activationCode || '').trim();
    const thid = String(input.thid || '').trim();
    if (!code || !thid) throw new Error('Host activation code and thid are required.');
    const match = {
      id: activationRecordId(hashActivationCode(code)),
      domain: normalizeDomain(input.domain),
      networkKind: normalizeNetworkKind(input.networkKind),
      nowIso: this.now().toISOString(),
      thid,
      approval: normalizeApproval(input.approval, normalizeDomain(input.domain)),
    };
    const consumed = await this.consumeStored(match);
    if (!consumed) {
      throw new Error('Host activation is invalid, expired, already consumed or does not match the approved domain/network; it may also not match approved host data.');
    }
    return consumed;
  }

  private async store(record: HostActivationRecord): Promise<void> {
    if (this.config.provider === 'mem') {
      hostActivationMemRecords.set(record.id, { ...record });
      return;
    }
    if (this.config.provider === 'firestore') {
      const module = await importModule('@google-cloud/firestore');
      const Firestore = module.Firestore;
      const client = new Firestore({
        ignoreUndefinedProperties: true,
        ...(this.config.firestoreProjectId ? { projectId: this.config.firestoreProjectId } : {}),
      });
      await client.collection(collectionName(this.config)).doc(record.id).create(record);
      return;
    }
    const module = await importModule('pg');
    const Pool = module.Pool || module.default.Pool;
    if (!this.config.postgresUrl) throw new Error('POSTGRES_URL is required for host activation storage.');
    const pool = new Pool({ connectionString: this.config.postgresUrl });
    try {
      await this.ensurePostgresTable(pool);
      await pool.query(
        `INSERT INTO "${collectionName(this.config)}" (id, data) VALUES ($1, $2)`,
        [record.id, JSON.stringify(record)],
      );
    } finally {
      await pool.end();
    }
  }

  private async consumeStored(match: {
    id: string;
    domain: string;
    networkKind: IcaNetworkKind;
    nowIso: string;
    thid: string;
    approval: HostActivationApproval;
  }): Promise<HostActivationRecord | undefined> {
    if (this.config.provider === 'mem') {
      const record = hostActivationMemRecords.get(match.id);
      if (!record || !this.matchesAvailableRecord(record, match)) return undefined;
      const consumed = this.toConsumedRecord(record, match);
      hostActivationMemRecords.set(match.id, consumed);
      return consumed;
    }
    if (this.config.provider === 'firestore') {
      const module = await importModule('@google-cloud/firestore');
      const Firestore = module.Firestore;
      const client = new Firestore({
        ignoreUndefinedProperties: true,
        ...(this.config.firestoreProjectId ? { projectId: this.config.firestoreProjectId } : {}),
      });
      const ref = client.collection(collectionName(this.config)).doc(match.id);
      return client.runTransaction(async (transaction: any) => {
        const snapshot = await transaction.get(ref);
        const record = snapshot.exists ? snapshot.data() as HostActivationRecord : undefined;
        if (!record || !this.matchesAvailableRecord(record, match)) return undefined;
        const consumed = this.toConsumedRecord(record, match);
        transaction.set(ref, consumed);
        return consumed;
      });
    }
    const module = await importModule('pg');
    const Pool = module.Pool || module.default.Pool;
    if (!this.config.postgresUrl) throw new Error('POSTGRES_URL is required for host activation storage.');
    const pool = new Pool({ connectionString: this.config.postgresUrl });
    const client = await pool.connect();
    try {
      await this.ensurePostgresTable(client);
      await client.query('BEGIN');
      const result = await client.query(
        `SELECT data FROM "${collectionName(this.config)}" WHERE id = $1 FOR UPDATE`,
        [match.id],
      );
      const record = result.rows[0]?.data as HostActivationRecord | undefined;
      if (!record || !this.matchesAvailableRecord(record, match)) {
        await client.query('ROLLBACK');
        return undefined;
      }
      const consumed = this.toConsumedRecord(record, match);
      await client.query(
        `UPDATE "${collectionName(this.config)}" SET data = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
        [match.id, JSON.stringify(consumed)],
      );
      await client.query('COMMIT');
      return consumed;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
      await pool.end();
    }
  }

  private matchesAvailableRecord(
    record: HostActivationRecord,
    match: {
      domain: string;
      networkKind: IcaNetworkKind;
      nowIso: string;
      approval: HostActivationApproval;
    },
  ): boolean {
    const storedApproval = normalizeApproval(record.approval, record.domain);
    return record.status === 'available'
      && record.domain === match.domain
      && record.networkKind === match.networkKind
      && JSON.stringify(storedApproval) === JSON.stringify(match.approval)
      && Date.parse(record.expiresAt) >= Date.parse(match.nowIso);
  }

  private toConsumedRecord(
    record: HostActivationRecord,
    match: { nowIso: string; thid: string },
  ): HostActivationRecord {
    return {
      ...record,
      status: 'consumed',
      consumedAt: match.nowIso,
      consumedByThid: match.thid,
    };
  }

  private async ensurePostgresTable(client: { query: (sql: string, params?: unknown[]) => Promise<unknown> }): Promise<void> {
    await client.query(`
      CREATE TABLE IF NOT EXISTS "${collectionName(this.config)}" (
        id VARCHAR(80) PRIMARY KEY,
        data JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }
}

/** Loads the activation store used by the running ICA process or its admin CLI. */
export function createHostActivationServiceFromEnv(): HostActivationService {
  const provider = String(process.env.DB_PROVIDER || 'mem').trim().toLowerCase();
  if (provider !== 'mem' && provider !== 'firestore' && provider !== 'postgres') {
    throw new Error('DB_PROVIDER must be mem, firestore or postgres.');
  }
  return new HostActivationService({
    provider,
    postgresUrl: String(process.env.POSTGRES_URL || '').trim() || undefined,
    firestoreProjectId: String(process.env.FIRESTORE_PROJECT_ID || '').trim() || undefined,
    collectionPrefix: String(process.env.ICA_COLLECTIONS_PREFIX || 'ica').trim(),
  });
}

export function resetHostActivationMemStateForTests(): void {
  hostActivationMemRecords.clear();
}
