import type {
  DidBindingRecord,
  DidDocumentRecord,
  EvidenceRecord,
  IssuedCredentialRecord,
  VerificationCollectionsAdapter,
  VerificationCollectionsConfig,
} from './types.ts';
import {
  resolveDidBindingsCollectionName,
  resolveDidDocumentsCollectionName,
  resolveEvidenceCollectionName,
  resolveIssuedCredentialsCollectionName,
} from '../verification-collections-storage.ts';

const memState = {
  issuedById: new Map<string, IssuedCredentialRecord>(),
  evidenceById: new Map<string, EvidenceRecord>(),
  didBindingsById: new Map<string, DidBindingRecord>(),
  didDocumentsById: new Map<string, DidDocumentRecord>(),
};

function stripUndefinedDeep<T>(value: T): T {
  if (Array.isArray(value)) {
    return value
      .map((entry) => stripUndefinedDeep(entry))
      .filter((entry) => entry !== undefined) as T;
  }

  if (value && typeof value === 'object') {
    const sanitizedEntries = Object.entries(value)
      .filter(([, entryValue]) => entryValue !== undefined)
      .map(([key, entryValue]) => [key, stripUndefinedDeep(entryValue)]);
    return Object.fromEntries(sanitizedEntries) as T;
  }

  return value;
}

export class VerificationCollectionsMemAdapter implements VerificationCollectionsAdapter {
  async storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void> {
    for (const record of records) {
      memState.issuedById.set(record.id, { ...record });
    }
  }

  async storeEvidenceRecords(records: EvidenceRecord[]): Promise<void> {
    for (const record of records) {
      memState.evidenceById.set(record.id, { ...record });
    }
  }

  async storeDidBindings(records: DidBindingRecord[]): Promise<void> {
    for (const record of records) {
      memState.didBindingsById.set(record.id, { ...record });
    }
  }

  async storeDidDocuments(records: DidDocumentRecord[]): Promise<void> {
    for (const record of records) {
      memState.didDocumentsById.set(record.id, { ...record });
    }
  }

  async listIssuedCredentials(): Promise<IssuedCredentialRecord[]> {
    return Array.from(memState.issuedById.values())
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  async listEvidenceRecords(): Promise<EvidenceRecord[]> {
    return Array.from(memState.evidenceById.values())
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  async listDidBindings(): Promise<DidBindingRecord[]> {
    return Array.from(memState.didBindingsById.values())
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  async listDidDocuments(): Promise<DidDocumentRecord[]> {
    return Array.from(memState.didDocumentsById.values())
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }
}

async function importFirestoreModuleDynamically(): Promise<any> {
  const dynamicImport = new Function('modulePath', 'return import(modulePath)') as (modulePath: string) => Promise<any>;
  return dynamicImport('@google-cloud/firestore');
}

export class VerificationCollectionsFirestoreAdapter implements VerificationCollectionsAdapter {
  private static readonly LIST_PAGE_SIZE = 200;
  private firestoreClientPromise: Promise<any> | null = null;
  private readonly config: VerificationCollectionsConfig;

  constructor(config: VerificationCollectionsConfig) {
    this.config = config;
  }

  private async getClient(): Promise<any> {
    if (!this.firestoreClientPromise) {
      this.firestoreClientPromise = (async () => {
        const module = await importFirestoreModuleDynamically();
        const FirestoreCtor = module.Firestore;
        if (!FirestoreCtor) {
          throw new Error('Failed to load @google-cloud/firestore module.');
        }
        const options: Record<string, unknown> = {
          ignoreUndefinedProperties: true,
        };
        if (this.config.firestoreProjectId) options.projectId = this.config.firestoreProjectId;
        return new FirestoreCtor(options);
      })();
    }
    return this.firestoreClientPromise;
  }

  /**
   * Reads a complete Firestore collection in deterministic document-id pages.
   *
   * ICA callers resolve current credentials, DID bindings and discovery data
   * after loading the collection through this adapter. Returning an arbitrary
   * first page would make recently issued records disappear once a collection
   * exceeds the Firestore page size.
   */
  private async listCollectionRecords<T>(collectionName: string): Promise<T[]> {
    const client = await this.getClient();
    const collection = client.collection(collectionName);
    const records: T[] = [];
    let lastDocument: any;

    while (true) {
      let query = collection
        .orderBy('__name__')
        .limit(VerificationCollectionsFirestoreAdapter.LIST_PAGE_SIZE);
      if (lastDocument) {
        query = query.startAfter(lastDocument);
      }

      const snapshot = await query.get();
      records.push(...snapshot.docs.map((doc: any) => doc.data() as T));

      if (snapshot.docs.length < VerificationCollectionsFirestoreAdapter.LIST_PAGE_SIZE) {
        break;
      }
      lastDocument = snapshot.docs[snapshot.docs.length - 1];
    }

    return records;
  }

  async storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void> {
    if (!records.length) return;
    const client = await this.getClient();
    const batch = client.batch();
    const collectionName = resolveIssuedCredentialsCollectionName(this.config.firestoreCollectionPrefix);
    for (const record of records) {
      const ref = client.collection(collectionName).doc(record.id);
      batch.set(ref, stripUndefinedDeep(record), { merge: true });
    }
    await batch.commit();
  }

  async storeEvidenceRecords(records: EvidenceRecord[]): Promise<void> {
    if (!records.length) return;
    const client = await this.getClient();
    const batch = client.batch();
    const collectionName = resolveEvidenceCollectionName(this.config.firestoreCollectionPrefix);
    for (const record of records) {
      const ref = client.collection(collectionName).doc(record.id);
      batch.set(ref, stripUndefinedDeep(record), { merge: true });
    }
    await batch.commit();
  }

  async storeDidBindings(records: DidBindingRecord[]): Promise<void> {
    if (!records.length) return;
    const client = await this.getClient();
    const batch = client.batch();
    const collectionName = resolveDidBindingsCollectionName(this.config.firestoreCollectionPrefix);
    for (const record of records) {
      const ref = client.collection(collectionName).doc(record.id);
      batch.set(ref, stripUndefinedDeep(record), { merge: true });
    }
    await batch.commit();
  }

  async storeDidDocuments(records: DidDocumentRecord[]): Promise<void> {
    if (!records.length) return;
    const client = await this.getClient();
    const batch = client.batch();
    const collectionName = resolveDidDocumentsCollectionName(this.config.firestoreCollectionPrefix);
    for (const record of records) {
      const ref = client.collection(collectionName).doc(record.id);
      batch.set(ref, stripUndefinedDeep(record), { merge: true });
    }
    await batch.commit();
  }

  async listIssuedCredentials(): Promise<IssuedCredentialRecord[]> {
    return this.listCollectionRecords<IssuedCredentialRecord>(
      resolveIssuedCredentialsCollectionName(this.config.firestoreCollectionPrefix),
    );
  }

  async listEvidenceRecords(): Promise<EvidenceRecord[]> {
    return this.listCollectionRecords<EvidenceRecord>(
      resolveEvidenceCollectionName(this.config.firestoreCollectionPrefix),
    );
  }

  async listDidBindings(): Promise<DidBindingRecord[]> {
    return this.listCollectionRecords<DidBindingRecord>(
      resolveDidBindingsCollectionName(this.config.firestoreCollectionPrefix),
    );
  }

  async listDidDocuments(): Promise<DidDocumentRecord[]> {
    return this.listCollectionRecords<DidDocumentRecord>(
      resolveDidDocumentsCollectionName(this.config.firestoreCollectionPrefix),
    );
  }
}

async function importPgModuleDynamically(): Promise<any> {
  const dynamicImport = new Function('modulePath', 'return import(modulePath)') as (modulePath: string) => Promise<any>;
  return dynamicImport('pg');
}

export class VerificationCollectionsPostgresAdapter implements VerificationCollectionsAdapter {
  private poolPromise: Promise<any> | null = null;
  private readonly config: VerificationCollectionsConfig;
  private tablesCreated = false;

  constructor(config: VerificationCollectionsConfig) {
    this.config = config;
  }

  private async getPool(): Promise<any> {
    if (!this.poolPromise) {
      this.poolPromise = (async () => {
        if (!this.config.postgresUrl) {
          throw new Error('DB_PROVIDER=postgres requires POSTGRES_URL.');
        }
        const pg = await importPgModuleDynamically();
        const Pool = pg.Pool || pg.default.Pool;
        return new Pool({ connectionString: this.config.postgresUrl });
      })();
    }
    return this.poolPromise;
  }
  
  private async ensureTables(pool: any): Promise<void> {
    if (this.tablesCreated) return;
    const issuedTable = resolveIssuedCredentialsCollectionName(this.config.firestoreCollectionPrefix);
    const evidenceTable = resolveEvidenceCollectionName(this.config.firestoreCollectionPrefix);
    const bindingsTable = resolveDidBindingsCollectionName(this.config.firestoreCollectionPrefix);
    const documentsTable = resolveDidDocumentsCollectionName(this.config.firestoreCollectionPrefix);
    
    const query = `
      CREATE TABLE IF NOT EXISTS "${issuedTable}" (id VARCHAR(255) PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE IF NOT EXISTS "${evidenceTable}" (id VARCHAR(255) PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE IF NOT EXISTS "${bindingsTable}" (id VARCHAR(255) PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE IF NOT EXISTS "${documentsTable}" (id VARCHAR(255) PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    `;
    await pool.query(query);
    this.tablesCreated = true;
  }

  private async upsertRecords(table: string, records: any[]): Promise<void> {
    if (!records.length) return;
    const pool = await this.getPool();
    await this.ensureTables(pool);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const query = `INSERT INTO "${table}" (id, data) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`;
      for (const record of records) {
        await client.query(query, [record.id, JSON.stringify(stripUndefinedDeep(record))]);
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void> {
    await this.upsertRecords(resolveIssuedCredentialsCollectionName(this.config.firestoreCollectionPrefix), records);
  }

  async storeEvidenceRecords(records: EvidenceRecord[]): Promise<void> {
    await this.upsertRecords(resolveEvidenceCollectionName(this.config.firestoreCollectionPrefix), records);
  }

  async storeDidBindings(records: DidBindingRecord[]): Promise<void> {
    await this.upsertRecords(resolveDidBindingsCollectionName(this.config.firestoreCollectionPrefix), records);
  }

  async storeDidDocuments(records: DidDocumentRecord[]): Promise<void> {
    await this.upsertRecords(resolveDidDocumentsCollectionName(this.config.firestoreCollectionPrefix), records);
  }

  private async getList<T>(table: string): Promise<T[]> {
    const pool = await this.getPool();
    await this.ensureTables(pool);
    const { rows } = await pool.query(`SELECT data FROM "${table}" ORDER BY id`);
    return rows.map((r: any) => r.data as T);
  }

  /** Releases the PostgreSQL pool used by one migration or server process. */
  async close(): Promise<void> {
    if (!this.poolPromise) return;
    const pool = await this.poolPromise;
    await pool.end();
    this.poolPromise = null;
    this.tablesCreated = false;
  }

  async listIssuedCredentials(): Promise<IssuedCredentialRecord[]> {
    return this.getList<IssuedCredentialRecord>(resolveIssuedCredentialsCollectionName(this.config.firestoreCollectionPrefix));
  }

  async listEvidenceRecords(): Promise<EvidenceRecord[]> {
    return this.getList<EvidenceRecord>(resolveEvidenceCollectionName(this.config.firestoreCollectionPrefix));
  }

  async listDidBindings(): Promise<DidBindingRecord[]> {
    return this.getList<DidBindingRecord>(resolveDidBindingsCollectionName(this.config.firestoreCollectionPrefix));
  }

  async listDidDocuments(): Promise<DidDocumentRecord[]> {
    return this.getList<DidDocumentRecord>(resolveDidDocumentsCollectionName(this.config.firestoreCollectionPrefix));
  }
}

export function createVerificationCollectionsAdapter(
  config: VerificationCollectionsConfig,
): VerificationCollectionsAdapter {
  if (config.provider === 'postgres') {
    return new VerificationCollectionsPostgresAdapter(config);
  }
  if (config.provider === 'firestore') {
    return new VerificationCollectionsFirestoreAdapter(config);
  }
  return new VerificationCollectionsMemAdapter();
}

export function resetVerificationCollectionsMemAdapterStateForTests(): void {
  memState.issuedById.clear();
  memState.evidenceById.clear();
  memState.didBindingsById.clear();
  memState.didDocumentsById.clear();
}
