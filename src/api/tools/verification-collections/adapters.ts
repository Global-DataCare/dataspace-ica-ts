import type {
  EvidenceRecord,
  IssuedCredentialRecord,
  VerificationCollectionsAdapter,
  VerificationCollectionsConfig,
} from './types.ts';

const memState = {
  issuedById: new Map<string, IssuedCredentialRecord>(),
  evidenceById: new Map<string, EvidenceRecord>(),
};

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

  async listIssuedCredentials(): Promise<IssuedCredentialRecord[]> {
    return Array.from(memState.issuedById.values())
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  async listEvidenceRecords(): Promise<EvidenceRecord[]> {
    return Array.from(memState.evidenceById.values())
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }
}

async function importFirestoreModuleDynamically(): Promise<any> {
  const dynamicImport = new Function('modulePath', 'return import(modulePath)') as (modulePath: string) => Promise<any>;
  return dynamicImport('@google-cloud/firestore');
}

export class VerificationCollectionsFirestoreAdapter implements VerificationCollectionsAdapter {
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
        const options: Record<string, unknown> = {};
        if (this.config.firestoreProjectId) options.projectId = this.config.firestoreProjectId;
        if (this.config.firestoreDatabaseId) options.databaseId = this.config.firestoreDatabaseId;
        return new FirestoreCtor(options);
      })();
    }
    return this.firestoreClientPromise;
  }

  async storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void> {
    if (!records.length) return;
    const client = await this.getClient();
    const batch = client.batch();
    for (const record of records) {
      const ref = client.collection(this.config.issuedCredentialsCollection).doc(record.id);
      batch.set(ref, record, { merge: true });
    }
    await batch.commit();
  }

  async storeEvidenceRecords(records: EvidenceRecord[]): Promise<void> {
    if (!records.length) return;
    const client = await this.getClient();
    const batch = client.batch();
    for (const record of records) {
      const ref = client.collection(this.config.evidenceCollection).doc(record.id);
      batch.set(ref, record, { merge: true });
    }
    await batch.commit();
  }

  async listIssuedCredentials(): Promise<IssuedCredentialRecord[]> {
    const client = await this.getClient();
    const snapshot = await client.collection(this.config.issuedCredentialsCollection).limit(200).get();
    return snapshot.docs.map((doc: any) => doc.data() as IssuedCredentialRecord);
  }

  async listEvidenceRecords(): Promise<EvidenceRecord[]> {
    const client = await this.getClient();
    const snapshot = await client.collection(this.config.evidenceCollection).limit(200).get();
    return snapshot.docs.map((doc: any) => doc.data() as EvidenceRecord);
  }
}

export function createVerificationCollectionsAdapter(
  config: VerificationCollectionsConfig,
): VerificationCollectionsAdapter {
  if (config.provider === 'firestore') {
    return new VerificationCollectionsFirestoreAdapter(config);
  }
  return new VerificationCollectionsMemAdapter();
}

export function resetVerificationCollectionsMemAdapterStateForTests(): void {
  memState.issuedById.clear();
  memState.evidenceById.clear();
}
