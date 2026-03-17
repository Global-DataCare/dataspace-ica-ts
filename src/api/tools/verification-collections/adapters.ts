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
    const client = await this.getClient();
    const snapshot = await client.collection(resolveIssuedCredentialsCollectionName(this.config.firestoreCollectionPrefix)).limit(200).get();
    return snapshot.docs.map((doc: any) => doc.data() as IssuedCredentialRecord);
  }

  async listEvidenceRecords(): Promise<EvidenceRecord[]> {
    const client = await this.getClient();
    const snapshot = await client.collection(resolveEvidenceCollectionName(this.config.firestoreCollectionPrefix)).limit(200).get();
    return snapshot.docs.map((doc: any) => doc.data() as EvidenceRecord);
  }

  async listDidBindings(): Promise<DidBindingRecord[]> {
    const client = await this.getClient();
    const snapshot = await client.collection(resolveDidBindingsCollectionName(this.config.firestoreCollectionPrefix)).limit(200).get();
    return snapshot.docs.map((doc: any) => doc.data() as DidBindingRecord);
  }

  async listDidDocuments(): Promise<DidDocumentRecord[]> {
    const client = await this.getClient();
    const snapshot = await client.collection(resolveDidDocumentsCollectionName(this.config.firestoreCollectionPrefix)).limit(200).get();
    return snapshot.docs.map((doc: any) => doc.data() as DidDocumentRecord);
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
  memState.didBindingsById.clear();
  memState.didDocumentsById.clear();
}
