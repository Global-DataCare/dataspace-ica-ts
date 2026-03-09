export type JsonObject = Record<string, unknown>;

export type VerificationCollectionsProvider = 'mem' | 'firestore';

export type DataspacePublicationStatus = 'origin' | 'pending' | 'synced' | 'failed';

export type DataspacePublication = {
  did: string;
  status: DataspacePublicationStatus;
  endpointUrl?: string;
  lastAttemptAt?: string;
  lastSuccessAt?: string;
  txId?: string;
  message?: string;
};

export type IssuedCredentialRecord = {
  id: string;
  tenantId: string;
  jurisdiction: string;
  sector: string;
  resourceType: string;
  thid: string;
  credentialType: string;
  credentialId: string;
  subjectId: string;
  issuerId: string;
  credential: JsonObject;
  originDataspaceDid?: string;
  dataspacePublications?: DataspacePublication[];
  contentHashSha3_384?: string;
  createdAt: string;
  updatedAt: string;
};

export type EvidenceRecord = {
  id: string;
  issuedCredentialRecordId: string;
  tenantId: string;
  jurisdiction: string;
  sector: string;
  resourceType: string;
  thid: string;
  evidenceType: string;
  evidence: JsonObject;
  originDataspaceDid?: string;
  dataspacePublications?: DataspacePublication[];
  contentHashSha3_384?: string;
  createdAt: string;
  updatedAt: string;
};

export type VerificationCollectionsConfig = {
  provider: VerificationCollectionsProvider;
  required: boolean;
  firestoreProjectId?: string;
  firestoreDatabaseId?: string;
  firestoreCollectionPrefix: string;
  issuedCredentialsCollection: string;
  evidenceCollection: string;
};

export interface VerificationCollectionsAdapter {
  storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void>;
  storeEvidenceRecords(records: EvidenceRecord[]): Promise<void>;
  listIssuedCredentials(): Promise<IssuedCredentialRecord[]>;
  listEvidenceRecords(): Promise<EvidenceRecord[]>;
}
