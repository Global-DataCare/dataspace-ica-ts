export type JsonObject = Record<string, unknown>;
export type DidBindingStatus = 'draft' | 'confirmed' | 'removed';
export type DidDocumentStatus = 'confirmed' | 'removed';

export type VerificationCollectionsProvider = 'mem' | 'firestore' | 'postgres';

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
  publicKeyJwk?: JsonObject;
  keySource?: 'attachment' | 'generated';
  originDataspaceDid?: string;
  dataspacePublications?: DataspacePublication[];
  contentHashSha3_384?: string;
  /**
   * Exact signed representations emitted at issuance. Both entries share
   * `credentialId`; they are not independent credentials or status records.
   */
  representations?: {
    vcJwt?: string;
  };
  createdAt: string;
  updatedAt: string;
};

export type DidBindingRecord = {
  id: string;
  tenantId: string;
  jurisdiction: string;
  sector: string;
  resourceType: string;
  thid: string;
  taxId: string;
  did?: string;
  controllerSameAs?: string;
  controllerPublicKeyJwk?: JsonObject;
  organizationPublicKeyJwk?: JsonObject;
  organizationKeySource?: 'attachment' | 'generated';
  status: DidBindingStatus;
  createdAt: string;
  updatedAt: string;
  confirmedAt?: string;
  removedAt?: string;
  removeReason?: string;
};

export type DidDocumentRecord = {
  id: string;
  tenantId: string;
  jurisdiction: string;
  sector: string;
  resourceType: string;
  thid: string;
  did: string;
  taxId?: string;
  controllerSameAs?: string;
  controllerPublicKeyJwk?: JsonObject;
  organizationPublicKeyJwk?: JsonObject;
  didDocument: JsonObject;
  status: DidDocumentStatus;
  createdAt: string;
  updatedAt: string;
  removedAt?: string;
  removeReason?: string;
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
  firestoreCollectionPrefix: string;
  postgresUrl?: string;
};

export interface VerificationCollectionsAdapter {
  storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void>;
  storeEvidenceRecords(records: EvidenceRecord[]): Promise<void>;
  storeDidBindings(records: DidBindingRecord[]): Promise<void>;
  storeDidDocuments(records: DidDocumentRecord[]): Promise<void>;
  listIssuedCredentials(): Promise<IssuedCredentialRecord[]>;
  listEvidenceRecords(): Promise<EvidenceRecord[]>;
  listDidBindings(): Promise<DidBindingRecord[]>;
  listDidDocuments(): Promise<DidDocumentRecord[]>;
}
