import type { IDecodedDidcommPayload } from 'gdc-common-utils-ts/models/confidential-message';

export type AllowedSector = 'animal-care' | 'health-care';

export type VerifyAction = '_verify' | '_verify-response';
export type ActivateAction = '_activate' | '_activate-response';
export type RotateAction = '_rotate' | '_rotate-response';
export type AddEvidenceAction = '_add' | '_add-response';
export type IssueCredentialAction = '_issue' | '_issue-response';
export type CredentialStatusAction = '_status' | '_status-response';
export type CredentialRevokeAction = '_revoke' | '_revoke-response';

export type VerifyJobStatus = 'queued' | 'running' | 'succeeded' | 'failed';
export type ActivateJobStatus = 'queued' | 'running' | 'succeeded' | 'failed';
export type EntityJobStatus = 'queued' | 'running' | 'succeeded' | 'failed';

export type RevocationStatus = 'good' | 'revoked' | 'unknown';

export type RevocationDebugStatus =
  | 'no_urls'
  | 'ok'
  | 'http_error'
  | 'timeout'
  | 'download_error'
  | 'parse_error'
  | 'revoked'
  | 'verify_error';

export interface RevocationDebugCheck {
  url?: string;
  phase: 'discovery' | 'download' | 'verify';
  status: RevocationDebugStatus;
  httpStatus?: number;
  message?: string;
}

export interface RevocationDebugInfo {
  finalStatus: RevocationStatus;
  checks: RevocationDebugCheck[];
}

export interface VerificationErrorDetails {
  revocation?: RevocationDebugInfo;
}

export interface VerifyRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'terms';
  format: 'pdf';
  resourceType: string;
  action: VerifyAction;
}

export interface ActivateRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'entity';
  format: 'keys';
  resourceType: 'credentials';
  action: ActivateAction;
}

export interface RotateRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'entity';
  format: 'keys';
  resourceType: 'credentials' | 'communications';
  action: RotateAction;
}

export interface AddEvidenceRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'network';
  format: 'evidence';
  evidenceType: string;
  action: AddEvidenceAction;
}

export interface IssueCredentialRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'network';
  format: 'credentials';
  credentialType: string;
  action: IssueCredentialAction;
}

export interface CredentialStatusRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'network';
  format: 'credentials';
  credentialType: string;
  action: CredentialStatusAction;
}

export interface CredentialRevokeRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'network';
  format: 'credentials';
  credentialType: string;
  action: CredentialRevokeAction;
}

export interface VerifySubmission {
  thid: string;
  pdfBytes: Buffer<ArrayBufferLike>;
  contentType: string;
}

export type SupportedSigningAlgorithm = 'ES384' | 'ES256K' | 'RS256' | 'PS256' | 'EdDSA';

export interface ActivateSigningKeyInput {
  kid?: string;
  alg: SupportedSigningAlgorithm;
  privateKeyPem: string;
  x5c?: string[];
  certificateChainPem?: string[];
}

export interface ActivateSigningKeySubmission {
  thid: string;
  keys: ActivateSigningKeyInput[];
}

export interface AddEvidenceSubmission {
  thid: string;
  evidence: Record<string, unknown>;
  issuedCredentialRecordId?: string;
  operatorDid?: string;
}

export interface IssueCredentialSubmission {
  thid: string;
  credential: Record<string, unknown>;
  evidence: Record<string, unknown>[];
}

export interface CredentialStatusSubmission {
  thid: string;
  issuedCredentialRecordId?: string;
  credentialId?: string;
  subjectId?: string;
}

export interface CredentialRevokeSubmission {
  thid: string;
  issuedCredentialRecordId?: string;
  credentialId?: string;
  subjectId?: string;
  reason?: string;
  revokedBy?: string;
}

export interface VerifyHashes {
  signedPdfSha256Hex: string;
  unsignedPdfSha256Hex: string;
  templateSha256Hex: string;
}

export interface VerifyDigest {
  alg: string;
  signedPdfHex: string;
  unsignedPdfHex: string;
  templateHex: string;
}

export type AuditStorageProvider = 'filesystem' | 'gcs';

export interface AuditDocumentReference {
  provider: AuditStorageProvider;
  objectId: string;
  objectKey: string;
  bucket?: string;
  attachmentUrl: string;
  contentType: string;
  sizeBytes: number;
  storedAt: string;
}

export interface VerifyResult {
  ok: boolean;
  verifiedAt: string;
  templateUrl: string;
  templateMatch: boolean;
  signatureValid: boolean;
  chainValid: boolean;
  revocationStatus: RevocationStatus;
  digest: VerifyDigest;
  signerCertificateSerialNumber: string;
  signerSubject: string;
  signerIssuer: string;
  hashes: VerifyHashes;
  notes: string[];
  revocationDebug?: RevocationDebugInfo;
  auditDocument?: AuditDocumentReference;
}

export interface VerificationJob {
  thid: string;
  route: VerifyRouteContext;
  status: VerifyJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: VerifyResult;
  error?: string;
  errorDetails?: VerificationErrorDetails;
}

export interface ActivateSigningKeyResultItem {
  kid: string;
  alg: SupportedSigningAlgorithm;
  activatedAt: string;
  assertionMethod: string;
  chainLength: number;
}

export interface ActivateSigningKeyResult {
  issuerDid: string;
  activated: ActivateSigningKeyResultItem[];
}

export interface ActivateSigningKeyJob {
  thid: string;
  route: ActivateRouteContext;
  status: ActivateJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: ActivateSigningKeyResult;
  error?: string;
}

export interface AddEvidenceResult {
  evidenceRecordId: string;
  evidenceType: string;
  issuedCredentialRecordId: string;
  linkedToCredential: boolean;
  storedAt: string;
  operatorDid?: string;
}

export interface AddEvidenceJob {
  thid: string;
  route: AddEvidenceRouteContext;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: AddEvidenceResult;
  error?: string;
}

export interface IssueCredentialResult {
  issuedCredentialRecordId: string;
  credentialId: string;
  credentialType: string;
  evidenceRecordIds: string[];
  storedAt: string;
}

export interface IssueCredentialJob {
  thid: string;
  route: IssueCredentialRouteContext;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: IssueCredentialResult;
  error?: string;
}

export interface CredentialStatusResult {
  status: RevocationStatus;
  checkedAt: string;
  issuedCredentialRecordId?: string;
  credentialId?: string;
  subjectId?: string;
  revokedAt?: string;
}

export interface CredentialStatusJob {
  thid: string;
  route: CredentialStatusRouteContext;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: CredentialStatusResult;
  error?: string;
}

export interface CredentialRevokeResult {
  status: 'revoked';
  revokedAt: string;
  issuedCredentialRecordId: string;
  credentialId: string;
  subjectId?: string;
  reason?: string;
  revokedBy?: string;
}

export interface CredentialRevokeJob {
  thid: string;
  route: CredentialRevokeRouteContext;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: CredentialRevokeResult;
  error?: string;
}

export interface PdfVerificationService {
  verify(route: VerifyRouteContext, submission: VerifySubmission): Promise<VerifyResult>;
}

export interface SignatureVerifierAdapter extends PdfVerificationService {
  readonly id: string;
  supports(route: VerifyRouteContext): boolean | Promise<boolean>;
}

export interface OperationOutcomeIssue {
  severity: 'information' | 'warning' | 'error' | 'fatal';
  code: string;
  diagnostics: string;
}

export interface OperationOutcomeResource {
  resourceType: 'OperationOutcome';
  issue: OperationOutcomeIssue[];
}

export interface VerifyBundleDataEntry {
  type: string;
  resource: unknown;
  response: {
    status: string;
    outcome: OperationOutcomeResource;
  };
}

export interface VerifyBundleResponse {
  resourceType: 'Bundle';
  type: 'batch-response';
  total: number;
  data: VerifyBundleDataEntry[];
  issues?: OperationOutcomeResource;
  result?: VerifyResult;
}

export type DidcommPlaintextMessage<TBody = unknown> =
  Omit<IDecodedDidcommPayload, 'body'> & { body: TBody };
