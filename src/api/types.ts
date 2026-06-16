import type { IDecodedDidcommPayload } from 'gdc-common-utils-ts/models/confidential-message';

export type AllowedSector = string;

export type VerifyAction = '_verify' | '_verify-response';
export type TermsRemoveAction = '_remove' | '_remove-response';
export type ActivateAction = '_activate' | '_activate-response';
export type RotateAction = '_rotate' | '_rotate-response';
export type CreateDidDocumentAction = '_create' | '_create-response';
export type AddEvidenceAction = '_add' | '_add-response';
export type DelegationPolicyAction = '_upsert' | '_upsert-response';
export type IssueCredentialAction = '_issue' | '_issue-response';
export type CredentialStatusAction = '_status' | '_status-response';
export type CredentialRevokeAction = '_revoke' | '_revoke-response';
export type CredentialSearchAction = '_search' | '_search-response';
export type CredentialRetrieveAction = '_retrieve' | '_retrieve-response';
export type SpacesAction = '_list' | '_replace';
export type DcatCatalogAction = 'request' | 'dataset';
export type DcatCatalogDdoAction = 'ddo-request' | 'ddo-dataset';
export type ControllerExchangeAction = '_exchange' | '_exchange-response';
export type ApiKeyProvisioningAction =
  | '_create'
  | '_create-response'
  | '_disable'
  | '_disable-response'
  | '_remove'
  | '_remove-response'
  | '_search'
  | '_search-response';
export type IdentityAuthAction =
  | '_dcr'
  | '_dcr-response'
  | '_code'
  | '_code-response'
  | '_token'
  | '_token-response'
  | '_exchange'
  | '_exchange-response';

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

export interface AnnexExtractionDebugInfo {
  fieldCount: number;
  fieldKeys: string[];
  warningCount: number;
  warnings: string[];
  hasOrganizationTaxId: boolean;
  hasOrganizationLegalName: boolean;
  organizationTaxId?: string;
  organizationLegalName?: string;
  personName?: string;
}

export interface VerificationErrorDetails {
  revocation?: RevocationDebugInfo;
  annex?: AnnexExtractionDebugInfo;
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

export type TemplateMatchMode = 'strict-bytes' | 'logical-content';

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
  knownRootCertUrls: string[];
  knownIntermediateCertUrls: string[];
  templateUrlPattern: string;
  strictRevocation: boolean;
  strictTemplateMatch: boolean;
  templateMatchMode: TemplateMatchMode;
  verifierVatList: string[];
  allowVerificationPartners: boolean;
  verificationPartnersVatList: string[];
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

export interface TermsRemoveRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'terms';
  format: 'pdf';
  resourceType: string;
  action: TermsRemoveAction;
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

export interface CreateDidDocumentRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'entity';
  format: 'did';
  resourceType: 'document';
  action: CreateDidDocumentAction;
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

export interface DelegationPolicyRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'network';
  format: 'policies';
  policyType: 'delegations';
  action: DelegationPolicyAction;
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

export interface CredentialSearchRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'network';
  format: 'credentials';
  credentialType: string;
  action: CredentialSearchAction;
}

export interface CredentialRetrieveRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'network';
  format: 'credentials';
  credentialType: string;
  action: CredentialRetrieveAction;
}

export interface SpacesRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'network';
  format: 'spaces';
  action: SpacesAction;
}

export interface DcatCatalogRequestRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'dcat3';
  format: 'catalog';
  action: 'request';
}

export interface DcatCatalogDatasetRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'dcat3';
  format: 'catalog';
  action: 'dataset';
  datasetId: string;
}

export interface DcatCatalogDdoRequestRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'dcat3';
  format: 'catalog-ddo';
  action: 'ddo-request';
}

export interface DcatCatalogDdoDatasetRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'dcat3';
  format: 'catalog-ddo';
  action: 'ddo-dataset';
  datasetId: string;
}

export interface ControllerExchangeRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'organization';
  format: 'dataspace-auth';
  action: ControllerExchangeAction;
}

export interface ApiKeyProvisioningRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'api-key';
  format: 'org.schema.action';
  action: ApiKeyProvisioningAction;
}

export interface IdentityAuthRouteContext {
  tenantId: string;
  jurisdiction: string;
  sector: AllowedSector;
  section: 'identity';
  format: 'auth';
  action: IdentityAuthAction;
}

export interface VerifySubmission {
  thid: string;
  pdfBytes: Buffer<ArrayBufferLike>;
  contentType: string;
  annexFormFields?: Record<string, string>;
  annexExtractionWarnings?: string[];
  controllerPublicKeyJwk?: Record<string, unknown>;
  organizationPublicKeyJwk?: Record<string, unknown>;
  /**
   * Optional compatibility payload used only for identity fields that are not
   * available in the signed PDF/certificate path.
   */
  organizationPayload?: Record<string, unknown>;
  /**
   * Optional representative identity payload.
   *
   * Security policy:
   * - strict/compat modes must source representative `sameAs` from the signed
   *   PDF annex or signer certificate email
    * - demo mode may additionally accept `sameAs` or `email` from this payload
    *   as a bootstrap convenience for local flows
   * - representative signing-key continuity is independent of that email
   *   alias and is projected separately from `controllerPublicKeyJwk` into the
   *   resulting person VC as `credentialSubject.hasCredential.material`
   */
  legalRepresentativePayload?: Record<string, unknown>;
}

export interface TermsRemoveInput {
  organization: {
    taxID?: string;
    identifier?: string;
  };
  controller: {
    sameAs?: string;
    publicKeyJwk?: Record<string, unknown>;
  };
  reason?: string;
}

export interface TermsRemoveSubmission {
  thid: string;
  items: TermsRemoveInput[];
}

export type SupportedSigningAlgorithm = 'ES384' | 'ES256K' | 'RS256' | 'PS256' | 'EdDSA';

export interface ActivateSigningKeyInput {
  kid?: string;
  alg: SupportedSigningAlgorithm;
  privateKeyPem: string;
  x5c?: string[];
  certificateChainPem?: string[];
}

export interface ControllerDidcommProof {
  jws: string;
  kid?: string;
  alg?: string;
}

export interface ActivateSigningKeySubmission {
  thid: string;
  jti?: string;
  keys: ActivateSigningKeyInput[];
  controllerProof?: ControllerDidcommProof;
  controllerAuthorizationPayloadBase64Url?: string;
}

export interface RotateSubmission {
  thid: string;
  jti?: string;
  controllerProof?: ControllerDidcommProof;
  controllerAuthorizationPayloadBase64Url?: string;
}

export interface CreateDidDocumentJwkSet {
  keys: Array<Record<string, unknown> & { purposes?: string[] }>;
}

export interface CreateDidDocumentControllerInput {
  sameAs?: string;
  alg?: SupportedSigningAlgorithm;
  publicKeyJwk?: Record<string, unknown>;
  jwks?: CreateDidDocumentJwkSet;
}

export interface CreateDidDocumentOrganizationInput {
  identifier?: string;
  taxID?: string;
  legalName?: string;
  sameAs?: string;
  url?: string;
  alternateName?: string;
  additionalType?: string;
  alg?: SupportedSigningAlgorithm;
  publicKeyJwk?: Record<string, unknown>;
  jwks?: CreateDidDocumentJwkSet;
}

export interface CreateDidDocumentInput {
  id?: string;
  controller: CreateDidDocumentControllerInput;
  organization: CreateDidDocumentOrganizationInput;
}

export interface CreateDidDocumentSubmission {
  thid: string;
  jti?: string;
  items: CreateDidDocumentInput[];
}

export interface AddEvidenceSubmission {
  thid: string;
  evidences: AddEvidenceInput[];
}

export interface AddEvidenceInput {
  evidence: Record<string, unknown>;
  issuedCredentialRecordId?: string;
  operatorDid?: string;
  source?: 'body' | 'didcomm-vc+jwt';
  attachmentId?: string;
  vcJwtIssuer?: string;
  vcJwtKid?: string;
  vcJwtAlg?: SupportedSigningAlgorithm;
  vcJwtCredentialId?: string;
}

export interface DelegationPolicySubmission {
  thid: string;
  policies: DelegationPolicyInput[];
}

export interface DelegationPolicyInput {
  resource: Record<string, unknown>;
}

export interface IssueCredentialSubmission {
  thid: string;
  items: IssueCredentialInput[];
}

export interface IssueCredentialInput {
  credential: Record<string, unknown>;
  evidence: Record<string, unknown>[];
}

export interface CredentialStatusSubmission {
  thid: string;
  lookups: CredentialLookupInput[];
}

export interface CredentialRevokeSubmission {
  thid: string;
  items: CredentialRevokeInput[];
}

export interface CredentialSearchSubmission {
  thid: string;
  queries: CredentialSearchInput[];
}

export interface SpacesListSubmission {
  thid: string;
}

export interface SpacesTargetInput {
  name?: string;
  did: string;
  endpointUrl?: string;
  apiKey?: string;
}

export interface SpacesReplaceSubmission {
  thid: string;
  targets: SpacesTargetInput[];
}

export interface CredentialLookupInput {
  issuedCredentialRecordId?: string;
  credentialId?: string;
  subjectId?: string;
  credentialStatusId?: string;
}

export interface CredentialRevokeInput extends CredentialLookupInput {
  reason?: string;
  revokedBy?: string;
}

export interface CredentialSearchInput {
  id?: string;
  text?: string;
  email?: string;
  taxId?: string;
  taxIdHash?: string;
  legalName?: string;
  subjectId?: string;
  issuerId?: string;
  credentialId?: string;
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
  encryptionKeyId?: string;
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
  signerCertificateSerialNumber?: string;
  signerSubject?: string;
  signerIssuer?: string;
  signerSigningTime?: string;
  organizationSigningTime?: string;
  personSigningTime?: string;
  verifierVatId?: string;
  verifierSigningTime?: string;
  hashes: VerifyHashes;
  notes: string[];
  annexFormFields?: Record<string, string>;
  revocationDebug?: RevocationDebugInfo;
  auditDocument?: AuditDocumentReference;
  controllerPublicKeyJwk?: Record<string, unknown>;
  organizationPublicKeyJwk?: Record<string, unknown>;
  organizationPrivateKeyJwk?: Record<string, unknown>;
  organizationKeySource?: 'attachment' | 'generated';
  /**
   * Optional compatibility payload retained in the async verification result.
   */
  organizationPayload?: Record<string, unknown>;
  /**
   * Optional representative identity payload retained in the async
   * verification result. Downstream VC mapping may use it only in demo mode
   * when the signed sources do not expose representative `sameAs`.
   *
   * The resulting VC may still project controller signing-key continuity
   * independently via `credentialSubject.hasCredential.material` derived from
   * `controllerPublicKeyJwk`.
   */
  legalRepresentativePayload?: Record<string, unknown>;
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
  evidenceType: string;
  storedCount: number;
  items: AddEvidenceResultItem[];
}

export interface AddEvidenceResultItem {
  evidenceRecordId: string;
  evidenceType: string;
  issuedCredentialRecordId: string;
  linkedToCredential: boolean;
  storedAt: string;
  operatorDid?: string;
  source?: 'body' | 'didcomm-vc+jwt';
  attachmentId?: string;
  vcJwtIssuer?: string;
  vcJwtKid?: string;
  vcJwtAlg?: SupportedSigningAlgorithm;
  vcJwtCredentialId?: string;
}

export interface DelegationPolicyUpsertResult {
  upsertedCount: number;
  items: DelegationPolicyUpsertResultItem[];
}

export interface DelegationPolicyUpsertResultItem {
  policyId: string;
  assigneeDid: string;
  roleIdentifier: string;
  upsertedAt: string;
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
  storedCount: number;
  items: IssueCredentialResultItem[];
}

export interface IssueCredentialResultItem {
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
  resolvedCount: number;
  items: CredentialStatusResultItem[];
}

export interface CredentialStatusResultItem {
  status: RevocationStatus;
  checkedAt: string;
  issuedCredentialRecordId?: string;
  credentialId?: string;
  subjectId?: string;
  credentialStatusId?: string;
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
  revokedCount: number;
  items: CredentialRevokeResultItem[];
}

export interface CredentialRevokeResultItem {
  status: 'revoked';
  revokedAt: string;
  issuedCredentialRecordId: string;
  credentialId: string;
  subjectId?: string;
  credentialStatusId?: string;
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

export interface CredentialSearchResult {
  matchedCount: number;
  items: CredentialSearchResultItem[];
}

export interface CredentialRetrieveResult {
  matchedCount: number;
  format: 'vc+json' | 'vc+jwt';
  item?: CredentialRetrieveResultItem;
}

export interface CreateDidDocumentResult {
  createdCount: number;
  items: CreateDidDocumentResultItem[];
}

export interface CreateDidDocumentResultItem {
  did: string;
  verificationMethod: string;
  nodeOperator: string;
  createdAt: string;
  controllerSameAs?: string;
  organizationTaxId?: string;
  organizationLegalName?: string;
  didDocument: Record<string, unknown>;
}

export interface CredentialSearchResultItem {
  issuedCredentialRecordId: string;
  credentialId: string;
  credentialType: string;
  subjectId: string;
  issuerId: string;
  legalName?: string;
  taxId?: string;
  taxIdHash?: string;
  organizationDid?: string;
  credential: Record<string, unknown>;
}

export interface CredentialRetrieveResultItem {
  issuedCredentialRecordId: string;
  credentialId: string;
  credentialType: string;
  subjectId: string;
  issuerId: string;
  legalName?: string;
  taxId?: string;
  taxIdHash?: string;
  organizationDid?: string;
  credential: Record<string, unknown>;
  vcJwt?: string;
}

export interface CredentialSearchJob {
  thid: string;
  route: CredentialSearchRouteContext;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: CredentialSearchResult;
  error?: string;
}

export interface CredentialRetrieveJob {
  thid: string;
  route: CredentialRetrieveRouteContext;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: CredentialRetrieveResult;
  error?: string;
}

export interface CreateDidDocumentJob {
  thid: string;
  route: CreateDidDocumentRouteContext;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: CreateDidDocumentResult;
  error?: string;
}

export interface TermsRemoveResult {
  removedCount: number;
  items: TermsRemoveResultItem[];
}

export interface TermsRemoveResultItem {
  organizationTaxId?: string;
  did: string;
  removedAt: string;
  reason?: string;
  effects: {
    didBindings: 'removed';
    didDocument: 'removed';
    catalogMembership: 'removed';
    organizationKeys: 'revoked';
  };
}

export interface TermsRemoveJob {
  thid: string;
  route: TermsRemoveRouteContext;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: TermsRemoveResult;
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
  publicKeyJwk?: Record<string, unknown>;
  privateKeyJwk?: Record<string, unknown>;
  keySource?: 'attachment' | 'generated';
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
}

export interface DidcommAttachmentData {
  base64?: string;
  json?: unknown;
  links?: string[];
}

export interface DidcommAttachment {
  id: string;
  media_type?: string;
  format?: string;
  filename?: string;
  data: DidcommAttachmentData;
}

export type DidcommPlaintextMessage<TBody = unknown> =
  Omit<IDecodedDidcommPayload, 'body'> & { body: TBody; attachments?: DidcommAttachment[] };
