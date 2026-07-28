import { createHash, createPrivateKey } from 'node:crypto';
import * as grpc from '@grpc/grpc-js';
import {
  connect,
  signers,
  type Contract,
  type Gateway,
  type Identity,
} from '@hyperledger/fabric-gateway';
import type { DidcommAttachment, VerifyBundleResponse } from '../types.ts';

type JsonObject = Record<string, unknown>;
type Environment = Record<string, string | undefined>;

export type CredentialLedgerConfig = {
  enabled: boolean;
  required: boolean;
  networkMode: string;
  channelName: string;
  chaincodeName: string;
  mspId: string;
};

export type CredentialLedgerAsset = {
  id: string;
  status: 'active' | 'suspended' | 'revoked' | 'expired';
  issuedAt: string | number;
  updatedAt: string | number;
  issuer: string;
  subject: string;
  metadata: {
    credentialType: string[];
    identity: {
      vcId: string;
      jwtJti: string;
      subjectId: string;
      jwtSub: string;
    };
    logicalContentHash: { alg: 'sha3-384'; value: string };
    representations: Array<{
      format: 'vc+ld+json' | 'vc+jwt';
      hashAlg: 'sha3-384';
      hashValue: string;
    }>;
    evidenceRefs: Array<{
      type: string;
      documentTxn?: string;
      verifier?: string;
      verifiedAt?: string;
      issuer?: string;
      serialNumber?: string;
      createdAt?: string;
    }>;
  };
  updatedBy?: string;
  reason?: string;
};

export interface CredentialLedgerAdapter {
  read(id: string): Promise<CredentialLedgerAsset | undefined>;
  create(asset: CredentialLedgerAsset): Promise<{ asset: CredentialLedgerAsset; transactionId?: string }>;
  updateStatus(
    id: string,
    status: CredentialLedgerAsset['status'],
    input: { timestamp: string; actor?: string; reason?: string; metadata: CredentialLedgerAsset['metadata'] },
  ): Promise<{ asset: CredentialLedgerAsset; transactionId?: string }>;
}

export type CredentialLedgerWriteResult = {
  action: 'disabled' | 'created' | 'skipped' | 'updated';
  credentialId: string;
  transactionId?: string;
};

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  return ['true', '1', 'yes'].includes(value.trim().toLowerCase());
}

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : undefined;
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  const objectValue = asObject(value);
  if (!objectValue) return value;
  return Object.fromEntries(
    Object.keys(objectValue).sort().map((key) => [key, canonicalize(objectValue[key])]),
  );
}

function sha3_384(value: unknown): string {
  const bytes = typeof value === 'string'
    ? value
    : JSON.stringify(canonicalize(value));
  return createHash('sha3-384').update(bytes).digest('base64url');
}

function decodeJwtPayload(jwt: string): JsonObject {
  const parts = jwt.split('.');
  if (parts.length !== 3 || !parts[1]) throw new Error('VC-JWT must be a compact JWT.');
  const parsed = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as unknown;
  const payload = asObject(parsed);
  if (!payload) throw new Error('VC-JWT payload must be a JSON object.');
  return payload;
}

function logicalCredentialContent(vc: JsonObject): JsonObject {
  const content = { ...vc };
  delete content.proof;
  return content;
}

function extractEvidenceRefs(vc: JsonObject): CredentialLedgerAsset['metadata']['evidenceRefs'] {
  const evidence = Array.isArray(vc.evidence) ? vc.evidence : [];
  return evidence.flatMap((entry) => {
    const item = asObject(entry);
    if (!item) return [];
    const verifier = asObject(item.verifier);
    const checkDetails = Array.isArray(item.check_details) ? item.check_details : [];
    const documentTxn = checkDetails
      .map(asObject)
      .map((check) => asString(check?.txn))
      .find(Boolean);
    return [{
      type: asString(item.type) || 'unknown',
      ...(documentTxn ? { documentTxn } : {}),
      ...(asString(verifier?.organization) ? { verifier: asString(verifier?.organization) } : {}),
      ...(asString(item.time) ? { verifiedAt: asString(item.time) } : {}),
      ...(asString(item.issuer) ? { issuer: asString(item.issuer) } : {}),
      ...(asString(item.serial_number) ? { serialNumber: asString(item.serial_number) } : {}),
      ...(asString(item.created_at) ? { createdAt: asString(item.created_at) } : {}),
    }];
  });
}

/**
 * Builds the immutable on-ledger projection for one logical credential.
 *
 * Identity contract:
 * - JSON VC `id` equals VC-JWT `jti` and is the Fabric asset key.
 * - `credentialSubject.id` equals VC-JWT `sub` and identifies the subject only.
 * - JSON-LD and JWT are representations of the same credential, not separate
 *   revocation records.
 * - evidence `check_details[].txn` is a document CID/reference; it is never
 *   represented as the Fabric transaction id.
 */
export function buildCredentialLedgerProjection(vcInput: JsonObject, vcJwt: string): CredentialLedgerAsset {
  const vc = structuredClone(vcInput);
  const payload = decodeJwtPayload(vcJwt);
  const credentialId = asString(vc.id);
  const subject = asObject(vc.credentialSubject);
  const subjectId = asString(subject?.id);
  const jwtJti = asString(payload.jti);
  const jwtSub = asString(payload.sub);
  if (!credentialId) throw new Error('VC id is required for credential ledger registration.');
  if (jwtJti !== credentialId) throw new Error(`JWT jti must equal VC id (${credentialId}).`);
  if (jwtSub !== subjectId) throw new Error(`JWT sub must equal credentialSubject.id (${subjectId}).`);
  const embeddedVc = asObject(payload.vc);
  if (embeddedVc && asString(embeddedVc.id) !== credentialId) {
    throw new Error('JWT vc.id must equal top-level VC id.');
  }
  const types = Array.isArray(vc.type) ? vc.type.map(asString).filter(Boolean) : [];
  const issuedAt = asString(vc.validFrom || vc.issuanceDate) || new Date(0).toISOString();
  const logicalContent = logicalCredentialContent(vc);
  return {
    id: credentialId,
    status: 'active',
    issuedAt,
    updatedAt: issuedAt,
    issuer: asString(vc.issuer),
    subject: subjectId,
    metadata: {
      credentialType: types,
      identity: { vcId: credentialId, jwtJti, subjectId, jwtSub },
      logicalContentHash: { alg: 'sha3-384', value: sha3_384(logicalContent) },
      representations: [
        { format: 'vc+ld+json', hashAlg: 'sha3-384', hashValue: sha3_384(vc) },
        { format: 'vc+jwt', hashAlg: 'sha3-384', hashValue: sha3_384(vcJwt) },
      ],
      evidenceRefs: extractEvidenceRefs(vc),
    },
  };
}

/**
 * Resolves the explicit migration gate. `test` can never write Fabric,
 * `local-network` uses Fabric by definition, and remote network modes require
 * ICA_CREDENTIAL_LEDGER_ENABLED so an existing staging runtime cannot acquire
 * ledger side effects accidentally.
 */
export function loadCredentialLedgerConfigFromEnv(env: Environment = process.env): CredentialLedgerConfig {
  const networkMode = asString(env.NETWORK_MODE).toLowerCase() || 'test';
  const localNetwork = networkMode === 'local-network';
  const fabricCapable = localNetwork || networkMode === 'test-network' || networkMode === 'network';
  const explicitlyEnabled = parseBoolean(env.ICA_CREDENTIAL_LEDGER_ENABLED, false);
  const enabled = networkMode !== 'test' && fabricCapable && (localNetwork || explicitlyEnabled);
  return {
    enabled,
    required: parseBoolean(env.ICA_CREDENTIAL_LEDGER_REQUIRED, enabled),
    networkMode,
    channelName: asString(env.ICA_CREDENTIAL_LEDGER_CHANNEL)
      || (localNetwork ? 'identity-local' : 'identity-global'),
    chaincodeName: asString(env.ICA_CREDENTIAL_LEDGER_CHAINCODE) || 'credential-sc',
    mspId: asString(env.ICA_FABRIC_MSP_ID) || 'Org1MSP',
  };
}

function envPem(name: string, mspId: string): string {
  const value = process.env[name] || process.env[`${name}_${mspId}`] || '';
  return value.replace(/\\n/g, '\n').trim();
}

class FabricCredentialLedgerAdapter implements CredentialLedgerAdapter {
  private readonly config: CredentialLedgerConfig;

  constructor(config: CredentialLedgerConfig) {
    this.config = config;
  }

  private async withContract<T>(handler: (contract: Contract) => Promise<T>): Promise<T> {
    const peer = asString(process.env.HLF_CONNECTION_PEER || process.env[`HLF_CONNECTION_PEER_${this.config.mspId}`]);
    const tlsPem = envPem('HLF_CONNECTION_PEM', this.config.mspId);
    const certificatePem = envPem('HLF_CERTIFICATE', this.config.mspId);
    const privateKeyPem = envPem('HLF_PRIVATE_KEY', this.config.mspId);
    if (!peer || !tlsPem || !certificatePem || !privateKeyPem) {
      throw new Error('Fabric credential ledger requires HLF_CONNECTION_PEER, HLF_CONNECTION_PEM, HLF_CERTIFICATE and HLF_PRIVATE_KEY.');
    }
    const tlsServerName = asString(process.env.ICA_FABRIC_TLS_SERVER_NAME);
    const client = new grpc.Client(
      peer,
      grpc.credentials.createSsl(Buffer.from(tlsPem)),
      tlsServerName
        ? {
          'grpc.ssl_target_name_override': tlsServerName,
          'grpc.default_authority': tlsServerName,
        }
        : {},
    );
    const identity: Identity = { mspId: this.config.mspId, credentials: Buffer.from(certificatePem) };
    const gateway: Gateway = connect({
      client,
      identity,
      signer: signers.newPrivateKeySigner(createPrivateKey(privateKeyPem)),
      evaluateOptions: () => ({ deadline: Date.now() + 5_000 }),
      endorseOptions: () => ({ deadline: Date.now() + 15_000 }),
      submitOptions: () => ({ deadline: Date.now() + 5_000 }),
      commitStatusOptions: () => ({ deadline: Date.now() + 60_000 }),
    });
    try {
      return await handler(gateway.getNetwork(this.config.channelName).getContract(this.config.chaincodeName));
    } finally {
      gateway.close();
      client.close();
    }
  }

  private async submit(fn: string, args: string[]): Promise<{ asset: CredentialLedgerAsset; transactionId?: string }> {
    return this.withContract(async (contract) => {
      const proposal = contract.newProposal(fn, { arguments: args, endorsingOrganizations: [this.config.mspId] });
      const endorsed = await proposal.endorse();
      const submitted = await endorsed.submit();
      const status = await submitted.getStatus();
      if (!status.successful) throw new Error(`Fabric transaction ${status.transactionId} failed with code ${status.code}.`);
      return {
        asset: JSON.parse(Buffer.from(endorsed.getResult()).toString('utf8')) as CredentialLedgerAsset,
        transactionId: status.transactionId,
      };
    });
  }

  async read(id: string): Promise<CredentialLedgerAsset | undefined> {
    try {
      return await this.withContract(async (contract) => {
        const bytes = await contract.evaluateTransaction('readCredential', id);
        return JSON.parse(Buffer.from(bytes).toString('utf8')) as CredentialLedgerAsset;
      });
    } catch (error: unknown) {
      if ((error as Error).message.includes('does not exist')) return undefined;
      throw error;
    }
  }

  async create(asset: CredentialLedgerAsset) {
    return this.submit('CreateCredential', [asset.id, JSON.stringify(asset)]);
  }

  async updateStatus(
    id: string,
    status: CredentialLedgerAsset['status'],
    input: { timestamp: string; actor?: string; reason?: string; metadata: CredentialLedgerAsset['metadata'] },
  ) {
    return this.submit('UpdateCredentialStatus', [
      id,
      status,
      String(Math.floor(Date.parse(input.timestamp) / 1000)),
      input.actor || '',
      input.reason || '',
      JSON.stringify(input.metadata),
    ]);
  }
}

export class CredentialLedgerService {
  readonly config: CredentialLedgerConfig;
  private readonly adapter?: CredentialLedgerAdapter;

  constructor(options?: { config?: CredentialLedgerConfig; adapter?: CredentialLedgerAdapter }) {
    this.config = options?.config || loadCredentialLedgerConfigFromEnv();
    this.adapter = options?.adapter || (this.config.enabled ? new FabricCredentialLedgerAdapter(this.config) : undefined);
  }

  /**
   * Creates one Fabric asset for one logical credential or returns `skipped`
   * when the same deterministic id and logical hash are already anchored.
   */
  async recordIssuedCredential(vc: JsonObject, vcJwt: string): Promise<CredentialLedgerWriteResult> {
    const projection = buildCredentialLedgerProjection(vc, vcJwt);
    if (!this.config.enabled || !this.adapter) return { action: 'disabled', credentialId: projection.id };
    try {
      const existing = await this.adapter.read(projection.id);
      if (existing) {
        if (existing.metadata?.logicalContentHash?.value !== projection.metadata.logicalContentHash.value) {
          throw new Error(`Credential ${projection.id} already exists with a different logical content hash.`);
        }
        return { action: 'skipped', credentialId: projection.id };
      }
      const result = await this.adapter.create(projection);
      return { action: 'created', credentialId: projection.id, transactionId: result.transactionId };
    } catch (error: unknown) {
      if (this.config.required) throw error;
      console.error(`[credential-ledger] issuance anchor failed: ${(error as Error).message}`);
      return { action: 'disabled', credentialId: projection.id };
    }
  }

  /**
   * Registers every VC in a verification Bundle while pairing it with the
   * corresponding VC-JWT attachment by its shared credential id.
   */
  async recordIssuedBundle(bundle: VerifyBundleResponse, attachments: DidcommAttachment[]): Promise<CredentialLedgerWriteResult[]> {
    const jwtAttachments = attachments.filter((attachment) => attachment.format === 'vc+jwt');
    const results: CredentialLedgerWriteResult[] = [];
    for (const entry of bundle.data) {
      const vc = asObject(entry.resource);
      if (!vc || !Array.isArray(vc.type) || !vc.type.includes('VerifiableCredential')) continue;
      const credentialId = asString(vc.id);
      const matchingAttachment = jwtAttachments.find((attachment) => {
        const data = asObject(attachment.data?.json);
        return asString(data?.credentialId) === credentialId;
      });
      const jwtData = asObject(matchingAttachment?.data?.json);
      const jwt = asString(jwtData?.jwt);
      if (!jwt) throw new Error(`Missing VC-JWT representation for credential ${credentialId}.`);
      results.push(await this.recordIssuedCredential(vc, jwt));
    }
    return results;
  }

  async getCredential(id: string): Promise<CredentialLedgerAsset | undefined> {
    if (!this.config.enabled || !this.adapter) return undefined;
    try {
      return await this.adapter.read(id);
    } catch (error: unknown) {
      if (this.config.required) throw error;
      console.error(`[credential-ledger] status read failed: ${(error as Error).message}`);
      return undefined;
    }
  }

  /**
   * Revokes the logical credential keyed by `vc.id`/JWT `jti`; the status
   * therefore applies to every stored representation of that credential.
   */
  async revokeCredential(
    id: string,
    input: { timestamp: string; actor?: string; reason?: string },
  ): Promise<CredentialLedgerWriteResult> {
    if (!this.config.enabled || !this.adapter) return { action: 'disabled', credentialId: id };
    try {
      const existing = await this.adapter.read(id);
      if (!existing) throw new Error(`Credential ${id} is not registered in Fabric.`);
      if (existing.status === 'revoked') return { action: 'skipped', credentialId: id };
      const result = await this.adapter.updateStatus(id, 'revoked', {
        ...input,
        metadata: existing.metadata,
      });
      return { action: 'updated', credentialId: id, transactionId: result.transactionId };
    } catch (error: unknown) {
      if (this.config.required) throw error;
      console.error(`[credential-ledger] revocation update failed: ${(error as Error).message}`);
      return { action: 'disabled', credentialId: id };
    }
  }
}
