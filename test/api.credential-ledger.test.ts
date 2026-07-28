import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CredentialLedgerService,
  buildCredentialLedgerProjection,
  loadCredentialLedgerConfigFromEnv,
  type CredentialLedgerAdapter,
  type CredentialLedgerAsset,
} from '../src/api/tools/credential-ledger.ts';

/**
 * Flow contract: credential issuance anchors one immutable asset per logical
 * VC, pairs its exact JSON and JWT representations by credential id regardless
 * of DIDComm attachment order, and keeps legacy test mode free of Fabric side
 * effects. Status changes address the credential id, never its subject id.
 */

function compactJwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.`;
}

const organizationVc = {
  id: 'urn:example:organization:vc:pdf-cid',
  type: ['VerifiableCredential', 'OrganizationCredential'],
  issuer: 'did:web:ica.example',
  validFrom: '2026-03-30T09:06:30.000Z',
  credentialStatus: {
    id: 'urn:example:organization:vc:pdf-cid#status',
    type: 'SimpleCredentialStatus2026',
  },
  credentialSubject: { id: 'did:web:organization.example' },
  evidence: [{
    type: 'document',
    verifier: { organization: 'did:web:verifier.example' },
    check_details: [{ check_method: 'vdig', txn: 'zPdfCid', time: '2026-03-30T09:06:30.000Z' }],
  }],
  proof: { type: 'JsonWebSignature2020', jws: 'proof-value' },
};

test('credential ledger config keeps NETWORK_MODE=test isolated from Fabric', () => {
  assert.equal(loadCredentialLedgerConfigFromEnv({
    NETWORK_MODE: 'test',
    ICA_CREDENTIAL_LEDGER_ENABLED: 'true',
  }).enabled, false);
  assert.deepEqual(
    loadCredentialLedgerConfigFromEnv({ NETWORK_MODE: 'local-network' }),
    {
      enabled: true,
      required: true,
      networkMode: 'local-network',
      channelName: 'identity-local',
      chaincodeName: 'credential-sc',
      mspId: 'Org1MSP',
    },
  );
  assert.equal(loadCredentialLedgerConfigFromEnv({
    NETWORK_MODE: 'test-network',
    ICA_CREDENTIAL_LEDGER_ENABLED: 'true',
  }).channelName, 'identity-global');
  assert.equal(loadCredentialLedgerConfigFromEnv({
    NETWORK_MODE: 'test-network',
  }).enabled, false);
});

test('projection uses vc.id/jti as credential identity and credentialSubject.id/sub only as subject', () => {
  const jwt = compactJwt({
    iss: organizationVc.issuer,
    sub: organizationVc.credentialSubject.id,
    jti: organizationVc.id,
    vc: { ...organizationVc, proof: undefined },
  });
  const projection = buildCredentialLedgerProjection(organizationVc, jwt);

  assert.equal(projection.id, organizationVc.id);
  assert.equal(projection.subject, organizationVc.credentialSubject.id);
  assert.equal(projection.metadata.identity.jwtJti, organizationVc.id);
  assert.equal(projection.metadata.identity.jwtSub, organizationVc.credentialSubject.id);
  assert.equal(projection.metadata.representations.length, 2);
  assert.equal(projection.metadata.evidenceRefs[0]?.documentTxn, 'zPdfCid');
});

test('projection rejects a JWT whose jti is the subject instead of vc.id', () => {
  const jwt = compactJwt({
    sub: organizationVc.credentialSubject.id,
    jti: organizationVc.credentialSubject.id,
    vc: organizationVc,
  });
  assert.throws(
    () => buildCredentialLedgerProjection(organizationVc, jwt),
    /JWT jti must equal VC id/,
  );
});

test('service skips an already anchored identical credential and rejects same id with different content', async () => {
  const assets = new Map<string, CredentialLedgerAsset>();
  let creates = 0;
  const adapter: CredentialLedgerAdapter = {
    async read(id) { return assets.get(id); },
    async create(asset) { creates += 1; assets.set(asset.id, asset); return { asset, transactionId: 'tx-create' }; },
    async updateStatus() { throw new Error('not used'); },
  };
  const service = new CredentialLedgerService({
    config: {
      enabled: true,
      required: true,
      networkMode: 'local-network',
      channelName: 'identity-local',
      chaincodeName: 'credential-sc',
      mspId: 'Org1MSP',
    },
    adapter,
  });
  const jwt = compactJwt({ sub: organizationVc.credentialSubject.id, jti: organizationVc.id, vc: organizationVc });

  assert.equal((await service.recordIssuedCredential(organizationVc, jwt)).action, 'created');
  assert.equal((await service.recordIssuedCredential(organizationVc, jwt)).action, 'skipped');
  assert.equal(creates, 1);

  assert.rejects(
    () => service.recordIssuedCredential({
      ...organizationVc,
      credentialSubject: { id: organizationVc.credentialSubject.id, legalName: 'ALTERED' },
    }, jwt),
    /different logical content hash/,
  );
});

test('bundle registration pairs VC-JWT attachments by credential id instead of array order', async () => {
  const secondVc = {
    ...organizationVc,
    id: 'urn:example:representative:vc:pdf-cid',
    type: ['VerifiableCredential', 'LegalRepresentativeCredential'],
    credentialSubject: { id: 'urn:example:person:representative' },
  };
  const firstJwt = compactJwt({
    sub: organizationVc.credentialSubject.id,
    jti: organizationVc.id,
    vc: organizationVc,
  });
  const secondJwt = compactJwt({
    sub: secondVc.credentialSubject.id,
    jti: secondVc.id,
    vc: secondVc,
  });
  const created: CredentialLedgerAsset[] = [];
  const adapter: CredentialLedgerAdapter = {
    async read() { return undefined; },
    async create(asset) { created.push(asset); return { asset }; },
    async updateStatus() { throw new Error('not used'); },
  };
  const service = new CredentialLedgerService({
    config: {
      enabled: true,
      required: true,
      networkMode: 'local-network',
      channelName: 'identity-local',
      chaincodeName: 'credential-sc',
      mspId: 'Org1MSP',
    },
    adapter,
  });

  await service.recordIssuedBundle(
    {
      resourceType: 'Bundle',
      type: 'batch-response',
      total: 2,
      data: [organizationVc, secondVc].map((resource) => ({
        type: 'POST',
        resource,
        response: {
          status: '201 Created',
          outcome: { resourceType: 'OperationOutcome', issue: [] },
        },
      })),
    },
    [
      { id: 'attachment-2', format: 'vc+jwt', data: { json: { credentialId: secondVc.id, jwt: secondJwt } } },
      { id: 'attachment-1', format: 'vc+jwt', data: { json: { credentialId: organizationVc.id, jwt: firstJwt } } },
    ],
  );

  assert.deepEqual(created.map((asset) => asset.id), [organizationVc.id, secondVc.id]);
});
