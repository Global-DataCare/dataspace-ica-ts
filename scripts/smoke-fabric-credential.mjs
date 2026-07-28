#!/usr/bin/env node

import assert from 'node:assert/strict';
import { CredentialLedgerService } from '../src/api/tools/credential-ledger.ts';

const credentialId = 'urn:dataspace-ica:local-network:credential-ledger-smoke:v1';
const subjectId = 'did:example:dataspace-ica-smoke-subject';
const vc = {
  id: credentialId,
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
  type: ['VerifiableCredential', 'OrganizationCredential', 'CredentialLedgerSmokeCredential'],
  issuer: 'did:example:dataspace-ica-smoke-issuer',
  validFrom: '2026-01-01T00:00:00.000Z',
  credentialStatus: {
    id: `${credentialId}#status`,
    type: 'SimpleCredentialStatus2026',
  },
  credentialSubject: {
    id: subjectId,
    '@type': 'Organization',
    legalName: 'ICA Fabric local smoke fixture',
  },
  evidence: [{
    type: 'document',
    time: '2026-01-01T00:00:00.000Z',
    verifier: { organization: 'did:example:dataspace-ica-smoke-issuer' },
    check_details: [{
      check_method: 'vdig',
      organization: 'did:example:dataspace-ica-smoke-issuer',
      time: '2026-01-01T00:00:00.000Z',
      txn: 'zLocalFabricCredentialSmokePdfCid',
    }],
  }],
};
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
  iss: vc.issuer,
  sub: subjectId,
  jti: credentialId,
  vc,
})}.`;

const service = new CredentialLedgerService();
assert.equal(service.config.enabled, true, 'Fabric credential ledger must be enabled for the smoke.');

const issued = await service.recordIssuedCredential(vc, jwt);
const active = await service.getCredential(credentialId);
assert.ok(active);
assert.equal(active.metadata.identity.vcId, credentialId);
assert.equal(active.metadata.identity.jwtJti, credentialId);
assert.equal(active.metadata.identity.subjectId, subjectId);
assert.equal(active.metadata.identity.jwtSub, subjectId);
assert.equal(active.metadata.representations.length, 2);

const revoked = await service.revokeCredential(credentialId, {
  timestamp: new Date().toISOString(),
  actor: vc.issuer,
  reason: 'local-network smoke',
});
const finalAsset = await service.getCredential(credentialId);
assert.equal(finalAsset?.status, 'revoked');

console.log(JSON.stringify({
  channel: service.config.channelName,
  chaincode: service.config.chaincodeName,
  credentialId,
  issuanceAction: issued.action,
  revocationAction: revoked.action,
  finalStatus: finalAsset?.status,
}, null, 2));
