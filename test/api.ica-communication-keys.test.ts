import assert from 'node:assert/strict';
import test from 'node:test';
import {
  bootstrapIcaCommunicationKeys,
  getIcaCommunicationIdentity,
  resetIcaCommunicationKeysForTests,
} from '../src/api/tools/ica-communication-keys.ts';
import { buildIcaDidDocument, buildIcaJwks } from '../src/api/tools/ica-identity.ts';

test('ICA bootstraps deterministic ML-DSA and ML-KEM transport keys without publishing private bytes', async () => {
  const previousSeed = process.env.ICA_COMMUNICATION_KEY_SEED_PASSPHRASE;
  const previousVcSeed = process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;
  const previousJwks = process.env.ICA_COMMUNICATION_JWKS_JSON;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  try {
    process.env.ICA_COMMUNICATION_KEY_SEED_PASSPHRASE = 'test-only-dedicated-communication-seed';
    delete process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;
    delete process.env.ICA_COMMUNICATION_JWKS_JSON;
    process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
    resetIcaCommunicationKeysForTests();

    const first = await bootstrapIcaCommunicationKeys();
    assert.equal(first.enabled, true);
    assert.equal(first.source, 'communication-seed');
    assert.ok(first.signingKid);
    assert.ok(first.encryptionKid);
    assert.ok(getIcaCommunicationIdentity()?.commSigningKeyPair.secretKeyBytes.length);
    assert.ok(getIcaCommunicationIdentity()?.commEncryptionKeyPair.secretKeyBytes.length);

    const publicJwks = JSON.parse(String(process.env.ICA_COMMUNICATION_JWKS_JSON));
    assert.equal(publicJwks.keys.length, 2);
    assert.equal(JSON.stringify(publicJwks).includes('secretKeyBytes'), false);
    assert.equal(JSON.stringify(publicJwks).includes('"dBytes"'), false);

    const did = buildIcaDidDocument() as Record<string, any>;
    assert.ok(did.authentication.includes(`did:web:ica.example.com#${first.signingKid}`));
    assert.ok(did.keyAgreement.includes(`did:web:ica.example.com#${first.encryptionKid}`));
    assert.equal((buildIcaJwks().keys as unknown[]).length >= 2, true);

    delete process.env.ICA_COMMUNICATION_JWKS_JSON;
    resetIcaCommunicationKeysForTests();
    const second = await bootstrapIcaCommunicationKeys();
    assert.equal(second.signingKid, first.signingKid);
    assert.equal(second.encryptionKid, first.encryptionKid);
  } finally {
    resetIcaCommunicationKeysForTests();
    if (previousSeed === undefined) delete process.env.ICA_COMMUNICATION_KEY_SEED_PASSPHRASE;
    else process.env.ICA_COMMUNICATION_KEY_SEED_PASSPHRASE = previousSeed;
    if (previousVcSeed === undefined) delete process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;
    else process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE = previousVcSeed;
    if (previousJwks === undefined) delete process.env.ICA_COMMUNICATION_JWKS_JSON;
    else process.env.ICA_COMMUNICATION_JWKS_JSON = previousJwks;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
  }
});
