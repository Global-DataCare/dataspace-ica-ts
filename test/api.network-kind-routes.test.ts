import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildVerifyResponseLocation,
  parseVerifyRoute,
} from '../src/api/path.ts';
import { loadCredentialLedgerConfigFromEnv } from '../src/api/tools/credential-ledger.ts';
import {
  activateSigningKey,
  resetActiveSigningKeysStateForTests,
} from '../src/api/tools/active-signing-keys.ts';
import { attachProofToCredential } from '../src/api/tools/ica-identity.ts';
import { PRIVATE_KEY_PEM } from './test-signing-key.fixture.ts';

/**
 * Flow contract: the path section selects the VC cryptographic/registration
 * context. `terms` remains a compatibility alias for `test`; it never enables
 * Fabric. Canonical response locations always expose the resolved networkKind.
 */
test('verify route resolves terms alias and all canonical network kinds', () => {
  const expected = ['test', 'local-network', 'test-network', 'network'] as const;
  for (const networkKind of expected) {
    const parsed = parseVerifyRoute(
      `/ica/cds-ES/v1/health-research/${networkKind}/pdf/contract/_verify`,
    );
    assert.ok(parsed?.ok);
    if (!parsed?.ok) continue;
    assert.equal(parsed.context.section, networkKind);
  }

  const legacy = parseVerifyRoute(
    '/ica/cds-ES/v1/health-research/terms/pdf/contract/_verify',
  );
  assert.ok(legacy?.ok);
  if (!legacy?.ok) return;
  assert.equal(legacy.context.section, 'test');
  assert.equal(
    buildVerifyResponseLocation(legacy.context, { thid: 'thread-1' }),
    '/ica/cds-ES/v1/health-research/test/pdf/contract/_verify-response?thid=thread-1',
  );
});

test('networkKind controls credential anchoring independently from process NETWORK_MODE', () => {
  const env = {
    NETWORK_MODE: 'network',
    ICA_CREDENTIAL_LEDGER_ENABLED: 'true',
    ICA_CREDENTIAL_LEDGER_REQUIRED: 'true',
  };
  assert.equal(loadCredentialLedgerConfigFromEnv(env, 'test').enabled, false);
  assert.equal(loadCredentialLedgerConfigFromEnv(env, 'local-network').enabled, true);
  assert.equal(loadCredentialLedgerConfigFromEnv(env, 'test-network').enabled, true);
  assert.equal(loadCredentialLedgerConfigFromEnv(env, 'network').enabled, true);
});

test('staging and production network kinds reject unchained VC signing keys', () => {
  resetActiveSigningKeysStateForTests();
  activateSigningKey({
    alg: 'ES384',
    privateKeyPem: PRIVATE_KEY_PEM,
  });
  const parsed = parseVerifyRoute(
    '/ica/cds-ES/v1/health-research/test-network/pdf/contract/_verify',
  );
  assert.ok(parsed?.ok);
  if (!parsed?.ok) return;
  assert.throws(
    () => attachProofToCredential({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:20000000-0000-4000-8000-000000000001',
      type: ['VerifiableCredential'],
      issuer: 'did:web:ica.example.org',
      validFrom: '2026-07-30T00:00:00.000Z',
      credentialSubject: { id: 'did:web:host.example.org' },
    }, parsed.context, 'did:web:ica.example.org'),
    /requires an externally chained VC signing key with x5c/,
  );
  resetActiveSigningKeysStateForTests();
});
