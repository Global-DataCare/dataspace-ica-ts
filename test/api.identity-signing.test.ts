import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { parseVerifyRoute } from '../src/api/path.ts';
import {
  attachProofToCredential,
  buildControllerDidDocument,
  buildIcaDidDocument,
  resolveControllerDidDocumentPath,
} from '../src/api/tools/ica-identity.ts';
import {
  activateSigningKey,
  getPreferredSigningKey,
  resetActiveSigningKeysStateForTests,
} from '../src/api/tools/active-signing-keys.ts';
import { deriveControllerEmailHashFromEmail } from '../src/api/tools/controller-identity.ts';
import {
  bootstrapSelfSigningKey,
  useInvalidProofForTestResourceVersion,
} from '../src/api/tools/self-signing.ts';
import { computeControllerAuthorizationPayloadBase64Url } from '../src/api/tools/controller-authorization-payload.ts';

test('computeControllerAuthorizationPayloadBase64Url excludes Bundle.id/meta/signature only', () => {
  const bundleBody = {
    resourceType: 'Bundle',
    id: 'bundle-001',
    meta: {
      versionId: '3',
    },
    signature: {
      data: 'aaa..bbb',
    },
    text: {
      status: 'generated',
      div: '<div>narrative</div>',
    },
    contained: [
      { resourceType: 'Organization', id: 'org-1' },
    ],
    data: [{ resource: { id: 'urn:uuid:vc-1' } }],
  };
  const encoded = computeControllerAuthorizationPayloadBase64Url(bundleBody);
  const canonical = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as Record<string, unknown>;
  assert.equal(canonical.resourceType, 'Bundle');
  assert.equal(canonical.id, undefined);
  assert.equal(canonical.meta, undefined);
  assert.equal(canonical.signature, undefined);
  assert.ok(canonical.text);
  assert.ok(Array.isArray(canonical.contained));

  const nonBundle = {
    resourceType: 'Organization',
    id: 'org-root',
    meta: { versionId: '9' },
    signature: { data: 'aaa..bbb' },
  };
  const nonBundleEncoded = computeControllerAuthorizationPayloadBase64Url(nonBundle);
  const nonBundleCanonical = JSON.parse(
    Buffer.from(nonBundleEncoded, 'base64url').toString('utf8'),
  ) as Record<string, unknown>;
  assert.equal(nonBundleCanonical.resourceType, 'Organization');
  assert.equal(nonBundleCanonical.id, 'org-root');
  assert.ok(nonBundleCanonical.meta);
  assert.equal(nonBundleCanonical.signature, undefined);
});

test('deriveControllerEmailHashFromEmail is deterministic multibase output', () => {
  const valueA = deriveControllerEmailHashFromEmail('It-Director@Example.org');
  const valueB = deriveControllerEmailHashFromEmail('it-director@example.org');
  assert.equal(valueA, valueB);
  assert.equal(valueA, 'zW1asF7QVMofcbd3hXTJncqMojdpQiRWBBdfkfGJQuEah9g');
  assert.equal(valueA.startsWith('z'), true);
  assert.equal(valueA.length > 40, true);
});

test('buildIcaDidDocument links controller did:web member and exposes controller did.json path', () => {
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousControllerKid = process.env.ICA_SELF_CONTROLLER_KID;
  const previousControllerEmail = process.env.ICA_SELF_CONTROLLER_EMAIL;
  const previousControllerMemberType = process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE;
  const previousControllerRole = process.env.ICA_SELF_CONTROLLER_ROLE;
  const previousControllerJurisdiction = process.env.ICA_SELF_CONTROLLER_JURISDICTION;
  const previousControllerSector = process.env.ICA_SELF_CONTROLLER_SECTOR;
  const previousControllerDid = process.env.ICA_SELF_CONTROLLER_DID;

  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.ICA_SELF_CONTROLLER_KID = 'controller-es384-kid';
  process.env.ICA_SELF_CONTROLLER_EMAIL = 'it-director@example.org';
  process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE = 'controller';
  process.env.ICA_SELF_CONTROLLER_ROLE = '1120';
  process.env.ICA_SELF_CONTROLLER_JURISDICTION = 'ES';
  process.env.ICA_SELF_CONTROLLER_SECTOR = 'management';
  delete process.env.ICA_SELF_CONTROLLER_DID;
  resetActiveSigningKeysStateForTests();

  activateSigningKey({
    kid: 'controller-es384-kid',
    alg: 'ES384',
    privateKeyPem: generateKeyPairSync('ec', { namedCurve: 'P-384' })
      .privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString(),
  });

  try {
    const didDocument = buildIcaDidDocument();
    const controllerDid = didDocument.controller as string;
    assert.match(
      controllerDid,
      /^did:web:ica\.example\.com:ica:cds-ES:v1:management:controller:1120:z/,
    );

    const verificationMethods = Array.isArray(didDocument.verificationMethod)
      ? didDocument.verificationMethod as Array<Record<string, unknown>>
      : [];
    assert.equal(
      verificationMethods.some((entry) => String(entry.id || '').startsWith(`${controllerDid}#controller-es384-kid`)),
      true,
    );

    const controllerPath = resolveControllerDidDocumentPath();
    assert.equal(Boolean(controllerPath?.startsWith('/ica/cds-ES/v1/management/controller/1120/')), true);
    assert.equal(controllerPath?.endsWith('/did.json'), true);

    const controllerDidDocument = buildControllerDidDocument();
    assert.equal(controllerDidDocument?.id, controllerDid);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousControllerKid === undefined) delete process.env.ICA_SELF_CONTROLLER_KID;
    else process.env.ICA_SELF_CONTROLLER_KID = previousControllerKid;
    if (previousControllerEmail === undefined) delete process.env.ICA_SELF_CONTROLLER_EMAIL;
    else process.env.ICA_SELF_CONTROLLER_EMAIL = previousControllerEmail;
    if (previousControllerMemberType === undefined) delete process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE;
    else process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE = previousControllerMemberType;
    if (previousControllerRole === undefined) delete process.env.ICA_SELF_CONTROLLER_ROLE;
    else process.env.ICA_SELF_CONTROLLER_ROLE = previousControllerRole;
    if (previousControllerJurisdiction === undefined) delete process.env.ICA_SELF_CONTROLLER_JURISDICTION;
    else process.env.ICA_SELF_CONTROLLER_JURISDICTION = previousControllerJurisdiction;
    if (previousControllerSector === undefined) delete process.env.ICA_SELF_CONTROLLER_SECTOR;
    else process.env.ICA_SELF_CONTROLLER_SECTOR = previousControllerSector;
    if (previousControllerDid === undefined) delete process.env.ICA_SELF_CONTROLLER_DID;
    else process.env.ICA_SELF_CONTROLLER_DID = previousControllerDid;
  }
});

test('controller member did defaults sector to management when ICA_SELF_CONTROLLER_SECTOR is not set', () => {
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousControllerEmail = process.env.ICA_SELF_CONTROLLER_EMAIL;
  const previousControllerMemberType = process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE;
  const previousControllerRole = process.env.ICA_SELF_CONTROLLER_ROLE;
  const previousControllerJurisdiction = process.env.ICA_SELF_CONTROLLER_JURISDICTION;
  const previousControllerSector = process.env.ICA_SELF_CONTROLLER_SECTOR;

  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.ICA_SELF_CONTROLLER_EMAIL = 'it-director@example.org';
  process.env.ICA_SELF_CONTROLLER_ROLE = '1120';
  process.env.ICA_SELF_CONTROLLER_JURISDICTION = 'ES';
  delete process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE;
  delete process.env.ICA_SELF_CONTROLLER_SECTOR;

  try {
    const controllerPath = resolveControllerDidDocumentPath();
    assert.equal(Boolean(controllerPath?.startsWith('/ica/cds-ES/v1/management/controller/1120/')), true);
  } finally {
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousControllerEmail === undefined) delete process.env.ICA_SELF_CONTROLLER_EMAIL;
    else process.env.ICA_SELF_CONTROLLER_EMAIL = previousControllerEmail;
    if (previousControllerMemberType === undefined) delete process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE;
    else process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE = previousControllerMemberType;
    if (previousControllerRole === undefined) delete process.env.ICA_SELF_CONTROLLER_ROLE;
    else process.env.ICA_SELF_CONTROLLER_ROLE = previousControllerRole;
    if (previousControllerJurisdiction === undefined) delete process.env.ICA_SELF_CONTROLLER_JURISDICTION;
    else process.env.ICA_SELF_CONTROLLER_JURISDICTION = previousControllerJurisdiction;
    if (previousControllerSector === undefined) delete process.env.ICA_SELF_CONTROLLER_SECTOR;
    else process.env.ICA_SELF_CONTROLLER_SECTOR = previousControllerSector;
  }
});

test('controller member did uses ICA_SELF_CONTROLLER_MEMBER_TYPE when configured', () => {
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousControllerEmail = process.env.ICA_SELF_CONTROLLER_EMAIL;
  const previousControllerMemberType = process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE;
  const previousControllerRole = process.env.ICA_SELF_CONTROLLER_ROLE;
  const previousControllerJurisdiction = process.env.ICA_SELF_CONTROLLER_JURISDICTION;
  const previousControllerSector = process.env.ICA_SELF_CONTROLLER_SECTOR;

  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.ICA_SELF_CONTROLLER_EMAIL = 'it-director@example.org';
  process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE = 'delegate';
  process.env.ICA_SELF_CONTROLLER_ROLE = '1120';
  process.env.ICA_SELF_CONTROLLER_JURISDICTION = 'ES';
  process.env.ICA_SELF_CONTROLLER_SECTOR = 'controller';

  try {
    const controllerPath = resolveControllerDidDocumentPath();
    assert.equal(Boolean(controllerPath?.startsWith('/ica/cds-ES/v1/management/delegate/1120/')), true);
  } finally {
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousControllerEmail === undefined) delete process.env.ICA_SELF_CONTROLLER_EMAIL;
    else process.env.ICA_SELF_CONTROLLER_EMAIL = previousControllerEmail;
    if (previousControllerMemberType === undefined) delete process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE;
    else process.env.ICA_SELF_CONTROLLER_MEMBER_TYPE = previousControllerMemberType;
    if (previousControllerRole === undefined) delete process.env.ICA_SELF_CONTROLLER_ROLE;
    else process.env.ICA_SELF_CONTROLLER_ROLE = previousControllerRole;
    if (previousControllerJurisdiction === undefined) delete process.env.ICA_SELF_CONTROLLER_JURISDICTION;
    else process.env.ICA_SELF_CONTROLLER_JURISDICTION = previousControllerJurisdiction;
    if (previousControllerSector === undefined) delete process.env.ICA_SELF_CONTROLLER_SECTOR;
    else process.env.ICA_SELF_CONTROLLER_SECTOR = previousControllerSector;
  }
});

test('buildIcaDidDocument publishes DCAT catalog service when configured', () => {
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousDcatServiceEndpoint = process.env.ICA_DCAT_SERVICE_ENDPOINT;

  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.ICA_DCAT_SERVICE_ENDPOINT = '/ica/cds-ES/v1/onehealth/dcat3/catalog/request';

  try {
    const didDocument = buildIcaDidDocument();
    const services = Array.isArray(didDocument.service)
      ? didDocument.service as Array<Record<string, unknown>>
      : [];
    const dcatService = services.find((entry) =>
      String(entry.id || '') === 'did:web:ica.example.com#dsp-catalog-service');
    assert.ok(dcatService);
    assert.equal(dcatService?.type, 'CatalogService');
    assert.equal(dcatService?.serviceEndpoint, '/ica/cds-ES/v1/onehealth/dcat3/catalog/request');
  } finally {
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousDcatServiceEndpoint === undefined) delete process.env.ICA_DCAT_SERVICE_ENDPOINT;
    else process.env.ICA_DCAT_SERVICE_ENDPOINT = previousDcatServiceEndpoint;
  }
});

test('attachProofToCredential generates invalid detached JWS proof for test resourceType', () => {
  const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/test-202603051133/_verify');
  assert.ok(parsed);
  assert.equal(parsed.ok, false);
  const previousUnifiedFlag = process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
  process.env.ICA_ENABLE_TEST_TERMS_PREFIX = 'true';
  const parsedAllowed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/test-202603051133/_verify');
  assert.ok(parsedAllowed);
  assert.equal(parsedAllowed?.ok, true);
  if (!parsedAllowed || !parsedAllowed.ok) return;

  try {
    const vc = attachProofToCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'LegalRepresentativeCredential'],
        issuer: 'did:web:ica.example.com',
        validFrom: '2026-03-05T00:00:00.000Z',
        credentialSubject: { id: 'did:web:holder.example.com' },
      },
      parsedAllowed.context,
    );

    assert.equal(typeof vc.proof, 'object');
    const proof = Array.isArray(vc.proof) ? vc.proof[0] : vc.proof;
    assert.equal(proof?.type, 'JsonWebSignature2020');
    assert.equal(proof?.proofPurpose, 'assertionMethod');
    assert.match(String(proof?.jws || ''), /\.\./);
  } finally {
    if (previousUnifiedFlag === undefined) delete process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
    else process.env.ICA_ENABLE_TEST_TERMS_PREFIX = previousUnifiedFlag;
  }
});

test('bootstrapSelfSigningKey auto-generates local ES384 key in self mode', async () => {
  const previousSelfSignEnabled = process.env.ICA_SELF_SIGN_TEST;
  const previousSelfSignIfMissing = process.env.ICA_SELF_SIGN_IF_MISSING;
  const previousSigningPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const previousSelfSignAlg = process.env.ICA_SELF_SIGN_TEST_ALG;
  const previousSelfSignKid = process.env.ICA_SELF_SIGN_TEST_KEY_ID;
  const previousSigningKeyId = process.env.ICA_VC_SIGNING_KEY_ID;
  const previousSigningAlg = process.env.ICA_VC_SIGNING_ALG;
  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-self-bootstrap-test-'));

  process.env.ICA_SELF_SIGN_TEST = 'true';
  process.env.ICA_SELF_SIGN_IF_MISSING = 'true';
  delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  delete process.env.ICA_SELF_SIGN_TEST_ALG;
  delete process.env.ICA_SELF_SIGN_TEST_KEY_ID;
  delete process.env.ICA_VC_SIGNING_KEY_ID;
  delete process.env.ICA_VC_SIGNING_ALG;
  resetActiveSigningKeysStateForTests();

  try {
    const first = bootstrapSelfSigningKey();
    assert.equal(first.enabled, true);
    assert.equal(first.activated, true);
    assert.equal(first.alg, 'ES384');
    assert.equal(typeof first.kid, 'string');
    assert.ok(first.kid);
    assert.equal((process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM || '').includes('BEGIN PRIVATE KEY'), true);
    assert.equal(process.env.ICA_VC_SIGNING_ALG, 'ES384');
    assert.equal(process.env.ICA_VC_SIGNING_KEY_ID, first.kid);

    const preferred = getPreferredSigningKey(undefined);
    assert.equal(preferred, undefined);

    const second = bootstrapSelfSigningKey();
    assert.equal(second.enabled, true);
    assert.equal(second.activated, false);
    assert.equal(second.source, 'env-signing-key');
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(tempDir, { recursive: true, force: true });
    if (previousSelfSignEnabled === undefined) delete process.env.ICA_SELF_SIGN_TEST;
    else process.env.ICA_SELF_SIGN_TEST = previousSelfSignEnabled;
    if (previousSelfSignIfMissing === undefined) delete process.env.ICA_SELF_SIGN_IF_MISSING;
    else process.env.ICA_SELF_SIGN_IF_MISSING = previousSelfSignIfMissing;
    if (previousSigningPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousSigningPem;
    if (previousSelfSignAlg === undefined) delete process.env.ICA_SELF_SIGN_TEST_ALG;
    else process.env.ICA_SELF_SIGN_TEST_ALG = previousSelfSignAlg;
    if (previousSelfSignKid === undefined) delete process.env.ICA_SELF_SIGN_TEST_KEY_ID;
    else process.env.ICA_SELF_SIGN_TEST_KEY_ID = previousSelfSignKid;
    if (previousSigningKeyId === undefined) delete process.env.ICA_VC_SIGNING_KEY_ID;
    else process.env.ICA_VC_SIGNING_KEY_ID = previousSigningKeyId;
    if (previousSigningAlg === undefined) delete process.env.ICA_VC_SIGNING_ALG;
    else process.env.ICA_VC_SIGNING_ALG = previousSigningAlg;
  }
});

test('attachProofToCredential can produce valid test proof when ICA_SELF_SIGN_TEST_VALID_PROOF=true', async () => {
  const previousUnifiedFlag = process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
  const previousValidProof = process.env.ICA_SELF_SIGN_TEST_VALID_PROOF;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousPrivateKeyPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-test-proof-mode-test-'));

  process.env.ICA_ENABLE_TEST_TERMS_PREFIX = 'true';
  process.env.ICA_SELF_SIGN_TEST_VALID_PROOF = 'true';
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  resetActiveSigningKeysStateForTests();

  try {
    const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/test-202603051133/_verify');
    assert.ok(parsed);
    assert.equal(parsed?.ok, true);
    if (!parsed || !parsed.ok) return;

    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    activateSigningKey({
      kid: 'ica-es384-test-proof-mode',
      alg: 'ES384',
      privateKeyPem,
    });

    const vc = attachProofToCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'LegalRepresentativeCredential'],
        issuer: 'did:web:ica.example.com',
        validFrom: '2026-03-05T00:00:00.000Z',
        credentialSubject: { id: 'did:web:holder.example.com' },
      },
      parsed.context,
    );

    const proof = Array.isArray(vc.proof) ? vc.proof[0] : vc.proof;
    const fakeSignatureBase64Url = Buffer.from('invalid-test-signature').toString('base64url');
    assert.equal(useInvalidProofForTestResourceVersion(), false);
    assert.equal(proof?.verificationMethod, 'did:web:ica.example.com#ica-es384-test-proof-mode');
    assert.equal(String(proof?.jws || '').includes(fakeSignatureBase64Url), false);
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(tempDir, { recursive: true, force: true });
    if (previousUnifiedFlag === undefined) delete process.env.ICA_ENABLE_TEST_TERMS_PREFIX;
    else process.env.ICA_ENABLE_TEST_TERMS_PREFIX = previousUnifiedFlag;
    if (previousValidProof === undefined) delete process.env.ICA_SELF_SIGN_TEST_VALID_PROOF;
    else process.env.ICA_SELF_SIGN_TEST_VALID_PROOF = previousValidProof;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousPrivateKeyPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousPrivateKeyPem;
  }
});

test('bootstrapSelfSigningKey derives deterministic kid from ICA_VC_PRIVATE_KEY_SEED_* config', async () => {
  const previousSelfSign = process.env.ICA_SELF_SIGN_TEST;
  const previousSelfSignIfMissing = process.env.ICA_SELF_SIGN_IF_MISSING;
  const previousSeedPassphrase = process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;
  const previousSeedConfig = process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG;
  const previousSeedAlg = process.env.ICA_VC_SEED_ALG;
  const previousSigningPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const previousSigningKeyId = process.env.ICA_VC_SIGNING_KEY_ID;
  const previousSigningAlg = process.env.ICA_VC_SIGNING_ALG;
  const dirA = await mkdtemp(path.join(tmpdir(), 'ica-seed-kid-a-'));
  const dirB = await mkdtemp(path.join(tmpdir(), 'ica-seed-kid-b-'));

  process.env.ICA_SELF_SIGN_TEST = 'true';
  process.env.ICA_SELF_SIGN_IF_MISSING = 'true';
  process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE = 'seed-passphrase-test';
  process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG = '17:8:1:48:ica-seed-salt-v1';
  process.env.ICA_VC_SEED_ALG = 'ES384';
  delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  delete process.env.ICA_VC_SIGNING_KEY_ID;
  delete process.env.ICA_VC_SIGNING_ALG;

  try {
    process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG = '17:8:1:48:ica-seed-salt-v1';
    resetActiveSigningKeysStateForTests();
    const first = bootstrapSelfSigningKey();
    assert.equal(first.enabled, true);
    assert.equal(first.activated, true);
    assert.equal(first.alg, 'ES384');
    assert.ok(first.kid);

    process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = '';
    process.env.ICA_VC_SIGNING_KEY_ID = '';
    process.env.ICA_VC_SIGNING_ALG = '';
    process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG = '17:8:1:48:ica-seed-salt-v1';
    resetActiveSigningKeysStateForTests();
    const second = bootstrapSelfSigningKey();
    assert.equal(second.enabled, true);
    assert.equal(second.activated, true);
    assert.equal(second.alg, 'ES384');
    assert.ok(second.kid);

    assert.equal(first.kid, second.kid);
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(dirA, { recursive: true, force: true });
    await rm(dirB, { recursive: true, force: true });
    if (previousSelfSign === undefined) delete process.env.ICA_SELF_SIGN_TEST;
    else process.env.ICA_SELF_SIGN_TEST = previousSelfSign;
    if (previousSelfSignIfMissing === undefined) delete process.env.ICA_SELF_SIGN_IF_MISSING;
    else process.env.ICA_SELF_SIGN_IF_MISSING = previousSelfSignIfMissing;
    if (previousSeedPassphrase === undefined) delete process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;
    else process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE = previousSeedPassphrase;
    if (previousSeedConfig === undefined) delete process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG;
    else process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG = previousSeedConfig;
    if (previousSeedAlg === undefined) delete process.env.ICA_VC_SEED_ALG;
    else process.env.ICA_VC_SEED_ALG = previousSeedAlg;
    if (previousSigningPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousSigningPem;
    if (previousSigningKeyId === undefined) delete process.env.ICA_VC_SIGNING_KEY_ID;
    else process.env.ICA_VC_SIGNING_KEY_ID = previousSigningKeyId;
    if (previousSigningAlg === undefined) delete process.env.ICA_VC_SIGNING_ALG;
    else process.env.ICA_VC_SIGNING_ALG = previousSigningAlg;
  }
});

test('bootstrapSelfSigningKey honors ICA_VC_PRIVATE_KEY_SEED_SALT override', () => {
  const previousSelfSign = process.env.ICA_SELF_SIGN_TEST;
  const previousSelfSignIfMissing = process.env.ICA_SELF_SIGN_IF_MISSING;
  const previousSeedPassphrase = process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;
  const previousSeedConfig = process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG;
  const previousSeedSalt = process.env.ICA_VC_PRIVATE_KEY_SEED_SALT;
  const previousSeedAlg = process.env.ICA_VC_SEED_ALG;
  const previousSigningPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const previousSigningKeyId = process.env.ICA_VC_SIGNING_KEY_ID;
  const previousSigningAlg = process.env.ICA_VC_SIGNING_ALG;

  process.env.ICA_SELF_SIGN_TEST = 'true';
  process.env.ICA_SELF_SIGN_IF_MISSING = 'true';
  process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE = 'seed-passphrase-test';
  process.env.ICA_VC_SEED_ALG = 'ES384';
  process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG = '17:8:1:48';
  process.env.ICA_VC_PRIVATE_KEY_SEED_SALT = 'seed-salt-override-v1';
  delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  delete process.env.ICA_VC_SIGNING_KEY_ID;
  delete process.env.ICA_VC_SIGNING_ALG;

  try {
    resetActiveSigningKeysStateForTests();
    const first = bootstrapSelfSigningKey();
    assert.equal(first.enabled, true);
    assert.equal(first.activated, true);
    assert.ok(first.kid);

    process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = '';
    process.env.ICA_VC_SIGNING_KEY_ID = '';
    process.env.ICA_VC_SIGNING_ALG = '';
    process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG = '17:8:1:48:legacy-salt-ignored';
    process.env.ICA_VC_PRIVATE_KEY_SEED_SALT = 'seed-salt-override-v1';
    resetActiveSigningKeysStateForTests();
    const second = bootstrapSelfSigningKey();
    assert.equal(second.enabled, true);
    assert.equal(second.activated, true);
    assert.ok(second.kid);

    assert.equal(first.kid, second.kid);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousSelfSign === undefined) delete process.env.ICA_SELF_SIGN_TEST;
    else process.env.ICA_SELF_SIGN_TEST = previousSelfSign;
    if (previousSelfSignIfMissing === undefined) delete process.env.ICA_SELF_SIGN_IF_MISSING;
    else process.env.ICA_SELF_SIGN_IF_MISSING = previousSelfSignIfMissing;
    if (previousSeedPassphrase === undefined) delete process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;
    else process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE = previousSeedPassphrase;
    if (previousSeedConfig === undefined) delete process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG;
    else process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG = previousSeedConfig;
    if (previousSeedSalt === undefined) delete process.env.ICA_VC_PRIVATE_KEY_SEED_SALT;
    else process.env.ICA_VC_PRIVATE_KEY_SEED_SALT = previousSeedSalt;
    if (previousSeedAlg === undefined) delete process.env.ICA_VC_SEED_ALG;
    else process.env.ICA_VC_SEED_ALG = previousSeedAlg;
    if (previousSigningPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousSigningPem;
    if (previousSigningKeyId === undefined) delete process.env.ICA_VC_SIGNING_KEY_ID;
    else process.env.ICA_VC_SIGNING_KEY_ID = previousSigningKeyId;
    if (previousSigningAlg === undefined) delete process.env.ICA_VC_SIGNING_ALG;
    else process.env.ICA_VC_SIGNING_ALG = previousSigningAlg;
  }
});

test('buildIcaDidDocument and production VC proof use configured signing key', () => {
  const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/202603051133/_verify');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const previousPrivateKeyPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const previousSigningAlg = process.env.ICA_VC_SIGNING_ALG;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousSigningKeyId = process.env.ICA_VC_SIGNING_KEY_ID;
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  process.env.ICA_VC_SIGNING_ALG = 'RS256';
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  process.env.ICA_VC_SIGNING_KEY_ID = 'ica-signing-key-1';
  resetActiveSigningKeysStateForTests();
  try {
    const didDocument = buildIcaDidDocument() as Record<string, unknown>;
    assert.equal(didDocument.id, 'did:web:ica.example.com');
    assert.equal(Array.isArray(didDocument.verificationMethod), true);
    assert.equal(Array.isArray(didDocument.assertionMethod), true);

    const vc = attachProofToCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'OrganizationCredential'],
        issuer: 'did:web:ica.example.com',
        validFrom: '2026-03-05T00:00:00.000Z',
        credentialSubject: { id: 'urn:organization:taxid:VATES-A12345678' },
      },
      parsed.context,
    );

    assert.equal(typeof vc.proof, 'object');
    const proof = Array.isArray(vc.proof) ? vc.proof[0] : vc.proof;
    assert.equal(proof?.verificationMethod, 'did:web:ica.example.com#ica-signing-key-1');
    assert.match(String(proof?.jws || ''), /\.\./);
  } finally {
    resetActiveSigningKeysStateForTests();
    if (previousPrivateKeyPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousPrivateKeyPem;
    if (previousSigningAlg === undefined) delete process.env.ICA_VC_SIGNING_ALG;
    else process.env.ICA_VC_SIGNING_ALG = previousSigningAlg;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousSigningKeyId === undefined) delete process.env.ICA_VC_SIGNING_KEY_ID;
    else process.env.ICA_VC_SIGNING_KEY_ID = previousSigningKeyId;
  }
});

test('activated signing key is reflected in DID document immediately', async () => {
  const previousActiveKeysFile = process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousPrivateKeyPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-signing-state-test-'));
  process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = path.join(tempDir, 'active-signing-keys.json');
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const activated = activateSigningKey({
      kid: 'ica-es384-test',
      alg: 'ES384',
      privateKeyPem,
      x5c: ['MIIBTESTCHAINBASE64'],
    });

    const didDocument = buildIcaDidDocument() as Record<string, any>;
    assert.equal(didDocument.id, 'did:web:ica.example.com');
    const verificationMethod = Array.isArray(didDocument.verificationMethod)
      ? didDocument.verificationMethod
      : [];
    const method = verificationMethod.find((entry: Record<string, unknown>) => entry.id === `did:web:ica.example.com#${activated.kid}`);
    assert.ok(method);
    assert.equal(method?.publicKeyJwk?.alg, 'ES384');
    assert.equal(Array.isArray(method?.publicKeyJwk?.x5c), true);
    assert.equal(method?.publicKeyJwk?.x5c?.[0], 'MIIBTESTCHAINBASE64');
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(tempDir, { recursive: true, force: true });
    if (previousActiveKeysFile === undefined) delete process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
    else process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = previousActiveKeysFile;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousPrivateKeyPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousPrivateKeyPem;
  }
});

test('production VC proof uses recently activated signing key', async () => {
  const parsed = parseVerifyRoute('/ica/cds-ES/v1/animal-care/terms/pdf/202603051133/_verify');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;

  const previousActiveKeysFile = process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
  const previousIssuerDid = process.env.ICA_DIDCOMM_ISSUER_DID;
  const previousPrivateKeyPem = process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  const tempDir = await mkdtemp(path.join(tmpdir(), 'ica-signing-proof-test-'));
  process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = path.join(tempDir, 'active-signing-keys.json');
  process.env.ICA_DIDCOMM_ISSUER_DID = 'did:web:ica.example.com';
  delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
  resetActiveSigningKeysStateForTests();

  try {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    activateSigningKey({
      kid: 'ica-es384-proof',
      alg: 'ES384',
      privateKeyPem,
    });

    const vc = attachProofToCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'OrganizationCredential'],
        issuer: 'did:web:ica.example.com',
        validFrom: '2026-03-05T00:00:00.000Z',
        credentialSubject: { id: 'urn:organization:taxid:VATES-A12345678' },
      },
      parsed.context,
    );

    const proof = Array.isArray(vc.proof) ? vc.proof[0] : vc.proof;
    assert.equal(proof?.verificationMethod, 'did:web:ica.example.com#ica-es384-proof');
    assert.match(String(proof?.jws || ''), /\.\./);
  } finally {
    resetActiveSigningKeysStateForTests();
    await rm(tempDir, { recursive: true, force: true });
    if (previousActiveKeysFile === undefined) delete process.env.ICA_ACTIVE_SIGNING_KEYS_FILE;
    else process.env.ICA_ACTIVE_SIGNING_KEYS_FILE = previousActiveKeysFile;
    if (previousIssuerDid === undefined) delete process.env.ICA_DIDCOMM_ISSUER_DID;
    else process.env.ICA_DIDCOMM_ISSUER_DID = previousIssuerDid;
    if (previousPrivateKeyPem === undefined) delete process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM;
    else process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = previousPrivateKeyPem;
  }
});
