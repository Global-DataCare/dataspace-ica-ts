import path from 'node:path';
import { writeFileSync } from 'node:fs';
import { multibase58MultihashSha3_256 } from 'gdc-common-utils-ts/utils/same-as';
import {
  buildDidWebFromDomain,
  computeJwkKid,
  deriveDeterministicEcKeyMaterial,
  parseSeedConfig,
  resolvePassphrase,
} from './bootstrap-common.js';

function buildControllerEmailHash(email) {
  const normalizedEmail = email.trim().toLowerCase();
  if (!normalizedEmail) {
    throw new Error('Controller email cannot be empty.');
  }
  return multibase58MultihashSha3_256(normalizedEmail);
}

function normalizeControllerRole(rawRole) {
  const value = (rawRole || '1120').trim();
  if (!/^\d{4}$/.test(value)) {
    throw new Error('--role-isco must be exactly 4 digits (ISCO-08).');
  }
  return value;
}

function buildControllerDid(issuerDid, options) {
  const tenantId = (options.tenantId || 'ica').trim() || 'ica';
  const jurisdiction = (options.jurisdiction || '').trim().toUpperCase();
  if (!jurisdiction) throw new Error('--jurisdiction is required.');
  const sector = (options.sector || 'controller').trim().toLowerCase() || 'controller';
  const role = normalizeControllerRole(options.roleIsco);
  const emailHash = options.emailHash;
  return `${issuerDid}:${tenantId}:cds-${jurisdiction}:v1:${sector}:member:${role}:${emailHash}`;
}

function controllerDidToDidJsonPath(controllerDid) {
  if (!controllerDid.startsWith('did:web:')) {
    throw new Error(`Invalid controller did:web value: ${controllerDid}`);
  }
  const didSuffix = controllerDid.slice('did:web:'.length);
  const segments = didSuffix.split(':').filter(Boolean);
  if (segments.length < 2) return '/did.json';
  const pathSegments = segments.slice(1).map((segment) => {
    try {
      return decodeURIComponent(segment);
    } catch {
      return segment;
    }
  });
  return `/${pathSegments.join('/')}/did.json`;
}

export function cmdControllerBootstrap(args, deps) {
  const {
    ensureDir,
    normalizeDomain,
    normalizeSubjectValue,
    requireArg,
    runOpenSsl,
    writeJson,
  } = deps;
  const writeTextFile = (filePath, content) => {
    ensureDir(path.dirname(filePath));
    writeFileSync(filePath, content);
  };

  const domain = normalizeDomain(requireArg(args, 'domain'));
  const email = requireArg(args, 'email').toLowerCase();
  const passphrase = resolvePassphrase(args, requireArg);
  const tenantId = (args['tenant-id'] || 'ica').trim() || 'ica';
  const jurisdiction = requireArg(args, 'jurisdiction').toUpperCase();
  const sector = (args.sector || 'controller').trim().toLowerCase() || 'controller';
  const roleIsco = normalizeControllerRole(args['role-isco'] || '1120');
  const alg = (args.alg || 'ES384').trim().toUpperCase();
  if (alg !== 'ES384' && alg !== 'ES256K') {
    throw new Error('--alg must be ES384 or ES256K for deterministic seed bootstrap.');
  }
  const country = (args.country || 'ES').trim().toUpperCase();
  const commonName = (args['common-name'] || `ICA Controller ${email}`).trim();
  const outDir = path.resolve(args['out-dir'] || path.join('output', 'controller-bootstrap'));

  const seedConfig = parseSeedConfig(args, {
    defaultScryptProfile: '17:8:1:48',
    defaultSalt: 'gdc:ica:controller:seed:v1',
  });
  const keyMaterial = deriveDeterministicEcKeyMaterial(
    passphrase,
    alg,
    seedConfig,
    `gdc:v1:ica:controller:${alg.toLowerCase()}`,
  );
  const kid = computeJwkKid(keyMaterial.publicJwk);
  const issuerDid = buildDidWebFromDomain(domain, normalizeDomain);
  const controllerEmailHash = buildControllerEmailHash(email);
  const controllerDid = buildControllerDid(issuerDid, {
    tenantId,
    jurisdiction,
    sector,
    roleIsco,
    emailHash: controllerEmailHash,
  });
  const controllerDidPath = controllerDidToDidJsonPath(controllerDid);
  const verificationMethodId = `${controllerDid}#${kid}`;
  const publicJwk = {
    ...keyMaterial.publicJwk,
    kid,
    alg,
    use: 'sig',
  };
  const controllerDidDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: controllerDid,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: 'JsonWebKey2020',
        controller: controllerDid,
        publicKeyJwk: publicJwk,
      },
    ],
    assertionMethod: [verificationMethodId],
    authentication: [verificationMethodId],
  };

  const privateKeyPath = path.join(outDir, 'controller-private-key.pem');
  const publicJwkPath = path.join(outDir, 'controller-public-jwk.json');
  const csrPath = path.join(outDir, 'controller.csr.pem');
  const didDocPath = path.join(outDir, 'controller-did.json');
  const hostedDidPath = path.join(outDir, 'publish', controllerDidPath.replace(/^\//, ''));
  const metadataPath = path.join(outDir, 'controller-bootstrap.json');
  const envPath = path.join(outDir, 'controller.env');

  writeTextFile(privateKeyPath, keyMaterial.privateKeyPem);
  writeJson(publicJwkPath, publicJwk);
  writeJson(didDocPath, controllerDidDocument);
  writeJson(hostedDidPath, controllerDidDocument);

  const csrDigestArg = alg === 'ES384' ? '-sha384' : '-sha256';
  const subject = `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}/emailAddress=${normalizeSubjectValue(email)}`;
  try {
    runOpenSsl([
      'req',
      '-new',
      csrDigestArg,
      '-key',
      privateKeyPath,
      '-out',
      csrPath,
      '-subj',
      subject,
      '-addext',
      `subjectAltName = email:${email}`,
    ]);
  } catch {
    runOpenSsl([
      'req',
      '-new',
      csrDigestArg,
      '-key',
      privateKeyPath,
      '-out',
      csrPath,
      '-subj',
      subject,
    ]);
  }

  const envLines = [
    '# ICA controller bootstrap (generated by ica-cli controller:bootstrap)',
    `ICA_SELF_CONTROLLER_KID=${kid}`,
    `ICA_SELF_CONTROLLER_EMAIL=${email}`,
    `ICA_SELF_CONTROLLER_EMAIL_HASH=${controllerEmailHash}`,
    `ICA_SELF_CONTROLLER_ROLE=${roleIsco}`,
    `ICA_SELF_CONTROLLER_JURISDICTION=${jurisdiction}`,
    `ICA_SELF_CONTROLLER_SECTOR=${sector}`,
    `ICA_SELF_CONTROLLER_DID=${controllerDid}`,
    `ICA_SELF_CONTROLLER_ALG=${alg}`,
    `ICA_SELF_CONTROLLER_PUBLIC_KEY_JWK=${JSON.stringify(publicJwk)}`,
  ];
  writeTextFile(envPath, `${envLines.join('\n')}\n`);

  writeJson(metadataPath, {
    generatedAt: new Date().toISOString(),
    command: 'controller:bootstrap',
    issuerDid,
    controllerDid,
    controllerDidPath,
    tenantId,
    jurisdiction,
    sector,
    roleIsco,
    email,
    controllerEmailHash,
    alg,
    kid,
    seed: {
      profile: seedConfig.scrypt.profile,
      log2N: seedConfig.scrypt.log2N,
      r: seedConfig.scrypt.r,
      p: seedConfig.scrypt.p,
      dkLen: seedConfig.scrypt.dkLen,
      saltEncoding: seedConfig.saltEncoding,
      salt: seedConfig.saltRaw,
      saltHex: seedConfig.saltBuffer.toString('hex'),
      source: seedConfig.source,
    },
    files: {
      privateKeyPem: privateKeyPath,
      publicJwk: publicJwkPath,
      csr: csrPath,
      controllerDidDocument: didDocPath,
      hostedControllerDidDocument: hostedDidPath,
      env: envPath,
    },
  });

  console.log(`Controller bootstrap generated in ${outDir}`);
  console.log(`- kid: ${kid}`);
  console.log(`- emailHash: ${controllerEmailHash}`);
  console.log(`- controllerDid: ${controllerDid}`);
  console.log(`- controllerDidPath: ${controllerDidPath}`);
  console.log(`- csr: ${csrPath}`);
  console.log(`- env snippet: ${envPath}`);
}
