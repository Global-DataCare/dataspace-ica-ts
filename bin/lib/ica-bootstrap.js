import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { normalizeDataspaceMembershipScope } from 'gdc-common-utils-ts/utils/dataspace-membership-scope';
import {
  buildDidWebFromDomain,
  computeJwkKid,
  deriveDeterministicEcKeyMaterial,
  parseSeedConfig,
  resolvePassphrase,
} from './bootstrap-common.js';

function normalizeScope(rawScope) {
  return normalizeDataspaceMembershipScope(rawScope || 'dataspace:ica');
}

function safeReadJson(filePath) {
  if (!existsSync(filePath)) return null;
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Invalid JSON file ${filePath}: ${error.message}`);
  }
}

function resolveControllerLinkage(args) {
  const explicitDid = (args['controller-did'] || '').trim();
  const explicitKid = (args['controller-kid'] || '').trim();
  const explicitJwkPath = (args['controller-jwk'] || '').trim();
  const controllerDirRaw = (args['controller-dir'] || '').trim();
  const result = {
    controllerDid: explicitDid || '',
    controllerKid: explicitKid || '',
    controllerPublicJwk: null,
    controllerSource: explicitDid ? 'arg' : '',
  };

  if (explicitJwkPath) {
    const jwk = safeReadJson(path.resolve(explicitJwkPath));
    if (jwk && typeof jwk === 'object' && !Array.isArray(jwk)) {
      result.controllerPublicJwk = jwk;
      result.controllerSource = result.controllerSource || 'arg-jwk';
    }
  }

  if (!controllerDirRaw) {
    return result;
  }

  const controllerDir = path.resolve(controllerDirRaw);
  const metadata = safeReadJson(path.join(controllerDir, 'controller-bootstrap.json'));
  const controllerJwk = safeReadJson(path.join(controllerDir, 'controller-public-jwk.json'));
  const controllerDidDoc = safeReadJson(path.join(controllerDir, 'controller-did.json'));

  if (!result.controllerDid) {
    if (typeof metadata?.controllerDid === 'string' && metadata.controllerDid.trim()) {
      result.controllerDid = metadata.controllerDid.trim();
      result.controllerSource = 'controller-dir-metadata';
    } else if (typeof controllerDidDoc?.id === 'string' && controllerDidDoc.id.trim()) {
      result.controllerDid = controllerDidDoc.id.trim();
      result.controllerSource = 'controller-dir-did';
    }
  }
  if (!result.controllerKid && typeof metadata?.kid === 'string' && metadata.kid.trim()) {
    result.controllerKid = metadata.kid.trim();
  }
  if (!result.controllerPublicJwk && controllerJwk && typeof controllerJwk === 'object' && !Array.isArray(controllerJwk)) {
    result.controllerPublicJwk = controllerJwk;
  }

  return result;
}

function normalizePublicJwkKid(publicJwk, fallbackKid) {
  const kid = (publicJwk?.kid || fallbackKid || '').trim();
  return kid || computeJwkKid(publicJwk);
}

function buildActivateTemplate(controllerDid, controllerKid, icaDid, signingKey) {
  const whoReference = controllerDid
    ? `${controllerDid}#${controllerKid || '<controller-kid>'}`
    : '<did:web:controller#kid>';
  return {
    jti: 'req-auto',
    thid: 'thid-auto',
    type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
    body: {
      resourceType: 'Bundle',
      type: 'batch',
      signature: {
        sigFormat: 'application/jose',
        who: {
          reference: whoReference,
        },
        data: '<detached-compact-jws-or-base64>',
      },
      data: [
        {
          key: {
            kid: signingKey.kid,
            alg: signingKey.alg,
            privateKeyPem: signingKey.privateKeyPem,
            certificateChainPem: [
              '-----BEGIN CERTIFICATE-----\n<leaf>\n-----END CERTIFICATE-----',
              '-----BEGIN CERTIFICATE-----\n<intermediate>\n-----END CERTIFICATE-----',
              '-----BEGIN CERTIFICATE-----\n<root>\n-----END CERTIFICATE-----',
            ],
          },
          resource: {
            id: `${icaDid}#${signingKey.kid}`,
            type: ['VerifiableCredentialSigningKey'],
          },
        },
      ],
    },
  };
}

export function cmdIcaBootstrap(args, deps) {
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
  const passphrase = resolvePassphrase(args, requireArg);
  const jurisdiction = requireArg(args, 'jurisdiction').toUpperCase();
  const scope = normalizeScope(args.scope || args.sector);
  const alg = (args.alg || 'ES384').trim().toUpperCase();
  if (alg !== 'ES384' && alg !== 'ES256K') {
    throw new Error('--alg must be ES384 or ES256K for deterministic seed bootstrap.');
  }
  const country = (args.country || 'ES').trim().toUpperCase();
  const commonName = (args['common-name'] || `ICA Signing Key ${domain}`).trim();
  const outDir = path.resolve(args['out-dir'] || path.join('output', 'ica-bootstrap'));

  const seedConfig = parseSeedConfig(args, {
    defaultScryptProfile: '17:8:1:48',
    defaultSalt: 'gdc:ica:vc:seed:v1',
  });
  const keyMaterial = deriveDeterministicEcKeyMaterial(
    passphrase,
    alg,
    seedConfig,
    `gdc:v1:ica:vc:${alg.toLowerCase()}`,
  );
  const kid = computeJwkKid(keyMaterial.publicJwk);
  const issuerDid = buildDidWebFromDomain(domain, normalizeDomain);
  const verificationMethodId = `${issuerDid}#${kid}`;
  const publicJwk = {
    ...keyMaterial.publicJwk,
    kid,
    alg,
    use: 'sig',
  };

  const controller = resolveControllerLinkage(args);
  const controllerDid = controller.controllerDid || undefined;
  const controllerPublicJwk = controller.controllerPublicJwk || undefined;
  const controllerKid = controllerPublicJwk
    ? normalizePublicJwkKid(controllerPublicJwk, controller.controllerKid)
    : controller.controllerKid || undefined;

  const didDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: issuerDid,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: 'JsonWebKey2020',
        controller: issuerDid,
        publicKeyJwk: publicJwk,
      },
    ],
    assertionMethod: [verificationMethodId],
    authentication: [verificationMethodId],
    ...(controllerDid ? { controller: controllerDid } : {}),
  };

  if (controllerDid && controllerPublicJwk) {
    const methodId = `${controllerDid}#${controllerKid}`;
    didDocument.verificationMethod.push({
      id: methodId,
      type: 'JsonWebKey2020',
      controller: controllerDid,
      publicKeyJwk: {
        ...controllerPublicJwk,
        kid: controllerKid,
      },
    });
  }

  const privateKeyPath = path.join(outDir, 'ica-signing-private-key.pem');
  const publicJwkPath = path.join(outDir, 'ica-signing-public-jwk.json');
  const csrPath = path.join(outDir, 'ica-signing.csr.pem');
  const didDocPath = path.join(outDir, 'ica-did.json');
  const hostedDidDocPath = path.join(outDir, 'publish', '.well-known', 'did.json');
  const metadataPath = path.join(outDir, 'ica-bootstrap.json');
  const envPath = path.join(outDir, 'ica.env');
  const activateTemplatePath = path.join(outDir, 'activate-request.template.json');

  writeTextFile(privateKeyPath, keyMaterial.privateKeyPem);
  writeJson(publicJwkPath, publicJwk);
  writeJson(didDocPath, didDocument);
  writeJson(hostedDidDocPath, didDocument);

  const csrDigestArg = alg === 'ES384' ? '-sha384' : '-sha256';
  const subject = `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}`;
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

  const envLines = [
    '# ICA signing bootstrap (generated by ica-cli ica:bootstrap)',
    '# Keep passphrase in secret manager and inject only at runtime.',
    'ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE=<set-in-secret-manager>',
    `ICA_VC_PRIVATE_KEY_SEED_CONFIG=${seedConfig.scrypt.profile}`,
    `ICA_VC_PRIVATE_KEY_SEED_SALT=${seedConfig.saltRaw}`,
    `ICA_VC_SEED_ALG=${alg}`,
    `ICA_VC_SIGNING_PREFERRED_ALG=${alg}`,
    `ICA_ISSUER_SCOPE=${scope}`,
    `ICA_ISSUER_JURISDICTION=${jurisdiction}`,
  ];
  writeTextFile(envPath, `${envLines.join('\n')}\n`);

  writeJson(activateTemplatePath, buildActivateTemplate(controllerDid, controllerKid, issuerDid, {
    kid,
    alg,
    privateKeyPem: keyMaterial.privateKeyPem,
  }));

  writeJson(metadataPath, {
    generatedAt: new Date().toISOString(),
    command: 'ica:bootstrap',
    issuerDid,
    scope,
    jurisdiction,
    country,
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
    controller: controllerDid
      ? {
        did: controllerDid,
        kid: controllerKid || null,
        source: controller.controllerSource || null,
      }
      : null,
    files: {
      privateKeyPem: privateKeyPath,
      publicJwk: publicJwkPath,
      csr: csrPath,
      didDocument: didDocPath,
      hostedDidDocument: hostedDidDocPath,
      env: envPath,
      activateTemplate: activateTemplatePath,
    },
  });

  console.log(`ICA bootstrap generated in ${outDir}`);
  console.log(`- kid: ${kid}`);
  console.log(`- issuerDid: ${issuerDid}`);
  console.log(`- scope: ${scope}`);
  console.log(`- jurisdiction: ${jurisdiction}`);
  if (controllerDid) {
    console.log(`- controllerDid linked: ${controllerDid}`);
  }
  console.log(`- csr: ${csrPath}`);
  console.log(`- env snippet: ${envPath}`);
  console.log(`- activate template: ${activateTemplatePath}`);
}
