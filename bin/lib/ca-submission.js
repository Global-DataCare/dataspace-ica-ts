import { cpSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

function readJsonIfExists(filePath) {
  if (!existsSync(filePath)) return null;
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function requireFile(filePath, label) {
  if (!existsSync(filePath)) {
    throw new Error(`Missing ${label}: ${filePath}`);
  }
}

function buildRequestId(raw) {
  if (typeof raw === 'string' && raw.trim()) {
    return raw.trim();
  }
  const now = new Date();
  const pad2 = (value) => String(value).padStart(2, '0');
  const stamp = [
    now.getFullYear(),
    pad2(now.getMonth() + 1),
    pad2(now.getDate()),
    pad2(now.getHours()),
    pad2(now.getMinutes()),
    pad2(now.getSeconds()),
  ].join('');
  return `ca-submission-${stamp}`;
}

export function cmdCaPrepareSubmission(args, deps) {
  const { ensureDir, requireArg, writeJson } = deps;
  const controllerDir = path.resolve(requireArg(args, 'controller-dir'));
  const icaDir = path.resolve(requireArg(args, 'ica-dir'));
  const requestId = buildRequestId(args['request-id']);
  const outRoot = path.resolve(args['out-dir'] || path.join('output', 'ca-submission'));
  const outDir = path.join(outRoot, requestId);

  const inputs = {
    controller: {
      csr: path.join(controllerDir, 'controller.csr.pem'),
      did: path.join(controllerDir, 'controller-did.json'),
      jwk: path.join(controllerDir, 'controller-public-jwk.json'),
      metadata: path.join(controllerDir, 'controller-bootstrap.json'),
    },
    ica: {
      csr: path.join(icaDir, 'ica-signing.csr.pem'),
      did: path.join(icaDir, 'ica-did.json'),
      jwk: path.join(icaDir, 'ica-signing-public-jwk.json'),
      metadata: path.join(icaDir, 'ica-bootstrap.json'),
    },
  };

  requireFile(inputs.controller.csr, 'controller CSR');
  requireFile(inputs.controller.did, 'controller DID document');
  requireFile(inputs.controller.jwk, 'controller JWK');
  requireFile(inputs.ica.csr, 'ICA signing CSR');
  requireFile(inputs.ica.did, 'ICA DID document');
  requireFile(inputs.ica.jwk, 'ICA signing JWK');

  const output = {
    controller: {
      csr: path.join(outDir, 'controller', 'controller.csr.pem'),
      did: path.join(outDir, 'controller', 'controller-did.json'),
      jwk: path.join(outDir, 'controller', 'controller-public-jwk.json'),
    },
    ica: {
      csr: path.join(outDir, 'ica', 'ica-signing.csr.pem'),
      did: path.join(outDir, 'ica', 'ica-did.json'),
      jwk: path.join(outDir, 'ica', 'ica-signing-public-jwk.json'),
      activateTemplate: path.join(outDir, 'ica', 'activate-request.template.json'),
    },
  };

  ensureDir(path.dirname(output.controller.csr));
  ensureDir(path.dirname(output.ica.csr));

  cpSync(inputs.controller.csr, output.controller.csr, { force: true });
  cpSync(inputs.controller.did, output.controller.did, { force: true });
  cpSync(inputs.controller.jwk, output.controller.jwk, { force: true });

  cpSync(inputs.ica.csr, output.ica.csr, { force: true });
  cpSync(inputs.ica.did, output.ica.did, { force: true });
  cpSync(inputs.ica.jwk, output.ica.jwk, { force: true });

  const activateTemplateInput = path.join(icaDir, 'activate-request.template.json');
  if (existsSync(activateTemplateInput)) {
    cpSync(activateTemplateInput, output.ica.activateTemplate, { force: true });
  }

  const controllerMetadata = readJsonIfExists(inputs.controller.metadata);
  const icaMetadata = readJsonIfExists(inputs.ica.metadata);

  writeJson(path.join(outDir, 'manifest.json'), {
    requestId,
    generatedAt: new Date().toISOString(),
    command: 'ca:prepare-submission',
    bucketLayout: {
      controller: {
        csr: 'controller/controller.csr.pem',
        did: 'controller/controller-did.json',
        jwk: 'controller/controller-public-jwk.json',
      },
      ica: {
        csr: 'ica/ica-signing.csr.pem',
        did: 'ica/ica-did.json',
        jwk: 'ica/ica-signing-public-jwk.json',
        activateTemplate: existsSync(activateTemplateInput) ? 'ica/activate-request.template.json' : null,
      },
    },
    controller: controllerMetadata
      ? {
        did: controllerMetadata.controllerDid || null,
        kid: controllerMetadata.kid || null,
        emailHash: controllerMetadata.controllerEmailHash || null,
      }
      : null,
    ica: icaMetadata
      ? {
        did: icaMetadata.issuerDid || null,
        kid: icaMetadata.kid || null,
        scope: icaMetadata.scope || null,
        jurisdiction: icaMetadata.jurisdiction || null,
      }
      : null,
    source: {
      controllerDir,
      icaDir,
    },
  });

  console.log(`CA submission prepared in ${outDir}`);
  console.log(`- requestId: ${requestId}`);
  console.log(`- manifest: ${path.join(outDir, 'manifest.json')}`);
  console.log(`- controller CSR: ${output.controller.csr}`);
  console.log(`- ICA CSR: ${output.ica.csr}`);
}
