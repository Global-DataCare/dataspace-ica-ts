#!/usr/bin/env node

import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const SUPPORTED_SCOPES = [
  'health-care:reader',
  'health-care:provider',
  'health-tech:provider',
  'health-research:provider',
  'health-research:reader',
  'animal-care:reader',
  'animal-care:provider',
  'animal-research:provider',
  'animal-research:reader',
  'health-insurance:provider',
  'health-insurance:reader',
  'vet-insurance:provider',
  'vet-insurance:reader',
];

function printHelp() {
  console.log(`
ica-cli (private)

Usage:
  ica-cli domain:reserve --domain <domain> --request-id <id>
  ica-cli domain:activate --domain <domain> --request-id <id>

  ica-cli ca:init-root --common-name <cn> [--country ES] [--out-dir ca/root] [--days 3650] [--force]
  ica-cli ca:init-ica \
    --common-name <cn> \
    --root-key <ca/root/root-key.pem> \
    --root-cert <ca/root/root-cert.pem> \
    [--country ES] [--out-dir ca/ica] [--days 1825] [--force]

  ica-cli request:ingest --bundle <submission.tgz> --request-id <id> [--requests-dir requests]
  ica-cli request:validate --request-id <id> [--requests-dir requests] [--allowed-isco 1219,2421] [--allowed-sectors health-research:provider,animal-care:provider]
  ica-cli request:approve --request-id <id> [--requests-dir requests]

  ica-cli csr:sign-batch \
    (--request-id <id> | --all) \
    --ica-key <ca/ica/ica-key.pem> \
    --ica-cert <ca/ica/ica-cert.pem> \
    --root-cert <ca/root/root-cert.pem> \
    [--days 730] \
    [--ica-name onehealth-ica.accuro.es.pem] \
    [--root-name root-unid.pem] \
    [--requests-dir requests]

  ica-cli publish:client --request-id <id> --client-repo <path> [--requests-dir requests]

  ica-cli dcat:add-service \
    --ica-public-repo <path> \
    --endpoint-url <https-url> \
    --publisher-did <did:web:ica...> \
    [--service-did <did:web:service...>] \
    [--service-title "<title>"] \
    [--service-description "<description>"] \
    [--sign-key <ca/ica/ica-key.pem>]

  ica-cli dcat:build-catalog \
    --ica-public-repo <path> \
    --publisher-did <did:web:ica...> \
    --base-url <https://ica-domain> \
    [--catalog-id <url>] \
    [--title "<title>"] \
    [--description "<description>"] \
    [--sign-key <ca/ica/ica-key.pem>]
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      args[key] = true;
      continue;
    }
    args[key] = next;
    i += 1;
  }
  return args;
}

function requireArg(args, name) {
  const value = args[name];
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`Missing required argument --${name}`);
  }
  return value.trim();
}

function ensureDir(dirPath) {
  mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function runCommand(bin, args, options = {}) {
  try {
    return execFileSync(bin, args, { stdio: 'pipe', ...options }).toString();
  } catch (error) {
    const stderr = error?.stderr?.toString?.() || error?.message || 'unknown error';
    throw new Error(`${bin} ${args.join(' ')} failed: ${stderr}`);
  }
}

function runOpenSsl(args) {
  return runCommand('openssl', args);
}

function normalizeDomain(rawDomain) {
  const trimmed = rawDomain.trim().toLowerCase();
  const withoutProtocol = trimmed.replace(/^https?:\/\//, '');
  return withoutProtocol.replace(/\/+$/, '');
}

function normalizeSubjectValue(value) {
  return value.replace(/[\/=+<>#;]/g, '_').trim();
}

function requestsDirFromArgs(args) {
  return path.resolve(args['requests-dir'] || 'requests');
}

function statePath(requestDir) {
  return path.join(requestDir, 'state.json');
}

function updateRequestState(requestDir, update) {
  const current = existsSync(statePath(requestDir)) ? readJson(statePath(requestDir)) : {};
  writeJson(statePath(requestDir), {
    ...current,
    ...update,
    updatedAt: new Date().toISOString(),
  });
}

function readPemAsBase64Der(pemPath) {
  const pem = readFileSync(pemPath, 'utf8');
  return pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}

function signAndHashFile(targetPath, signKeyPath) {
  const content = readFileSync(targetPath);
  const digestHex = createHash('sha256').update(content).digest('hex');
  const shaFile = `${targetPath}.sha256`;
  const sigFile = `${targetPath}.sig`;
  writeFileSync(shaFile, `${digestHex}  ${path.basename(targetPath)}\n`);
  if (signKeyPath) {
    runOpenSsl(['dgst', '-sha256', '-sign', signKeyPath, '-out', sigFile, targetPath]);
  }
}

function getRequestDirs(args) {
  const requestsDir = requestsDirFromArgs(args);
  if (args.all) {
    if (!existsSync(requestsDir)) return [];
    return readdirSync(requestsDir)
      .map((entry) => path.join(requestsDir, entry))
      .filter((entryPath) => statSync(entryPath).isDirectory() && existsSync(path.join(entryPath, 'normalized')));
  }

  const requestId = requireArg(args, 'request-id');
  const requestDir = path.join(requestsDir, requestId);
  if (!existsSync(requestDir)) {
    throw new Error(`Request not found: ${requestId}`);
  }
  return [requestDir];
}

function loadReservations(dbPath) {
  if (!existsSync(dbPath)) return { domains: {} };
  return readJson(dbPath);
}

function saveReservations(dbPath, value) {
  writeJson(dbPath, value);
}

function extractDomainFromDid(didValue) {
  if (typeof didValue !== 'string' || !didValue.startsWith('did:web:')) {
    return null;
  }
  const parts = didValue.replace('did:web:', '').split(':');
  return parts[0] || null;
}

function getAllowedSectors(args) {
  const raw = typeof args['allowed-sectors'] === 'string'
    ? args['allowed-sectors']
    : SUPPORTED_SCOPES.join(',');
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

function cmdDomainReserve(args) {
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const requestId = requireArg(args, 'request-id');
  const dbPath = path.resolve(args.db || path.join('reservations', 'domains.json'));
  const data = loadReservations(dbPath);
  const current = data.domains[domain];
  if (current && current.status === 'active' && current.requestId !== requestId) {
    throw new Error(`Domain ${domain} already active for request ${current.requestId}.`);
  }
  data.domains[domain] = {
    requestId,
    status: 'reserved',
    reservedAt: new Date().toISOString(),
  };
  saveReservations(dbPath, data);
  console.log(`Reserved domain ${domain} for request ${requestId}`);
}

function cmdDomainActivate(args) {
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const requestId = requireArg(args, 'request-id');
  const dbPath = path.resolve(args.db || path.join('reservations', 'domains.json'));
  const data = loadReservations(dbPath);
  const current = data.domains[domain];
  if (!current) {
    throw new Error(`Domain ${domain} not found in reservations.`);
  }
  if (current.requestId !== requestId) {
    throw new Error(`Domain ${domain} is reserved for ${current.requestId}, not ${requestId}.`);
  }
  data.domains[domain] = {
    ...current,
    status: 'active',
    activatedAt: new Date().toISOString(),
  };
  saveReservations(dbPath, data);
  console.log(`Activated domain ${domain} for request ${requestId}`);
}

function cmdCaInitRoot(args) {
  const commonName = requireArg(args, 'common-name');
  const country = (args.country || 'ES').toUpperCase();
  const outDir = path.resolve(args['out-dir'] || path.join('ca', 'root'));
  const days = Number.parseInt(args.days || '3650', 10);
  if (Number.isNaN(days) || days <= 0) throw new Error('--days must be a positive integer.');

  if (existsSync(outDir) && args.force) {
    rmSync(outDir, { recursive: true, force: true });
  }
  ensureDir(outDir);

  const keyPath = path.join(outDir, 'root-key.pem');
  const certPath = path.join(outDir, 'root-cert.pem');
  const certDerPath = path.join(outDir, 'root-cert.der');
  runOpenSsl(['ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', keyPath]);
  runOpenSsl([
    'req',
    '-x509',
    '-new',
    '-sha384',
    '-key',
    keyPath,
    '-out',
    certPath,
    '-days',
    `${days}`,
    '-subj',
    `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}`,
  ]);
  runOpenSsl(['x509', '-in', certPath, '-outform', 'der', '-out', certDerPath]);

  console.log(`Root CA generated in ${outDir}`);
}

function cmdCaInitIca(args) {
  const commonName = requireArg(args, 'common-name');
  const rootKey = path.resolve(requireArg(args, 'root-key'));
  const rootCert = path.resolve(requireArg(args, 'root-cert'));
  const country = (args.country || 'ES').toUpperCase();
  const outDir = path.resolve(args['out-dir'] || path.join('ca', 'ica'));
  const days = Number.parseInt(args.days || '1825', 10);
  if (Number.isNaN(days) || days <= 0) throw new Error('--days must be a positive integer.');

  if (existsSync(outDir) && args.force) {
    rmSync(outDir, { recursive: true, force: true });
  }
  ensureDir(outDir);

  const keyPath = path.join(outDir, 'ica-key.pem');
  const csrPath = path.join(outDir, 'ica.csr.pem');
  const certPath = path.join(outDir, 'ica-cert.pem');
  const certDerPath = path.join(outDir, 'ica-cert.der');
  const chainPath = path.join(outDir, 'chain.pem');

  runOpenSsl(['ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', keyPath]);
  runOpenSsl([
    'req',
    '-new',
    '-sha384',
    '-key',
    keyPath,
    '-out',
    csrPath,
    '-subj',
    `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}`,
  ]);
  runOpenSsl([
    'x509',
    '-req',
    '-in',
    csrPath,
    '-CA',
    rootCert,
    '-CAkey',
    rootKey,
    '-CAcreateserial',
    '-out',
    certPath,
    '-days',
    `${days}`,
    '-sha384',
  ]);
  runOpenSsl(['x509', '-in', certPath, '-outform', 'der', '-out', certDerPath]);

  const chain = `${readFileSync(certPath, 'utf8')}${readFileSync(rootCert, 'utf8')}`;
  writeFileSync(chainPath, chain);

  console.log(`ICA certificate generated in ${outDir}`);
}

function cmdRequestIngest(args) {
  const bundle = path.resolve(requireArg(args, 'bundle'));
  const requestId = requireArg(args, 'request-id');
  const requestsDir = requestsDirFromArgs(args);
  if (!existsSync(bundle)) throw new Error(`Bundle not found: ${bundle}`);

  const requestDir = path.join(requestsDir, requestId);
  const intakeDir = path.join(requestDir, 'intake');
  const normalizedDir = path.join(requestDir, 'normalized');
  if (existsSync(normalizedDir)) {
    rmSync(normalizedDir, { recursive: true, force: true });
  }
  ensureDir(intakeDir);
  ensureDir(normalizedDir);

  const intakeBundle = path.join(intakeDir, 'submission.tgz');
  writeFileSync(intakeBundle, readFileSync(bundle));
  runCommand('tar', ['-xzf', intakeBundle, '-C', normalizedDir]);

  updateRequestState(requestDir, {
    requestId,
    status: 'ingested',
    ingestedAt: new Date().toISOString(),
  });
  console.log(`Ingested request ${requestId}`);
}

function cmdRequestValidate(args) {
  const requestId = requireArg(args, 'request-id');
  const requestsDir = requestsDirFromArgs(args);
  const requestDir = path.join(requestsDir, requestId);
  const normalizedDir = path.join(requestDir, 'normalized');
  if (!existsSync(normalizedDir)) throw new Error(`Normalized request not found: ${requestId}`);

  const errors = [];
  const warnings = [];
  const didPath = path.join(normalizedDir, '.well-known', 'did.json');
  const jwksPath = path.join(normalizedDir, '.well-known', 'jwks.json');
  const vcPath = path.join(normalizedDir, '.well-known', 'vc.json');
  const orgProfilePath = path.join(normalizedDir, 'onboarding', 'state', 'organization-profile.json');

  if (!existsSync(didPath)) errors.push('Missing .well-known/did.json');
  if (!existsSync(jwksPath)) errors.push('Missing .well-known/jwks.json');
  if (!existsSync(vcPath)) errors.push('Missing .well-known/vc.json');
  if (!existsSync(orgProfilePath)) errors.push('Missing onboarding/state/organization-profile.json');

  let orgDomain = null;
  if (existsSync(didPath)) {
    const didDoc = readJson(didPath);
    orgDomain = extractDomainFromDid(didDoc.id);
    if (!orgDomain) {
      errors.push('Invalid organization DID in .well-known/did.json');
    }
  }

  if (orgDomain) {
    const orgCsrPath = path.join(normalizedDir, 'pki', `${orgDomain}.csr.pem`);
    if (!existsSync(orgCsrPath)) {
      errors.push(`Missing organization CSR: pki/${orgDomain}.csr.pem`);
    }
  }

  const evidencePdf = path.join(normalizedDir, 'evidence', 'terms-fnmt-signed.pdf');
  if (!existsSync(evidencePdf)) {
    warnings.push('Missing evidence/terms-fnmt-signed.pdf');
  }

  const allowedIsco = args['allowed-isco']
    ? new Set(args['allowed-isco'].split(',').map((r) => r.trim()).filter(Boolean))
    : null;
  const allowedSectors = getAllowedSectors(args);
  let orgSector = null;
  if (existsSync(orgProfilePath)) {
    const profile = readJson(orgProfilePath);
    orgSector = (profile?.sector || '').toLowerCase();
    if (!orgSector) {
      errors.push('organization-profile.json missing "sector"');
    } else if (!allowedSectors.has(orgSector)) {
      errors.push(`sector ${orgSector} not allowed`);
    }
  }

  const employeeRoot = path.join(normalizedDir, 'employee', 'multibase');
  const employeeResults = [];
  if (existsSync(employeeRoot)) {
    for (const employeeId of readdirSync(employeeRoot)) {
      const employeeDir = path.join(employeeRoot, employeeId);
      if (!statSync(employeeDir).isDirectory()) continue;

      const didFile = path.join(employeeDir, 'did.json');
      const vcFile = path.join(employeeDir, 'vc.json');
      const csrFile = path.join(normalizedDir, 'pki', `employee-${employeeId}.csr.pem`);
      const employeeErrors = [];

      if (!existsSync(didFile)) employeeErrors.push('Missing did.json');
      if (!existsSync(vcFile)) employeeErrors.push('Missing vc.json');
      if (!existsSync(csrFile)) employeeErrors.push(`Missing CSR pki/employee-${employeeId}.csr.pem`);

      let roleIsco = null;
      if (existsSync(vcFile)) {
        const vc = readJson(vcFile);
        roleIsco = vc?.credentialSubject?.roleIsco || null;
      }
      if (allowedIsco && roleIsco && !allowedIsco.has(roleIsco)) {
        employeeErrors.push(`roleIsco ${roleIsco} not allowed`);
      }

      employeeResults.push({
        employeeId,
        roleIsco,
        ok: employeeErrors.length === 0,
        errors: employeeErrors,
      });
      errors.push(...employeeErrors.map((e) => `employee:${employeeId}: ${e}`));
    }
  }

  const report = {
    requestId,
    validatedAt: new Date().toISOString(),
    ok: errors.length === 0,
    organizationDomain: orgDomain,
    organizationSector: orgSector,
    errors,
    warnings,
    employees: employeeResults,
  };
  writeJson(path.join(requestDir, 'validation', 'report.json'), report);
  updateRequestState(requestDir, {
    status: report.ok ? 'validated' : 'validation_failed',
    validatedAt: report.validatedAt,
  });

  if (!report.ok) {
    throw new Error(`Validation failed with ${errors.length} error(s). See requests/${requestId}/validation/report.json`);
  }
  console.log(`Request ${requestId} validated`);
}

function cmdRequestApprove(args) {
  const requestId = requireArg(args, 'request-id');
  const requestDir = path.join(requestsDirFromArgs(args), requestId);
  if (!existsSync(requestDir)) throw new Error(`Request not found: ${requestId}`);
  updateRequestState(requestDir, {
    status: 'approved',
    approvedAt: new Date().toISOString(),
  });
  console.log(`Request ${requestId} approved`);
}

function cmdCsrSignBatch(args) {
  const requestDirs = getRequestDirs(args);
  if (requestDirs.length === 0) {
    console.log('No requests found.');
    return;
  }

  const icaKey = path.resolve(requireArg(args, 'ica-key'));
  const icaCert = path.resolve(requireArg(args, 'ica-cert'));
  const rootCert = path.resolve(requireArg(args, 'root-cert'));
  const days = Number.parseInt(args.days || '730', 10);
  if (Number.isNaN(days) || days <= 0) throw new Error('--days must be a positive integer.');

  const icaCertName = args['ica-name'] || 'ica.pem';
  const rootCertName = args['root-name'] || 'root-unid.pem';
  const icaX5c = readPemAsBase64Der(icaCert);
  const rootX5c = readPemAsBase64Der(rootCert);

  for (const requestDir of requestDirs) {
    const requestId = path.basename(requestDir);
    const normalizedDir = path.join(requestDir, 'normalized');
    const pkiDir = path.join(normalizedDir, 'pki');
    if (!existsSync(pkiDir)) {
      throw new Error(`Missing pki directory in request ${requestId}`);
    }

    const signedDir = path.join(requestDir, 'signed');
    const publishRepo = path.join(requestDir, 'publish', 'repo');
    rmSync(signedDir, { recursive: true, force: true });
    rmSync(path.join(requestDir, 'publish'), { recursive: true, force: true });
    ensureDir(signedDir);
    ensureDir(path.dirname(publishRepo));
    cpSync(normalizedDir, publishRepo, { recursive: true, force: true });

    const csrFiles = readdirSync(pkiDir).filter((f) => f.endsWith('.csr.pem'));
    if (csrFiles.length === 0) {
      throw new Error(`No CSR files found in request ${requestId}`);
    }

    const signedArtifacts = [];
    for (const csrFile of csrFiles) {
      const csrPath = path.join(pkiDir, csrFile);
      const baseName = csrFile.replace(/\.csr\.pem$/, '');
      const certPath = path.join(signedDir, `${baseName}.pem`);
      const chainPath = path.join(signedDir, `${baseName}.chain.pem`);
      runOpenSsl([
        'x509',
        '-req',
        '-in',
        csrPath,
        '-CA',
        icaCert,
        '-CAkey',
        icaKey,
        '-CAcreateserial',
        '-out',
        certPath,
        '-days',
        `${days}`,
        '-sha384',
      ]);
      const chainPem = `${readFileSync(certPath, 'utf8')}${readFileSync(icaCert, 'utf8')}${readFileSync(rootCert, 'utf8')}`;
      writeFileSync(chainPath, chainPem);

      const publishPkiDir = path.join(publishRepo, 'pki');
      ensureDir(publishPkiDir);
      writeFileSync(path.join(publishPkiDir, `${baseName}.pem`), readFileSync(certPath));
      writeFileSync(path.join(publishPkiDir, `${baseName}.chain.pem`), chainPem);
      const publishCsrPath = path.join(publishPkiDir, csrFile);
      if (existsSync(publishCsrPath)) unlinkSync(publishCsrPath);

      signedArtifacts.push({ csr: csrFile, cert: `${baseName}.pem`, chain: `${baseName}.chain.pem` });
    }

    const publishPkiDir = path.join(publishRepo, 'pki');
    writeFileSync(path.join(publishPkiDir, icaCertName), readFileSync(icaCert));
    writeFileSync(path.join(publishPkiDir, rootCertName), readFileSync(rootCert));

    const orgDidPath = path.join(publishRepo, '.well-known', 'did.json');
    if (existsSync(orgDidPath)) {
      const orgDid = readJson(orgDidPath)?.id;
      const orgDomain = extractDomainFromDid(orgDid);
      if (orgDomain) {
        const orgCertPath = path.join(signedDir, `${orgDomain}.pem`);
        const orgJwksPath = path.join(publishRepo, '.well-known', 'jwks.json');
        if (existsSync(orgCertPath) && existsSync(orgJwksPath)) {
          const orgJwks = readJson(orgJwksPath);
          const certX5c = readPemAsBase64Der(orgCertPath);
          if (Array.isArray(orgJwks.keys) && orgJwks.keys.length > 0) {
            orgJwks.keys[0].x5c = [certX5c, icaX5c, rootX5c];
            writeJson(orgJwksPath, orgJwks);
          }
        }
      }
    }

    const employeeRoot = path.join(publishRepo, 'employee', 'multibase');
    if (existsSync(employeeRoot)) {
      for (const employeeId of readdirSync(employeeRoot)) {
        const employeeDir = path.join(employeeRoot, employeeId);
        if (!statSync(employeeDir).isDirectory()) continue;
        const employeeCertPath = path.join(signedDir, `employee-${employeeId}.pem`);
        const employeeJwksPath = path.join(employeeDir, 'jwks.json');
        if (!existsSync(employeeCertPath) || !existsSync(employeeJwksPath)) continue;
        const employeeJwks = readJson(employeeJwksPath);
        if (Array.isArray(employeeJwks.keys) && employeeJwks.keys.length > 0) {
          employeeJwks.keys[0].x5c = [readPemAsBase64Der(employeeCertPath), icaX5c, rootX5c];
          writeJson(employeeJwksPath, employeeJwks);
        }
      }
    }

    writeJson(path.join(signedDir, 'report.json'), {
      requestId,
      signedAt: new Date().toISOString(),
      artifacts: signedArtifacts,
      icaCertName,
      rootCertName,
    });
    updateRequestState(requestDir, {
      status: 'signed',
      signedAt: new Date().toISOString(),
    });

    console.log(`Signed request ${requestId}: ${signedArtifacts.length} CSR(s)`);
  }
}

function cmdPublishClient(args) {
  const requestId = requireArg(args, 'request-id');
  const clientRepo = path.resolve(requireArg(args, 'client-repo'));
  const requestDir = path.join(requestsDirFromArgs(args), requestId);
  const publishRepo = path.join(requestDir, 'publish', 'repo');
  if (!existsSync(publishRepo)) {
    throw new Error(`Missing publish output for request ${requestId}. Run csr:sign-batch first.`);
  }
  ensureDir(clientRepo);
  for (const entry of readdirSync(publishRepo)) {
    cpSync(path.join(publishRepo, entry), path.join(clientRepo, entry), { recursive: true, force: true });
  }
  updateRequestState(requestDir, {
    status: 'published',
    publishedAt: new Date().toISOString(),
  });
  console.log(`Published request ${requestId} to ${clientRepo}`);
}

function cmdDcatAddService(args) {
  const icaPublicRepo = path.resolve(requireArg(args, 'ica-public-repo'));
  const endpointUrl = requireArg(args, 'endpoint-url');
  const publisherDid = requireArg(args, 'publisher-did');
  const serviceTitle = args['service-title'] || 'Data Service';
  const serviceDescription = args['service-description'] || 'Data service published by ICA';
  const serviceDid = args['service-did'] || `did:web:${new URL(endpointUrl).host}`;
  const signKey = args['sign-key'] ? path.resolve(args['sign-key']) : null;

  const serviceHost = new URL(endpointUrl).host;
  const fileName = `dcat3_animal-index_${serviceHost}.jsonld`;
  const dcatDir = path.join(icaPublicRepo, 'dsp', 'dcat3', 'animal-index');
  ensureDir(dcatDir);
  const targetPath = path.join(dcatDir, fileName);

  const serviceDoc = {
    '@context': [
      'https://w3id.org/dspace/2025/1/context.jsonld',
      {
        dcat: 'http://www.w3.org/ns/dcat#',
        dct: 'http://purl.org/dc/terms/',
        sec: 'https://w3id.org/security#',
      },
    ],
    '@id': serviceDid,
    '@type': 'dcat:DataService',
    'dct:title': serviceTitle,
    'dct:description': serviceDescription,
    'dct:publisher': publisherDid,
    'dcat:endpointURL': endpointUrl,
    'sec:signature': {
      type: 'DetachedSignature',
      algorithm: 'SHA-256',
      signatureFile: `${fileName}.sig`,
    },
  };

  writeJson(targetPath, serviceDoc);
  signAndHashFile(targetPath, signKey);
  console.log(`DCAT service generated: ${targetPath}`);
}

function cmdDcatBuildCatalog(args) {
  const icaPublicRepo = path.resolve(requireArg(args, 'ica-public-repo'));
  const publisherDid = requireArg(args, 'publisher-did');
  const baseUrl = requireArg(args, 'base-url').replace(/\/+$/, '');
  const catalogId = args['catalog-id'] || `${baseUrl}/dsp/dcat3/catalog`;
  const title = args.title || 'ICA Catalog';
  const description = args.description || 'Catalog of ICA services';
  const signKey = args['sign-key'] ? path.resolve(args['sign-key']) : null;

  const animalDir = path.join(icaPublicRepo, 'dsp', 'dcat3', 'animal-index');
  ensureDir(animalDir);
  const serviceFiles = readdirSync(animalDir).filter((f) => f.endsWith('.jsonld'));
  const serviceRefs = serviceFiles.map((fileName) => ({
    '@id': `${baseUrl}/dsp/dcat3/animal-index/${fileName}`,
  }));

  const catalog = {
    '@context': [
      'https://w3id.org/dspace/2025/1/context.jsonld',
      {
        dcat: 'http://www.w3.org/ns/dcat#',
        dct: 'http://purl.org/dc/terms/',
      },
    ],
    '@id': catalogId,
    '@type': 'dcat:Catalog',
    'dct:title': title,
    'dct:description': description,
    'dct:publisher': {
      '@id': publisherDid,
    },
    'dcat:service': serviceRefs,
  };

  const catalogPath = path.join(icaPublicRepo, 'dsp', 'dcat3', 'catalog.jsonld');
  writeJson(catalogPath, catalog);
  signAndHashFile(catalogPath, signKey);
  console.log(`DCAT catalog generated: ${catalogPath}`);
}

async function main() {
  const [, , command, ...rest] = process.argv;
  if (!command || command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    return;
  }
  const args = parseArgs(rest);

  switch (command) {
    case 'domain:reserve':
      cmdDomainReserve(args);
      return;
    case 'domain:activate':
      cmdDomainActivate(args);
      return;
    case 'ca:init-root':
      cmdCaInitRoot(args);
      return;
    case 'ca:init-ica':
      cmdCaInitIca(args);
      return;
    case 'request:ingest':
      cmdRequestIngest(args);
      return;
    case 'request:validate':
      cmdRequestValidate(args);
      return;
    case 'request:approve':
      cmdRequestApprove(args);
      return;
    case 'csr:sign-batch':
      cmdCsrSignBatch(args);
      return;
    case 'publish:client':
      cmdPublishClient(args);
      return;
    case 'dcat:add-service':
      cmdDcatAddService(args);
      return;
    case 'dcat:build-catalog':
      cmdDcatBuildCatalog(args);
      return;
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
