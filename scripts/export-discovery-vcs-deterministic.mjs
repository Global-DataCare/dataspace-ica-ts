#!/usr/bin/env node
/**
 * Regenera VCs desde PDFs locales (ya descargados) llamando a ICA _verify/_verify-response
 * y exporta en carpeta separada (discovery deterministic).
 *
 * No descarga PDFs. Si no hay PDF local, ese caso no se procesa.
 *
 * Salida:
 * <outdir>/<namespace>/ica/organization/VATES-<VAT>/vc-contract-organization-<timestamp>.json
 * <outdir>/<namespace>/ica/organization-representative/VATES-<VAT>/vc-contract-representative-<timestamp>.json
 * <outdir>/logs/<project>/*.txt
 */

import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

function parseArgs(argv) {
  const args = {
    base: 'http://localhost:8010',
    tenant: 'ica',
    jurisdiction: 'ES',
    sector: 'health-care',
    resource: 'contract',
    namespace: '',
    pdfRoot: 'discovery/default/pdfs',
    outdir: 'discovery-deterministic',
    project: 'default',
    maxAttempts: 40,
    pollDelayMs: 1000,
    limit: 0,
    bearer: '',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--base') { args.base = argv[++i] || args.base; continue; }
    if (arg === '--tenant') { args.tenant = argv[++i] || args.tenant; continue; }
    if (arg === '--jurisdiction' || arg === '--jur') { args.jurisdiction = argv[++i] || args.jurisdiction; continue; }
    if (arg === '--sector') { args.sector = argv[++i] || args.sector; continue; }
    if (arg === '--resource') { args.resource = argv[++i] || args.resource; continue; }
    if (arg === '--namespace') { args.namespace = argv[++i] || ''; continue; }
    if (arg === '--pdf-root') { args.pdfRoot = argv[++i] || args.pdfRoot; continue; }
    if (arg === '--outdir') { args.outdir = argv[++i] || args.outdir; continue; }
    if (arg === '--project') { args.project = argv[++i] || args.project; continue; }
    if (arg === '--max-attempts') {
      const raw = Number(argv[++i]);
      if (!Number.isNaN(raw) && raw > 0) args.maxAttempts = raw;
      continue;
    }
    if (arg === '--poll-delay-ms') {
      const raw = Number(argv[++i]);
      if (!Number.isNaN(raw) && raw > 0) args.pollDelayMs = raw;
      continue;
    }
    if (arg === '--limit') {
      const raw = Number(argv[++i]);
      if (!Number.isNaN(raw) && raw > 0) args.limit = raw;
      continue;
    }
    if (arg === '--bearer') { args.bearer = argv[++i] || ''; continue; }
    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }
  return args;
}

function printHelp() {
  console.log([
    'Usage:',
    '  node scripts/export-discovery-vcs-deterministic.mjs --pdf-root <path> [options]',
    '',
    'Options:',
    '  --base <url>            ICA base URL (default: http://localhost:8010)',
    '  --tenant <id>           Tenant (default: ica)',
    '  --jurisdiction <id>     Jurisdiction (default: ES)',
    '  --sector <id>           Sector (default: health-care)',
    '  --resource <id>         Resource type (default: contract)',
    '  --namespace <name>      Discovery namespace (default: inferred from project)',
    '  --pdf-root <path>       Root folder with downloaded PDFs',
    '  --outdir <path>         Output root (default: discovery-deterministic)',
    '  --project <name>        Project label for logs subfolder',
    '  --max-attempts <n>      Max polling attempts (default: 40)',
    '  --poll-delay-ms <n>     Poll delay (default: 1000)',
    '  --limit <n>             Process only first N PDFs',
    '  --bearer <token>        Optional Authorization bearer token',
  ].join('\n'));
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : undefined;
}

function asString(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeVat(value) {
  const normalized = asString(value).toUpperCase().replace(/^VATES-?/i, '');
  return normalized.replace(/^[A-Z]{2}-/, '');
}

function sanitizeTimestamp(input) {
  const ms = Date.parse(asString(input));
  if (Number.isNaN(ms)) return '00000000000000';
  const d = new Date(ms);
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mi = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${yyyy}${mm}${dd}${hh}${mi}${ss}`;
}

function extractVatFromCredential(kind, credential) {
  const subject = asObject(credential?.credentialSubject);
  if (!subject) return '';
  if (kind === 'organization') {
    return normalizeVat(subject.taxID || subject.taxId);
  }
  const memberOf = asObject(subject.memberOf);
  return normalizeVat(memberOf?.taxID || memberOf?.taxId);
}

function extractDocumentTime(credential) {
  const evidence = Array.isArray(credential?.evidence) ? credential.evidence : [];
  const docEvidence = evidence.find((entry) => asString(entry?.type) === 'document');
  return asString(docEvidence?.time);
}

function writeJsonFile(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function sanitizeCredentialForDiscovery(credentialInput) {
  const credential = JSON.parse(JSON.stringify(credentialInput || {}));
  const evidence = Array.isArray(credential?.evidence) ? credential.evidence : [];
  for (const entry of evidence) {
    if (!entry || typeof entry !== 'object') continue;
    if (asString(entry.type) !== 'document') continue;
    const details = asObject(entry.document_details);
    if (!details) continue;
    if ('annexFormFields' in details) {
      delete details.annexFormFields;
    }
  }
  return credential;
}

function writeTextFile(filePath, lines) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, 'utf8');
}

function walkPdfFiles(rootDir) {
  const files = [];
  function walk(current) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const next = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(next);
        continue;
      }
      if (entry.isFile() && entry.name.toLowerCase().endsWith('.pdf')) {
        files.push(next);
      }
    }
  }
  walk(rootDir);
  return files.sort();
}

function buildAuthHeaders(args, contentType) {
  const headers = { 'content-type': contentType };
  if (args.bearer) headers.authorization = `Bearer ${args.bearer}`;
  return headers;
}

async function postJson(url, payload, args, contentType = 'application/didcomm-plain+json') {
  const response = await fetch(url, {
    method: 'POST',
    headers: buildAuthHeaders(args, contentType),
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, headers: Object.fromEntries(response.headers.entries()), text, json };
}

function resolveLocation(baseUrl, location) {
  if (!location) return '';
  return location.startsWith('http') ? location : `${baseUrl}${location}`;
}

function extractDiagnostics(result) {
  const issues = result?.json?.body?.issues?.issue;
  if (!Array.isArray(issues)) return [];
  return issues
    .map((entry) => asString(entry?.diagnostics))
    .filter(Boolean);
}

async function pollResponse(location, args) {
  for (let attempt = 1; attempt <= args.maxAttempts; attempt += 1) {
    const response = await postJson(location, {}, args, 'application/json');
    if (response.status === 202) {
      await new Promise((resolve) => setTimeout(resolve, args.pollDelayMs));
      continue;
    }
    return response;
  }
  return { status: 599, headers: {}, text: 'poll-timeout', json: null };
}

function buildOutPath(outRoot, namespace, kind, vat, ts, collision) {
  const vatDir = `VATES-${normalizeVat(vat)}`;
  const baseName = kind === 'organization'
    ? `vc-contract-organization-${ts}`
    : `vc-contract-representative-${ts}`;
  const fileName = collision > 0 ? `${baseName}-${collision}.json` : `${baseName}.json`;
  return path.join(outRoot, namespace, 'ica', kind, vatDir, fileName);
}

function resolveDiscoveryNamespace(_project, explicitNamespace) {
  const normalizedExplicit = asString(explicitNamespace).toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
  if (normalizedExplicit) return normalizedExplicit;
  return 'dataspace';
}

function pickCredentialByType(data, typeName) {
  if (!Array.isArray(data)) return undefined;
  return data.find((entry) => asString(entry?.type) === typeName)?.resource;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const baseUrl = args.base.replace(/\/+$/, '');
  const namespace = resolveDiscoveryNamespace(args.project, args.namespace);
  const verifyUrl = `${baseUrl}/${args.tenant}/cds-${args.jurisdiction}/v1/${args.sector}/terms/pdf/${args.resource}/_verify`;
  const pdfRoot = path.resolve(args.pdfRoot);
  const outRoot = path.resolve(args.outdir);
  const logRoot = path.join(outRoot, 'logs', args.project);

  ensureDir(outRoot);
  ensureDir(logRoot);

  let pdfFiles = walkPdfFiles(pdfRoot);
  if (args.limit > 0) pdfFiles = pdfFiles.slice(0, args.limit);

  const runTag = sanitizeTimestamp(new Date().toISOString());
  const okLines = [];
  const failLines = [];
  const summaryLines = [];
  const collisions = new Map();

  for (const pdfPath of pdfFiles) {
    try {
      const pdfBytes = fs.readFileSync(pdfPath);
      const thid = `th-${randomUUID()}`;
      const payload = {
        jti: `req-${randomUUID()}`,
        thid,
        type: 'application/bundle-api+json',
        body: {},
        attachments: [
          {
            id: 'signed-terms',
            media_type: 'application/pdf',
            data: { base64: pdfBytes.toString('base64') },
          },
        ],
      };

      const submit = await postJson(verifyUrl, payload, args);
      if (submit.status !== 202) {
        failLines.push(`${pdfPath}\tsubmit_http_${submit.status}\t${extractDiagnostics(submit).join(' | ')}`);
        continue;
      }
      const pollUrl = resolveLocation(baseUrl, submit.headers.location);
      const final = await pollResponse(pollUrl, args);
      if (final.status !== 200) {
        failLines.push(`${pdfPath}\tpoll_http_${final.status}\t${extractDiagnostics(final).join(' | ')}`);
        continue;
      }

      const data = final?.json?.body?.data;
      const organizationCredential = pickCredentialByType(data, 'Organization-verification-v1.0');
      const representativeCredential = pickCredentialByType(data, 'LegalRepresentative-verification-v1.0');

      if (!organizationCredential) {
        failLines.push(`${pdfPath}\tmissing_organization_credential`);
        continue;
      }

      const orgVat = extractVatFromCredential('organization', organizationCredential);
      if (!orgVat) {
        failLines.push(`${pdfPath}\tmissing_org_vat`);
        continue;
      }
      const tsIso =
        extractDocumentTime(organizationCredential)
        || extractDocumentTime(representativeCredential)
        || new Date().toISOString();
      const ts = sanitizeTimestamp(tsIso);

      const orgKey = `organization::${orgVat}::${ts}`;
      const orgCount = (collisions.get(orgKey) || 0) + 1;
      collisions.set(orgKey, orgCount);
      const orgOut = buildOutPath(outRoot, namespace, 'organization', orgVat, ts, orgCount - 1);
      writeJsonFile(orgOut, sanitizeCredentialForDiscovery(organizationCredential));
      okLines.push(`${pdfPath}\torganization\t${orgVat}\t${orgOut}`);

      if (representativeCredential) {
        const repVat = extractVatFromCredential('organization-representative', representativeCredential) || orgVat;
        const repKey = `representative::${repVat}::${ts}`;
        const repCount = (collisions.get(repKey) || 0) + 1;
        collisions.set(repKey, repCount);
        const repOut = buildOutPath(outRoot, namespace, 'organization-representative', repVat, ts, repCount - 1);
        writeJsonFile(repOut, sanitizeCredentialForDiscovery(representativeCredential));
        okLines.push(`${pdfPath}\torganization-representative\t${repVat}\t${repOut}`);
      } else {
        summaryLines.push(`no_representative_credential\t${pdfPath}\t${orgVat}`);
      }
    } catch (error) {
      failLines.push(`${pdfPath}\texception\t${error?.message || String(error)}`);
    }
  }

  writeTextFile(path.join(logRoot, `deterministic-export-ok-${runTag}.txt`), okLines.length ? okLines : ['']);
  writeTextFile(path.join(logRoot, `deterministic-export-failed-${runTag}.txt`), failLines.length ? failLines : ['']);
  writeTextFile(path.join(logRoot, `deterministic-export-summary-${runTag}.txt`), [
    `base=${baseUrl}`,
    `tenant=${args.tenant}`,
    `jurisdiction=${args.jurisdiction}`,
    `sector=${args.sector}`,
    `resource=${args.resource}`,
    `namespace=${namespace}`,
    `pdfRoot=${pdfRoot}`,
    `outRoot=${outRoot}`,
    `project=${args.project}`,
    `pdfFiles=${pdfFiles.length}`,
    `ok=${okLines.length}`,
    `failed=${failLines.length}`,
    '',
    ...summaryLines,
  ]);

  console.log('Deterministic export completed.');
  console.log(`  Base:            ${baseUrl}`);
  console.log(`  Namespace:       ${namespace}`);
  console.log(`  PDF root:        ${pdfRoot}`);
  console.log(`  Output root:     ${outRoot}`);
  console.log(`  Files processed: ${pdfFiles.length}`);
  console.log(`  OK lines:        ${okLines.length}`);
  console.log(`  Failed lines:    ${failLines.length}`);
  console.log(`  Logs:            ${logRoot}`);
}

main().catch((error) => {
  console.error(`ERROR: ${error?.message || String(error)}`);
  process.exit(1);
});
