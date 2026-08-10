#!/usr/bin/env node
/**
 * Exporta VCs de organizaciones y representantes desde Firestore ICA
 * a estructura discovery/ para repositorio publico.
 *
 * Estructura de salida:
 * discovery/<namespace>/ica/organization/VATES-<VAT>/vc-contract-organization-<timestamp>.json
 * discovery/<namespace>/ica/organization-representative/VATES-<VAT>/vc-contract-representative-<timestamp>.json
 * discovery/logs/*.txt
 *
 * Uso:
 *   node scripts/export-discovery-vcs.mjs --project <project> --prefix dev --namespace <namespace>
 *   node scripts/export-discovery-vcs.mjs --project <project> --prefix parallel-staging --outdir discovery --tenant ica
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

function parseArgs(argv) {
  const args = {
    project: process.env.FIRESTORE_PROJECT_ID || '',
    prefix: 'dev',
    outdir: 'discovery',
    namespace: '',
    tenant: '',
    jurisdiction: '',
    sector: '',
    includeAllVersions: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--project') { args.project = argv[++i] || args.project; continue; }
    if (arg === '--prefix') { args.prefix = argv[++i] || args.prefix; continue; }
    if (arg === '--outdir') { args.outdir = argv[++i] || args.outdir; continue; }
    if (arg === '--namespace') { args.namespace = argv[++i] || ''; continue; }
    if (arg === '--tenant') { args.tenant = argv[++i] || ''; continue; }
    if (arg === '--jurisdiction') { args.jurisdiction = argv[++i] || ''; continue; }
    if (arg === '--sector') { args.sector = argv[++i] || ''; continue; }
    if (arg === '--all') { args.includeAllVersions = true; continue; }
    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }
  return args;
}

function printHelp() {
  console.log(
    [
      'Usage:',
      '  node scripts/export-discovery-vcs.mjs --project <gcp-project> --prefix <collection-prefix> [options]',
      '',
      'Options:',
      '  --project <id>       Firestore project ID (or FIRESTORE_PROJECT_ID)',
      '  --prefix <value>     Collection prefix (default: dev)',
      '  --outdir <path>      Output root (default: discovery)',
      '  --namespace <name>   Discovery namespace (default: inferred from project)',
      '  --tenant <id>        Optional tenant filter (e.g. ica)',
      '  --jurisdiction <id>  Optional jurisdiction filter (e.g. ES)',
      '  --sector <id>        Optional sector filter (e.g. health-care)',
      '  --all                Export all versions (default: latest per VAT+type)',
    ].join('\n'),
  );
}

function colName(prefix, leaf) {
  const normalized = String(prefix || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized ? `${normalized}_${leaf}` : leaf;
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

function sanitizeTimestampForFilename(input) {
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) return '';
  const yyyy = date.getUTCFullYear();
  const mm = String(date.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(date.getUTCDate()).padStart(2, '0');
  const hh = String(date.getUTCHours()).padStart(2, '0');
  const mi = String(date.getUTCMinutes()).padStart(2, '0');
  const ss = String(date.getUTCSeconds()).padStart(2, '0');
  return `${yyyy}${mm}${dd}${hh}${mi}${ss}`;
}

function extractVerifierVisualTimestampFromCredential(credential, fallbackA, fallbackB) {
  const evidence = Array.isArray(credential?.evidence) ? credential.evidence : [];
  const documentEvidence = evidence.find((entry) => asString(entry?.type) === 'document');
  const documentTime = asString(documentEvidence?.time);
  if (documentTime) return documentTime;
  return asString(fallbackA) || asString(fallbackB) || '';
}

function detectCredentialKind(credential, credentialTypeField) {
  const typeValues = Array.isArray(credential?.type)
    ? credential.type.map((value) => asString(value))
    : [asString(credential?.type), asString(credentialTypeField)].filter(Boolean);

  const joined = typeValues.join(',').toLowerCase();
  const subject = asObject(credential?.credentialSubject);
  const subjectType = asString(subject?.['@type']).toLowerCase();

  const isOrganization =
    joined.includes('organizationcredential')
    || joined.includes('organization-verification')
    || subjectType === 'organization';

  const isRepresentative =
    joined.includes('legalrepresentativecredential')
    || joined.includes('legalrepresentative-verification')
    || (subjectType === 'person' && asObject(subject?.memberOf));

  if (isOrganization) return 'organization';
  if (isRepresentative) return 'organization-representative';
  return '';
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

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
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

function toMillis(value) {
  const ms = Date.parse(asString(value));
  return Number.isNaN(ms) ? 0 : ms;
}

function pickLatest(records) {
  return [...records].sort((a, b) => {
    const left = Math.max(toMillis(a.updatedAt), toMillis(a.createdAt));
    const right = Math.max(toMillis(b.updatedAt), toMillis(b.createdAt));
    return right - left;
  })[0];
}

function applyScopeFilters(record, args) {
  if (args.tenant && asString(record.tenantId).toLowerCase() !== args.tenant.toLowerCase()) return false;
  if (args.jurisdiction && asString(record.jurisdiction).toLowerCase() !== args.jurisdiction.toLowerCase()) return false;
  if (args.sector && asString(record.sector).toLowerCase() !== args.sector.toLowerCase()) return false;
  return true;
}

function buildOutputPath(outRoot, namespace, kind, vat, timestamp, counter) {
  const vatDir = `VATES-${normalizeVat(vat)}`;
  const baseName = kind === 'organization'
    ? `vc-contract-organization-${timestamp}`
    : `vc-contract-representative-${timestamp}`;
  const fileName = counter > 0 ? `${baseName}-${counter}.json` : `${baseName}.json`;
  return path.join(
    outRoot,
    namespace,
    'ica',
    kind,
    vatDir,
    fileName,
  );
}

function resolveDiscoveryNamespace(_project, explicitNamespace) {
  const normalizedExplicit = asString(explicitNamespace).toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
  if (normalizedExplicit) return normalizedExplicit;
  return 'dataspace';
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.project) {
    throw new Error('--project or FIRESTORE_PROJECT_ID is required');
  }
  const issuedCollection = colName(args.prefix, 'issued_credentials');
  const discoveryNamespace = resolveDiscoveryNamespace(args.project, args.namespace);

  const require = createRequire(import.meta.url);
  let Firestore;
  try {
    ({ Firestore } = require('@google-cloud/firestore'));
  } catch {
    console.error('ERROR: @google-cloud/firestore no disponible. Ejecuta npm install en dataspace-ica-ts.');
    process.exit(1);
  }

  const db = new Firestore({ projectId: args.project, ignoreUndefinedProperties: true });
  const snap = await db.collection(issuedCollection).get();
  const docs = snap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

  const scoped = docs.filter((record) => applyScopeFilters(record, args));
  const parsed = scoped
    .map((record) => {
      const credential = asObject(record.credential);
      if (!credential) return undefined;
      const kind = detectCredentialKind(credential, record.credentialType);
      if (!kind) return undefined;
      const vat = extractVatFromCredential(kind, credential);
      if (!vat) return undefined;
      const verifierTimestampIso = extractVerifierVisualTimestampFromCredential(
        credential,
        record.updatedAt,
        record.createdAt,
      );
      const ts = sanitizeTimestampForFilename(verifierTimestampIso || record.updatedAt || record.createdAt);
      const tsSafe = ts || '00000000000000';
      const documentEvidence = Array.isArray(credential.evidence)
        ? credential.evidence.find((entry) => asString(entry?.type) === 'document')
        : undefined;
      const pdfLink = asString(documentEvidence?.attachments?.url);
      return {
        id: record.id,
        kind,
        vat,
        verifierTimestampIso: verifierTimestampIso || '',
        timestampSafe: tsSafe,
        credential,
        tenantId: asString(record.tenantId),
        jurisdiction: asString(record.jurisdiction),
        sector: asString(record.sector),
        createdAt: asString(record.createdAt),
        updatedAt: asString(record.updatedAt),
        pdfLink,
      };
    })
    .filter(Boolean);

  const grouped = new Map();
  for (const item of parsed) {
    const key = `${item.vat}::${item.kind}`;
    const list = grouped.get(key) || [];
    list.push(item);
    grouped.set(key, list);
  }

  const selected = [];
  for (const entries of grouped.values()) {
    if (args.includeAllVersions) {
      selected.push(...entries);
    } else {
      selected.push(pickLatest(entries));
    }
  }

  const outRoot = path.resolve(args.outdir);
  const logRoot = path.join(outRoot, 'logs', args.project);
  ensureDir(logRoot);

  const now = new Date();
  const runTag = sanitizeTimestampForFilename(now.toISOString()) || String(Date.now());
  const summaryLines = [];
  const pdfLinkLines = [];
  const missingPdfLinkLines = [];
  const vatLines = [];

  const fileCollisions = new Map();
  for (const item of selected) {
    const key = `${item.kind}::${item.vat}::${item.timestampSafe}`;
    const count = (fileCollisions.get(key) || 0) + 1;
    fileCollisions.set(key, count);
    const outPath = buildOutputPath(
      outRoot,
      discoveryNamespace,
      item.kind,
      item.vat,
      item.timestampSafe,
      count - 1,
    );
    writeJsonFile(outPath, sanitizeCredentialForDiscovery(item.credential));

    summaryLines.push(
      [
        `id=${item.id}`,
        `kind=${item.kind}`,
        `vat=${item.vat}`,
        `tenant=${item.tenantId}`,
        `jurisdiction=${item.jurisdiction}`,
        `sector=${item.sector}`,
        `verifierTimestamp=${item.verifierTimestampIso || '-'}`,
        `file=${outPath}`,
      ].join(' | '),
    );

    vatLines.push(`${item.vat}\t${item.kind}\t${item.id}`);
    if (item.pdfLink) {
      pdfLinkLines.push(`${item.vat}\t${item.kind}\t${item.id}\t${item.pdfLink}`);
    } else {
      missingPdfLinkLines.push(`${item.vat}\t${item.kind}\t${item.id}`);
    }
  }

  const uniqueVats = [...new Set(selected.map((item) => item.vat))].sort();
  writeTextFile(path.join(logRoot, `export-summary-${runTag}.txt`), [
    `project=${args.project}`,
    `prefix=${args.prefix}`,
    `collection=${issuedCollection}`,
    `namespace=${discoveryNamespace}`,
    `outdir=${outRoot}`,
    `records_scanned=${docs.length}`,
    `records_scoped=${scoped.length}`,
    `records_parsed=${parsed.length}`,
    `records_exported=${selected.length}`,
    `unique_vats=${uniqueVats.length}`,
    '',
    ...summaryLines,
  ]);
  writeTextFile(path.join(logRoot, `vats-${runTag}.txt`), uniqueVats);
  writeTextFile(path.join(logRoot, `vat-records-${runTag}.txt`), vatLines.length ? vatLines : ['']);
  writeTextFile(path.join(logRoot, `pdf-links-${runTag}.txt`), pdfLinkLines.length ? pdfLinkLines : ['']);
  writeTextFile(
    path.join(logRoot, `missing-pdf-links-${runTag}.txt`),
    missingPdfLinkLines.length ? missingPdfLinkLines : [''],
  );

  console.log('Export completed.');
  console.log(`  Project:            ${args.project}`);
  console.log(`  Prefix:             ${args.prefix}`);
  console.log(`  Issued collection:  ${issuedCollection}`);
  console.log(`  Namespace:          ${discoveryNamespace}`);
  console.log(`  Exported records:   ${selected.length}`);
  console.log(`  Unique VATs:        ${uniqueVats.length}`);
  console.log(`  Output root:        ${outRoot}`);
  console.log(`  Logs:               ${logRoot}`);
}

main().catch((error) => {
  console.error(`ERROR: ${error?.message || String(error)}`);
  process.exit(1);
});
