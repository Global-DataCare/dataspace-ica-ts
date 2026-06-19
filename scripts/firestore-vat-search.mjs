#!/usr/bin/env node
/**
 * Search Firestore ICA collections for documents related to a VAT.
 *
 * Usage:
 *   node scripts/firestore-vat-search.mjs --vat VATES-B00112233
 *   node scripts/firestore-vat-search.mjs --vat VATES-B00112233 --prefix st-v2
 *   node scripts/firestore-vat-search.mjs --vat VATES-B00112233 --project globaldatacare-ica-dev --json
 */

import { createRequire } from 'node:module';

function parseArgs(argv) {
  const args = {
    vat: '',
    prefix: 'dev',
    project: 'globaldatacare-ica-dev',
    json: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--vat') { args.vat = argv[++i] ?? ''; continue; }
    if (arg === '--prefix') { args.prefix = argv[++i] ?? args.prefix; continue; }
    if (arg === '--project') { args.project = argv[++i] ?? args.project; continue; }
    if (arg === '--json') { args.json = true; continue; }
    if (arg === '--help' || arg === '-h') {
      console.log([
        'Usage:',
        '  node scripts/firestore-vat-search.mjs --vat VATES-B00112233 [options]',
        '',
        'Options:',
        '  --vat <value>      VAT to search (required)',
        '  --prefix <value>   Collection prefix (default: dev)',
        '  --project <id>     Firestore project ID (default: globaldatacare-ica-dev)',
        '  --json             Print raw JSON output',
      ].join('\n'));
      process.exit(0);
    }
  }

  return args;
}

function colName(prefix, leaf) {
  const normalized = String(prefix || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized ? `${normalized}_${leaf}` : leaf;
}

function containsVat(value, needleUpper) {
  if (value == null) return false;
  return String(value).toUpperCase().includes(needleUpper);
}

function stringifyContainsVat(value, needleUpper) {
  return JSON.stringify(value || {}).toUpperCase().includes(needleUpper);
}

function buildSummary(doc) {
  const data = doc.data() || {};
  return {
    id: doc.id,
    thid: data.thid || '',
    taxId: data.taxId || data.credential?.credentialSubject?.taxID || data.credential?.credentialSubject?.taxId || '',
    subjectId: data.subjectId || '',
    status: data.status || '',
    createdAt: data.createdAt || '',
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.vat) {
    console.error('ERROR: --vat is required. Example: --vat VATES-B00112233');
    process.exit(1);
  }

  const vatUpper = args.vat.trim().toUpperCase();
  const collections = [
    colName(args.prefix, 'issued_credentials'),
    colName(args.prefix, 'evidence_records'),
    colName(args.prefix, 'did_bindings'),
    colName(args.prefix, 'did_documents'),
  ];

  const require = createRequire(import.meta.url);
  let Firestore;
  try {
    ({ Firestore } = require('@google-cloud/firestore'));
  } catch {
    console.error('ERROR: @google-cloud/firestore not found. Run npm install inside dataspace-ica-ts.');
    process.exit(1);
  }

  const db = new Firestore({ projectId: args.project, ignoreUndefinedProperties: true });
  const results = {};

  for (const name of collections) {
    const snap = await db.collection(name).get();
    const matches = snap.docs.filter((doc) => stringifyContainsVat(doc.data(), vatUpper));
    results[name] = matches.map(buildSummary);
  }

  if (args.json) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  console.log(`Searching in project=${args.project} prefix=${args.prefix} vat=${vatUpper}`);
  let total = 0;
  for (const [name, rows] of Object.entries(results)) {
    console.log(`\n### ${name} -> ${rows.length} match(es)`);
    for (const row of rows) {
      const parts = [row.id];
      if (containsVat(row.taxId, vatUpper)) parts.push(`taxId=${row.taxId}`);
      if (containsVat(row.subjectId, vatUpper)) parts.push(`subjectId=${row.subjectId}`);
      if (row.thid) parts.push(`thid=${row.thid}`);
      if (row.status) parts.push(`status=${row.status}`);
      if (row.createdAt) parts.push(`createdAt=${row.createdAt}`);
      console.log(`  ${parts.join(' | ')}`);
    }
    total += rows.length;
  }
  console.log(`\nTotal: ${total} document(s) matching ${vatUpper}`);
}

main().catch((error) => {
  console.error(`ERROR: ${error?.message || String(error)}`);
  process.exit(1);
});
