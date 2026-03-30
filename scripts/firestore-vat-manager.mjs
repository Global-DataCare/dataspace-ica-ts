#!/usr/bin/env node
/**
 * firestore-vat-manager.mjs
 *
 * Inspect or delete Firestore documents related to a specific VAT number
 * across all 4 ICA collections (issued_credentials, evidence_records,
 * did_bindings, did_documents).
 *
 * Usage:
 *   node scripts/firestore-vat-manager.mjs --vat VATES-B00112233
 *   node scripts/firestore-vat-manager.mjs --vat VATES-B00112233 --prefix st-v2
 *   node scripts/firestore-vat-manager.mjs --vat VATES-B00112233 --delete
 *   node scripts/firestore-vat-manager.mjs --vat VATES-B00112233 --prefix st-v2 --project globaldatacare-ica-dev --delete
 *
 * Options:
 *   --vat       VAT number to search (required). Case-insensitive.
 *   --prefix    Firestore collection prefix (default: dev)
 *   --project   GCP project ID         (default: globaldatacare-ica-dev)
 *   --delete    Execute deletion after interactive confirmation
 *   --yes       Skip confirmation prompt (only valid with --delete)
 *   --json      Output raw JSON instead of formatted table
 */

import { createInterface } from 'node:readline';
import { createRequire } from 'node:module';

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const args = { vat: '', prefix: 'dev', project: 'globaldatacare-ica-dev', delete: false, yes: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--vat')        { args.vat     = argv[++i] ?? ''; continue; }
    if (arg === '--prefix')     { args.prefix  = argv[++i] ?? 'dev'; continue; }
    if (arg === '--project')    { args.project = argv[++i] ?? args.project; continue; }
    if (arg === '--delete')     { args.delete  = true; continue; }
    if (arg === '--yes' || arg === '-y') { args.yes = true; continue; }
    if (arg === '--json')       { args.json    = true; continue; }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));

if (!args.vat) {
  console.error('ERROR: --vat is required. Example: --vat VATES-B00112233');
  process.exit(1);
}

const VAT_UPPER = args.vat.trim().toUpperCase();

// ---------------------------------------------------------------------------
// Collection names (mirrors verification-collections-storage.ts)
// ---------------------------------------------------------------------------
function colName(prefix, leaf) {
  const norm = prefix.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  return norm ? `${norm}_${leaf}` : leaf;
}

const COLLECTIONS = {
  issued_credentials: colName(args.prefix, 'issued_credentials'),
  evidence_records:   colName(args.prefix, 'evidence_records'),
  did_bindings:       colName(args.prefix, 'did_bindings'),
  did_documents:      colName(args.prefix, 'did_documents'),
};

// ---------------------------------------------------------------------------
// Firestore client
// ---------------------------------------------------------------------------
const require = createRequire(import.meta.url);
let Firestore;
try {
  ({ Firestore } = require('@google-cloud/firestore'));
} catch {
  console.error('ERROR: @google-cloud/firestore not found. Run: npm install inside dataspace-ica-ts/');
  process.exit(1);
}

const db = new Firestore({ projectId: args.project, ignoreUndefinedProperties: true });

// ---------------------------------------------------------------------------
// Match helpers – each collection uses the most specific field available
// ---------------------------------------------------------------------------

/**
 * issued_credentials: match by subjectId contains VAT  OR
 *                     credential.credentialSubject.taxID / taxId
 */
function matchIssuedCredential(doc) {
  const d = doc.data();
  if (containsVat(d.subjectId)) return true;
  const cs = d?.credential?.credentialSubject;
  if (cs) {
    if (containsVat(cs.taxID))  return true;
    if (containsVat(cs.taxId))  return true;
    if (containsVat(cs.id))     return true;
  }
  return false;
}

/**
 * did_bindings: exact match on taxId field
 */
function matchDidBinding(doc) {
  return containsVat(doc.data().taxId);
}

/**
 * did_documents: exact match on taxId OR did contains VAT
 */
function matchDidDocument(doc) {
  const d = doc.data();
  return containsVat(d.taxId) || containsVat(d.did);
}

/**
 * evidence_records: match by thid of already-matched issued_credentials,
 *                   or broad fallback search on serialised content.
 */
function matchEvidenceRecord(doc, matchedThids) {
  const d = doc.data();
  if (matchedThids.has(d.thid)) return true;
  // fallback: subjectId in nested evidence
  return containsVat(JSON.stringify(d.evidence ?? {}));
}

function containsVat(value) {
  if (!value) return false;
  return String(value).toUpperCase().includes(VAT_UPPER);
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------
async function listAll(collectionName) {
  const snap = await db.collection(collectionName).get();
  return snap.docs;
}

async function inspectAll() {
  const allDocs = {};

  console.log(`\nSearching in project=${args.project}  prefix=${args.prefix}  vat=${VAT_UPPER}\n`);

  // issued_credentials first so we can extract thids for evidence correlation
  console.log(`Querying ${COLLECTIONS.issued_credentials} …`);
  const rawIssued = await listAll(COLLECTIONS.issued_credentials);
  allDocs.issued_credentials = rawIssued.filter(matchIssuedCredential);

  const matchedThids = new Set(allDocs.issued_credentials.map(d => d.data().thid).filter(Boolean));

  console.log(`Querying ${COLLECTIONS.evidence_records} …`);
  const rawEvidence = await listAll(COLLECTIONS.evidence_records);
  allDocs.evidence_records = rawEvidence.filter(d => matchEvidenceRecord(d, matchedThids));

  console.log(`Querying ${COLLECTIONS.did_bindings} …`);
  const rawBindings = await listAll(COLLECTIONS.did_bindings);
  allDocs.did_bindings = rawBindings.filter(matchDidBinding);

  console.log(`Querying ${COLLECTIONS.did_documents} …`);
  const rawDocs = await listAll(COLLECTIONS.did_documents);
  allDocs.did_documents = rawDocs.filter(matchDidDocument);

  return allDocs;
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------
function printResults(allDocs, useJson) {
  const summary = {};
  for (const [leaf, docs] of Object.entries(allDocs)) {
    summary[COLLECTIONS[leaf]] = docs.map(d => ({
      id: d.id,
      thid:   d.data().thid,
      taxId:  d.data().taxId   || d.data().credential?.credentialSubject?.taxID || '',
      subjectId: d.data().subjectId || '',
      status: d.data().status  || '',
      createdAt: d.data().createdAt || '',
    }));
  }

  if (useJson) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  let total = 0;
  for (const [col, rows] of Object.entries(summary)) {
    console.log(`\n### ${col} → ${rows.length} match(es)`);
    for (const row of rows) {
      const parts = [row.id];
      if (row.taxId)     parts.push(`taxId=${row.taxId}`);
      if (row.subjectId) parts.push(`subjectId=${row.subjectId}`);
      if (row.thid)      parts.push(`thid=${row.thid}`);
      if (row.status)    parts.push(`status=${row.status}`);
      if (row.createdAt) parts.push(`createdAt=${row.createdAt}`);
      console.log('  ' + parts.join('  |  '));
    }
    total += rows.length;
  }
  console.log(`\nTotal: ${total} document(s) matching ${VAT_UPPER}`);
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------
async function deleteAll(allDocs) {
  for (const [leaf, docs] of Object.entries(allDocs)) {
    const col = COLLECTIONS[leaf];
    if (!docs.length) {
      console.log(`Skipping ${col} (0 docs)`);
      continue;
    }
    console.log(`Deleting ${docs.length} document(s) from ${col} …`);
    // Firestore batch max 500 ops; chunk if needed
    const CHUNK = 400;
    for (let i = 0; i < docs.length; i += CHUNK) {
      const batch = db.batch();
      for (const doc of docs.slice(i, i + CHUNK)) {
        batch.delete(doc.ref);
      }
      await batch.commit();
      for (const doc of docs.slice(i, i + CHUNK)) {
        console.log(`  deleted ${col}/${doc.id}`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Confirm prompt
// ---------------------------------------------------------------------------
async function confirm(message) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(`${message} [yes/NO] `, answer => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'yes' || answer.trim().toLowerCase() === 'y');
    });
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
(async () => {
  try {
    const allDocs = await inspectAll();
    printResults(allDocs, args.json);

    const total = Object.values(allDocs).reduce((s, d) => s + d.length, 0);

    if (!args.delete) {
      console.log('\nRun with --delete to remove these documents.');
      return;
    }

    if (total === 0) {
      console.log('\nNothing to delete.');
      return;
    }

    let confirmed = args.yes;
    if (!confirmed) {
      confirmed = await confirm(`\nDelete ${total} document(s) from project=${args.project} prefix=${args.prefix}?`);
    }

    if (!confirmed) {
      console.log('Aborted.');
      return;
    }

    await deleteAll(allDocs);
    console.log(`\nDone. Deleted ${total} document(s) for ${VAT_UPPER}.`);
  } catch (err) {
    console.error('ERROR:', err.message || err);
    process.exit(1);
  }
})();
