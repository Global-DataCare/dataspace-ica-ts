#!/usr/bin/env node

# gcloud config set project globaldatacare-ica-dev

const { Firestore } = require('@google-cloud/firestore');

const db = new Firestore({ projectId: 'globaldatacare-ica-dev' });
const taxId = 'B42215152';
const collections = [
  'dev_issued_credentials',
  'dev_evidence_records',
  'dev_did_bindings',
  'dev_did_documents',
];

function containsTaxId(value, needle) {
  return JSON.stringify(value || {}).toUpperCase().includes(needle.toUpperCase());
}

(async () => {
  for (const name of collections) {
    const snap = await db.collection(name).get();
    const matches = snap.docs
      .map(doc => ({ id: doc.id, data: doc.data() }))
      .filter(entry => containsTaxId(entry.data, taxId));
    console.log(`\n### ${name} -> ${matches.length} match(es)`);
    for (const match of matches) {
      console.log(match.id);
    }
  }
})().catch(err => {
  console.error(err);
  process.exit(1);
});