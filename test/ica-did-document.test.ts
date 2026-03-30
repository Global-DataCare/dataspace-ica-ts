// @ts-nocheck
// Carga automática de variables de entorno desde .env.local para los tests
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
import { buildIcaDid, addAlsoKnownAsToDidDocument } from '../src/api/tools/ica-identity';

describe('ICA DID Document logic', () => {
  import fs from 'node:fs';
  import path from 'node:path';
  import { fileURLToPath } from 'node:url';
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const outdir = path.resolve(__dirname, '../artifacts/tests/output');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

  function writeOutput(name, data) {
    console.log(`[ICA-DID-TEST] About to write output: ${name}`);
    fs.mkdirSync(outdir, { recursive: true });
    fs.writeFileSync(
      path.join(outdir, `ica-did-document.${name}.${timestamp}.json`),
      JSON.stringify(data, null, 2)
    );
    console.log(`[ICA-DID-TEST] Output written: ${name}`);
  }

  it('should build ICA DID as did:web:<domain>:<tenant>', () => {
    process.env.DID_WEB_DOMAIN = 'procuredata.org';
    process.env.ICA_LOCAL_TENANT_ID = 'ica';
    const did = buildIcaDid();
    writeOutput('buildIcaDid-env', { did });
    expect(did).toBe('did:web:procuredata.org:ica');
  });

  it('should fallback to autodetect if DID_WEB_DOMAIN is not set', () => {
    delete process.env.DID_WEB_DOMAIN;
    process.env.ICA_LOCAL_TENANT_ID = 'ica';
    const req = { headers: { host: 'mydomain.com:8080' } };
    const did = buildIcaDid(req);
    writeOutput('buildIcaDid-autodetect', { did });
    expect(did).toBe('did:web:mydomain.com%3A8080:ica');
  });

  it('should add alsoKnownAs with real host if MASK_LOCAL_ICA is false', () => {
    process.env.MASK_LOCAL_ICA = 'false';
    const doc = { id: 'did:web:procuredata.org:ica' };
    const req = { headers: { host: 'realhost.com' } };
    addAlsoKnownAsToDidDocument(doc, req);
    writeOutput('alsoKnownAs-false', doc);
    expect(doc.alsoKnownAs).toEqual(['https://realhost.com']);
  });

  it('should NOT add alsoKnownAs if MASK_LOCAL_ICA is true', () => {
    process.env.MASK_LOCAL_ICA = 'true';
    const doc = { id: 'did:web:procuredata.org:ica' };
    const req = { headers: { host: 'realhost.com' } };
    addAlsoKnownAsToDidDocument(doc, req);
    writeOutput('alsoKnownAs-true', doc);
    expect(doc.alsoKnownAs).toBeUndefined();
  });
});
