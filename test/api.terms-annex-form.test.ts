import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  TERMS_ANNEX_FIELD_SPECS,
  extractTermsAnnexFormFieldsFromPdf,
  generateTermsAnnexPdf,
} from '../src/api/tools/terms-annex-form.ts';

test('generateTermsAnnexPdf builds annex PDF and extractTermsAnnexFormFieldsFromPdf returns known values', async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'ica-terms-annex-'));
  const outFile = path.join(tempDir, 'terms-annex.pdf');

  const generated = await generateTermsAnnexPdf({
    outputPath: outFile,
    title: 'ICA Terms Annex',
    termsText: 'Linea 1 de terminos.\nLinea 2 de terminos.',
    initialValues: {
      'organization.did': 'did:web:member.example.org',
      'organization.registrationNumber': 'ES-SAN-REG-0001',
      'legalRepresentative.email': 'rep@example.org',
      'controller.kid': 'controller-es384-20260309',
    },
  });

  assert.equal(generated.outputPath, outFile);
  assert.equal(generated.includedFieldNames.length, TERMS_ANNEX_FIELD_SPECS.length);
  assert.equal(generated.includedFieldNames.includes('organization.did'), true);
  assert.equal(generated.includedFieldNames.includes('controller.publicKeyJwk'), true);

  const pdfBytes = await readFile(outFile);
  const extracted = await extractTermsAnnexFormFieldsFromPdf(pdfBytes);
  assert.equal(extracted.warnings.length, 0);
  assert.equal(extracted.fields['organization.did'], 'did:web:member.example.org');
  assert.equal(extracted.fields['organization.registrationNumber'], 'ES-SAN-REG-0001');
  assert.equal(extracted.fields['legalRepresentative.email'], 'rep@example.org');
  assert.equal(extracted.fields['controller.kid'], 'controller-es384-20260309');
});
