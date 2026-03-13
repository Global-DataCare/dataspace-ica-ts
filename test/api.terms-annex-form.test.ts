import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  TERMS_ANNEX_FIELD_SPECS,
  extractTermsAnnexFormFieldsFromPdf,
  generateTermsAnnexPdf,
} from '../src/api/tools/terms-annex-form.ts';

const require = createRequire(import.meta.url);
const { PDFDocument } = require('pdf-lib') as {
  PDFDocument: {
    create(): Promise<{
      addPage(size: [number, number]): unknown;
      getForm(): {
        createTextField(name: string): {
          setText(value: string): void;
          addToPage(page: unknown, options: Record<string, unknown>): void;
        };
      };
      save(): Promise<Uint8Array<ArrayBufferLike>>;
    }>;
  };
};

test('generateTermsAnnexPdf builds annex PDF and extractTermsAnnexFormFieldsFromPdf returns known values', async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'ica-terms-annex-'));
  const outFile = path.join(tempDir, 'terms-annex.pdf');

  const generated = await generateTermsAnnexPdf({
    outputPath: outFile,
    title: 'ICA Terms Annex',
    termsText: 'Linea 1 de terminos.\nLinea 2 de terminos.',
    initialValues: {
      'organization.sameAs': 'did:web:member.example.org',
      'organization.url': 'member.example.org',
      'organization.registrationNumber': 'ES-SAN-REG-0001',
      'person.alternateName': 'controller-es384-20260309',
    },
  });

  assert.equal(generated.outputPath, outFile);
  assert.equal(generated.includedFieldNames.length, TERMS_ANNEX_FIELD_SPECS.length);
  assert.equal(generated.includedFieldNames.includes('organization.sameAs'), true);
  assert.equal(generated.includedFieldNames.includes('organization.url'), true);
  assert.equal(generated.includedFieldNames.includes('person.additionalType'), true);

  const pdfBytes = await readFile(outFile);
  const extracted = await extractTermsAnnexFormFieldsFromPdf(pdfBytes);
  assert.equal(extracted.warnings.length, 0);
  assert.equal(extracted.fields['organization.sameAs'], 'did:web:member.example.org');
  assert.equal(extracted.fields['organization.url'], 'member.example.org');
  assert.equal(extracted.fields['organization.registrationNumber'], 'ES-SAN-REG-0001');
  assert.equal(extracted.fields['person.alternateName'], 'controller-es384-20260309');
});

test('extractTermsAnnexFormFieldsFromPdf matches Organization.* and Person.* field names case-insensitively', async () => {
  const document = await PDFDocument.create();
  const page = document.addPage([400, 200]);
  const form = document.getForm();

  const sameAsField = form.createTextField('Organization.sameAs');
  sameAsField.setText('did:web:member.example.org');
  sameAsField.addToPage(page, { x: 20, y: 140, width: 250, height: 20 });

  const urlField = form.createTextField('Organization.url');
  urlField.setText('member.example.org');
  urlField.addToPage(page, { x: 20, y: 110, width: 250, height: 20 });

  const personField = form.createTextField('Person.alternateName');
  personField.setText('controller-es384-20260309');
  personField.addToPage(page, { x: 20, y: 80, width: 250, height: 20 });

  const pdfBytes = Buffer.from(await document.save());
  const extracted = await extractTermsAnnexFormFieldsFromPdf(pdfBytes);

  assert.equal(extracted.warnings.length, 0);
  assert.equal(extracted.fields['organization.sameAs'], 'did:web:member.example.org');
  assert.equal(extracted.fields['organization.url'], 'member.example.org');
  assert.equal(extracted.fields['person.alternateName'], 'controller-es384-20260309');
});
