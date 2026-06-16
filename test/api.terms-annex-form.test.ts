import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  TERMS_ANNEX_FIELD_SPECS,
  parseOrganizationIdentityFromPlainText,
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

test('extractTermsAnnexFormFieldsFromPdf preserves non-canonical visible organization identity fields', async () => {
  const document = await PDFDocument.create();
  const page = document.addPage([400, 200]);
  const form = document.getForm();

  const taxIdField = form.createTextField('Organization.taxID');
  taxIdField.setText('ES-B12345678');
  taxIdField.addToPage(page, { x: 20, y: 140, width: 250, height: 20 });

  const legalNameField = form.createTextField('Organization.legalName');
  legalNameField.setText('Acme Health SL');
  legalNameField.addToPage(page, { x: 20, y: 110, width: 250, height: 20 });

  const pdfBytes = Buffer.from(await document.save());
  const extracted = await extractTermsAnnexFormFieldsFromPdf(pdfBytes);

  assert.equal(extracted.warnings.length, 0);
  assert.equal(extracted.fields['Organization.taxID'], 'ES-B12345678');
  assert.equal(extracted.fields['Organization.legalName'], 'Acme Health SL');
});

const VITEMARKETING_FIXTURE_PATH =
  path.join(os.homedir(), 'GITS', 'gdc-workspace', 'examples', 'prueba-Contrato de Adhesión PROCUREDATA_VITEMARKETING.pdf');

test(
  'extractTermsAnnexFormFieldsFromPdf extracts visible organization identity from VITEMARKETING real fixture',
  { skip: !existsSync(VITEMARKETING_FIXTURE_PATH) },
  async () => {
    const pdfBytes = await readFile(VITEMARKETING_FIXTURE_PATH);
    const extracted = await extractTermsAnnexFormFieldsFromPdf(pdfBytes);

    const visibleTaxIdCandidates = [
      extracted.fields['organization.taxID'],
      extracted.fields['organization.taxId'],
      extracted.fields['Organization.taxID'],
      extracted.fields['Organization.taxId'],
      extracted.fields['organization.cif'],
      extracted.fields['Organization.cif'],
      extracted.fields['organization.vat'],
      extracted.fields['Organization.vat'],
      extracted.fields['organization.vatNumber'],
      extracted.fields['Organization.vatNumber'],
      extracted.fields['Identificacion Empresa'],
      extracted.fields['Identificación Empresa'],
      extracted.fields['Identificacion'],
      extracted.fields['Identificación'],
    ].filter((value): value is string => Boolean(value && value.trim()));

    const visibleLegalNameCandidates = [
      extracted.fields['organization.legalName'],
      extracted.fields['Organization.legalName'],
      extracted.fields['organization.name'],
      extracted.fields['Organization.name'],
      extracted.fields['organization.legal_name'],
      extracted.fields['Organization.legal_name'],
      extracted.fields['organization.razonSocial'],
      extracted.fields['Organization.razonSocial'],
      extracted.fields['organization.razon_social'],
      extracted.fields['Organization.razon_social'],
      extracted.fields['Razon Social'],
      extracted.fields['Razón Social'],
    ].filter((value): value is string => Boolean(value && value.trim()));

    assert.ok(
      visibleTaxIdCandidates.length > 0,
      `No visible organization VAT/CIF extracted from real fixture. Extracted keys: ${Object.keys(extracted.fields).join(', ')}`,
    );
    assert.ok(
      visibleLegalNameCandidates.length > 0,
      `No visible organization legal name extracted from real fixture. Extracted keys: ${Object.keys(extracted.fields).join(', ')}`,
    );
  },
);

test('parseOrganizationIdentityFromPlainText maps VATPT when Domicilio Fiscal ends in Portugal and extracts Representante legal', () => {
  const text = [
    'Razón Social: FALCK PORTUGAL, S.A.',
    'CIF: 507910626',
    'Domicilio Fiscal: Rua de Lisboa 100, 1000-100 Lisboa, Portugal',
    'Representante legal: Joao Silva',
  ].join('\n');

  const parsed = parseOrganizationIdentityFromPlainText(text, ['VATES-B87617981'], 'ES');
  assert.equal(parsed.taxID, 'VATPT-507910626');
  assert.equal(parsed.legalName, 'FALCK PORTUGAL, S.A.');
  assert.equal(parsed.legalRepresentativeName, 'Joao Silva');
});
