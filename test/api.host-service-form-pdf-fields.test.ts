import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { UrnPrefixes } from 'gdc-common-utils-ts/constants/urn';
import {
  HOST_SERVICE_FORM_VERSION,
  HostServiceFormPdfFieldName,
} from '../src/api/models/host-service-form-pdf-fields.ts';
import type { HostServiceFormPdfFields } from '../src/api/models/host-service-form-pdf-fields.ts';
import { validateHostServiceFormPdfFields } from '../src/api/tools/host-service-form-pdf-validation.ts';
import { extractTermsAnnexFormFieldsFromPdf } from '../src/api/tools/terms-annex-form.ts';

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

const HOST_SERVICE_FORM_VALUES = {
  [HostServiceFormPdfFieldName.formVersion]: HOST_SERVICE_FORM_VERSION,
  [HostServiceFormPdfFieldName.url]: 'https://host.example.org',
  [HostServiceFormPdfFieldName.providerLegalName]: 'Example Provider Foundation',
  [HostServiceFormPdfFieldName.providerAddressCountry]: 'ES',
  [HostServiceFormPdfFieldName.providerIdentifierAdditionalType]: 'TAX',
  [HostServiceFormPdfFieldName.providerIdentifierValue]: 'VATES-X0000000X',
  [HostServiceFormPdfFieldName.ownerEmail]: 'controller@example.org',
  [HostServiceFormPdfFieldName.ownerHasCredentialMaterial]:
    `${UrnPrefixes.JwkThumbprintSha256KeyId}${'A'.repeat(43)}`,
} as const;

/**
 * Flow contract: the signed AcroForm identifies the host service, responsible
 * provider and controller. Fabric channels, permissions, block fingerprints
 * and chaincode policy are deliberately configured outside this legal PDF.
 */
test('signed host-service PDF exposes every field required for Service VC issuance', async () => {
  const document = await PDFDocument.create();
  const page = document.addPage([700, 700]);
  const form = document.getForm();
  let y = 650;

  for (const [name, value] of Object.entries(HOST_SERVICE_FORM_VALUES)) {
    const field = form.createTextField(name);
    field.setText(value);
    field.addToPage(page, { x: 20, y, width: 620, height: 20 });
    y -= 30;
  }

  const extracted = await extractTermsAnnexFormFieldsFromPdf(Buffer.from(await document.save()));
  const validation = validateHostServiceFormPdfFields(extracted.fields);

  assert.deepEqual(extracted.warnings, []);
  assert.deepEqual(extracted.fields, HOST_SERVICE_FORM_VALUES);
  assert.deepEqual(validation, { valid: true, missingFields: [], errors: [] });
});

test('host-service form requires provider identifier value or taxID', () => {
  const fields = { ...HOST_SERVICE_FORM_VALUES } as Record<string, string>;
  delete fields[HostServiceFormPdfFieldName.providerIdentifierValue];
  delete fields[HostServiceFormPdfFieldName.providerIdentifierAdditionalType];

  const validation = validateHostServiceFormPdfFields(fields);

  assert.equal(validation.valid, false);
  assert.deepEqual(validation.missingFields, [
    `${HostServiceFormPdfFieldName.providerIdentifierValue}|${HostServiceFormPdfFieldName.providerTaxID}`,
  ]);
});

test('host-service PDF contract excludes mutable Fabric governance configuration', () => {
  assert.equal('channel' in HostServiceFormPdfFieldName, false);
  assert.equal('permissions' in HostServiceFormPdfFieldName, false);
  assert.equal('genesisSha256' in HostServiceFormPdfFieldName, false);
  assert.equal('chaincodes' in HostServiceFormPdfFieldName, false);
  assert.equal('serviceType' in HostServiceFormPdfFieldName, false);
  assert.equal('category' in HostServiceFormPdfFieldName, false);
});

test('HostServiceFormPdfFields exposes camelCase TypeScript properties', () => {
  const fields: HostServiceFormPdfFields = {
    providerLegalName: 'Example Provider Foundation',
    providerAddressCountry: 'ES',
    providerTaxID: 'VATES-X0000000X',
    ownerEmail: 'controller@example.org',
    ownerHasCredentialMaterial: HOST_SERVICE_FORM_VALUES[HostServiceFormPdfFieldName.ownerHasCredentialMaterial],
  };

  assert.equal(fields.providerLegalName, 'Example Provider Foundation');
  assert.equal(fields.ownerEmail, 'controller@example.org');
});
