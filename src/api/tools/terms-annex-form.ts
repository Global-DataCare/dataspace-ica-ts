import { mkdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

type PdfRgbColor = { type: 'RGB'; red: number; green: number; blue: number };

type PdfFontLike = {
  widthOfTextAtSize(text: string, size: number): number;
};

type PdfTextFieldLike = {
  setText(value: string): void;
  addToPage(page: unknown, options: Record<string, unknown>): void;
};

type PdfFormFieldLike = {
  getName(): string;
  getText?: () => string | undefined;
  getSelected?: () => string[] | string | undefined;
  isChecked?: () => boolean;
};

type PdfFormLike = {
  getFields(): PdfFormFieldLike[];
  createTextField(name: string): PdfTextFieldLike;
};

type PdfPageLike = {
  drawText(text: string, options: Record<string, unknown>): void;
  drawRectangle(options: Record<string, unknown>): void;
};

type PdfDocumentLike = {
  getForm(): PdfFormLike;
  addPage(size: [number, number]): PdfPageLike;
  embedFont(fontName: string): Promise<PdfFontLike>;
  save(): Promise<Uint8Array<ArrayBufferLike>>;
};

type PdfLibModule = {
  PDFDocument: {
    load(
      bytes: Buffer<ArrayBufferLike>,
      options: { ignoreEncryption: boolean; updateMetadata: boolean },
    ): Promise<PdfDocumentLike>;
    create(): Promise<PdfDocumentLike>;
  };
  StandardFonts: {
    Helvetica: string;
    HelveticaBold: string;
  };
  rgb(red: number, green: number, blue: number): PdfRgbColor;
};

const require = createRequire(import.meta.url);
let pdfLibModule: PdfLibModule | null = null;

async function loadPdfLib(): Promise<PdfLibModule> {
  if (!pdfLibModule) {
    pdfLibModule = require('pdf-lib') as PdfLibModule;
  }
  return pdfLibModule;
}

export type TermsAnnexFieldSpec = {
  name: string;
  label: string;
  placeholder?: string;
  required?: boolean;
};

export type TermsAnnexPdfOptions = {
  outputPath: string;
  termsText: string;
  title?: string;
  initialValues?: Record<string, string>;
};

export const TERMS_ANNEX_FIELD_SPECS: TermsAnnexFieldSpec[] = [
  {
    name: 'organization.additionalType',
    label: 'Organization profile / additionalType',
    placeholder: 'sector=onehealth;section=dataprovider;kind=clinic;action=_index-provider,_research-provider',
  },
  {
    name: 'organization.sameAs',
    label: 'Organization sameAs',
    placeholder: 'did:web:member.example.org',
  },
  {
    name: 'organization.url',
    label: 'Organization primary domain',
    placeholder: 'member.example.org',
  },
  {
    name: 'organization.alternateName',
    label: 'Organization alias',
    placeholder: 'acme',
  },
  {
    name: 'organization.registrationNumber',
    label: 'Sector registration number',
    placeholder: 'ES-SAN-REG-0001',
  },
  {
    name: 'person.email',
    label: 'Controller hash/email',
    placeholder: 'zControllerHash',
  },
  {
    name: 'person.alternateName',
    label: 'Controller key id (kid)',
    placeholder: 'controller-es384-20260309',
  },
  {
    name: 'person.additionalType',
    label: 'Controller algorithm',
    placeholder: 'ES384 | ML-DSA',
  },
];

const CANONICAL_ANNEX_FIELD_NAMES = new Map(
  TERMS_ANNEX_FIELD_SPECS.map((spec) => [spec.name.toLowerCase(), spec.name] as const),
);

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function wrapByWidth(
  text: string,
  maxWidth: number,
  font: PdfFontLike,
  fontSize: number,
): string[] {
  const words = text
    .replace(/\r/g, '')
    .split(/\s+/)
    .map((word) => word.trim())
    .filter(Boolean);
  if (!words.length) return [''];

  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, fontSize) <= maxWidth) {
      current = candidate;
      continue;
    }
    if (current) {
      lines.push(current);
      current = word;
      continue;
    }
    lines.push(word);
  }
  if (current) lines.push(current);
  return lines;
}

function normalizeFormValue(value: unknown): string {
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function readFieldValue(field: unknown): string {
  const maybeField = field as {
    getText?: () => string | undefined;
    getSelected?: () => string[] | string | undefined;
    isChecked?: () => boolean;
    getName?: () => string;
  };

  if (typeof maybeField.getText === 'function') {
    return normalizeFormValue(maybeField.getText());
  }

  if (typeof maybeField.getSelected === 'function') {
    const selected = maybeField.getSelected();
    if (Array.isArray(selected)) {
      return selected.map((entry) => normalizeFormValue(entry)).filter(Boolean).join(', ');
    }
    return normalizeFormValue(selected);
  }

  if (typeof maybeField.isChecked === 'function') {
    return maybeField.isChecked() ? 'true' : 'false';
  }

  return '';
}

export async function extractTermsAnnexFormFieldsFromPdf(
  pdfBytes: Buffer<ArrayBufferLike>,
): Promise<{ fields: Record<string, string>; warnings: string[] }> {
  const warnings: string[] = [];
  try {
    const { PDFDocument } = await loadPdfLib();
    const document = await PDFDocument.load(pdfBytes, { ignoreEncryption: true, updateMetadata: false });
    const form = document.getForm();
    const allFields = form.getFields();
    if (!allFields.length) {
      return { fields: {}, warnings };
    }

    const byName = new Map<string, { field: unknown; outputName: string }>();
    for (const field of allFields) {
      const name = asNonEmptyString((field as { getName?: () => string }).getName?.());
      if (!name) continue;
      const canonicalName = CANONICAL_ANNEX_FIELD_NAMES.get(name.toLowerCase());
      const outputName = canonicalName || name;
      const lookupKey = outputName.toLowerCase();
      if (byName.has(lookupKey)) continue;
      byName.set(lookupKey, { field, outputName });
    }

    const fields: Record<string, string> = {};
    for (const entry of byName.values()) {
      const value = readFieldValue(entry.field);
      if (!value) continue;
      fields[entry.outputName] = value;
    }
    return { fields, warnings };
  } catch (error: unknown) {
    warnings.push(`Annex field extraction skipped: ${(error as Error)?.message || String(error)}`);
    return { fields: {}, warnings };
  }
}

export async function generateTermsAnnexPdf(options: TermsAnnexPdfOptions): Promise<{
  outputPath: string;
  includedFieldNames: string[];
}> {
  const { PDFDocument, StandardFonts, rgb } = await loadPdfLib();
  const document = await PDFDocument.create();
  const form = document.getForm();
  const regular = await document.embedFont(StandardFonts.Helvetica);
  const bold = await document.embedFont(StandardFonts.HelveticaBold);

  const pageWidth = 595.28;
  const pageHeight = 841.89;
  const marginX = 36;
  const marginTop = 36;
  const marginBottom = 42;
  const rowHeight = 28;
  const labelWidth = 220;
  const fieldWidth = pageWidth - marginX * 2 - labelWidth - 8;

  let page = document.addPage([pageWidth, pageHeight]);
  let y = pageHeight - marginTop;

  const ensureSpace = (requiredHeight: number): void => {
    if (y - requiredHeight >= marginBottom) return;
    page = document.addPage([pageWidth, pageHeight]);
    y = pageHeight - marginTop;
  };

  const drawTextLine = (text: string, size: number, isBold = false): void => {
    ensureSpace(size + 8);
    page.drawText(text, {
      x: marginX,
      y: y - size,
      size,
      font: isBold ? bold : regular,
      color: rgb(0.1, 0.1, 0.1),
    });
    y -= size + 8;
  };

  const drawParagraph = (text: string, size = 10): void => {
    const blocks = text
      .replace(/\r/g, '')
      .split('\n')
      .map((line) => line.trimEnd());
    const width = pageWidth - marginX * 2;
    const lineHeight = size + 3;
    for (const block of blocks) {
      if (!block.trim()) {
        y -= lineHeight;
        continue;
      }
      const lines = wrapByWidth(block, width, regular, size);
      for (const line of lines) {
        ensureSpace(lineHeight + 2);
        page.drawText(line, {
          x: marginX,
          y: y - size,
          size,
          font: regular,
          color: rgb(0.12, 0.12, 0.12),
        });
        y -= lineHeight;
      }
    }
  };

  drawTextLine(options.title?.trim() || 'Terms and Conditions Annex', 16, true);
  drawParagraph(options.termsText, 10);
  y -= 8;
  drawTextLine('Annex form fields (predefined names)', 12, true);

  for (const fieldSpec of TERMS_ANNEX_FIELD_SPECS) {
    ensureSpace(rowHeight + 8);

    page.drawRectangle({
      x: marginX,
      y: y - rowHeight,
      width: labelWidth,
      height: rowHeight,
      borderColor: rgb(0.83, 0.83, 0.83),
      borderWidth: 0.8,
      color: rgb(0.98, 0.98, 0.98),
    });
    page.drawRectangle({
      x: marginX + labelWidth + 8,
      y: y - rowHeight,
      width: fieldWidth,
      height: rowHeight,
      borderColor: rgb(0.76, 0.76, 0.76),
      borderWidth: 0.8,
      color: rgb(1, 1, 1),
    });

    page.drawText(fieldSpec.label, {
      x: marginX + 4,
      y: y - 13,
      size: 9,
      font: regular,
      color: rgb(0.16, 0.16, 0.16),
    });
    page.drawText(fieldSpec.name, {
      x: marginX + 4,
      y: y - 24,
      size: 7,
      font: regular,
      color: rgb(0.36, 0.36, 0.36),
    });

    const textField = form.createTextField(fieldSpec.name);
    const initialValue = asNonEmptyString(options.initialValues?.[fieldSpec.name] || fieldSpec.placeholder || '');
    if (initialValue) {
      textField.setText(initialValue);
    }
    textField.addToPage(page, {
      x: marginX + labelWidth + 12,
      y: y - rowHeight + 6,
      width: fieldWidth - 8,
      height: rowHeight - 12,
      borderColor: rgb(0.6, 0.6, 0.6),
      borderWidth: 0.6,
      textColor: rgb(0.08, 0.08, 0.08),
      font: regular,
      backgroundColor: rgb(1, 1, 1),
    });

    y -= rowHeight + 4;
  }

  y -= 6;
  drawParagraph(
    'These fields are intended to be signed together with the terms PDF so ICA can map them into verification evidence.',
    9,
  );

  const bytes = await document.save();
  await mkdir(path.dirname(options.outputPath), { recursive: true });
  await writeFile(options.outputPath, bytes, { mode: 0o600 });
  return {
    outputPath: options.outputPath,
    includedFieldNames: TERMS_ANNEX_FIELD_SPECS.map((item) => item.name),
  };
}
