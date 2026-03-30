import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

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
let pdfParseModule: { PDFParse?: new (input: { data: Buffer<ArrayBufferLike> }) => {
  getText: () => Promise<{ text?: string }>;
  destroy?: () => Promise<void> | void;
} } | null = null;
const execFileAsync = promisify(execFile);

async function loadPdfLib(): Promise<PdfLibModule> {
  if (!pdfLibModule) {
    pdfLibModule = require('pdf-lib') as PdfLibModule;
  }
  return pdfLibModule;
}

async function loadPdfParseModule(): Promise<typeof pdfParseModule> {
  if (!pdfParseModule) {
    pdfParseModule = require('pdf-parse') as typeof pdfParseModule;
  }
  return pdfParseModule;
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

function normalizeVerifierVatToken(value: string): string {
  const upper = (value || '').trim().toUpperCase().replace(/[\s-]+/g, '');
  if (!upper) return '';
  const withoutVates = upper.startsWith('VATES') ? upper.slice(5) : upper;
  const withoutVatPrefix = withoutVates.startsWith('VAT') ? withoutVates.slice(3) : withoutVates;
  return withoutVatPrefix;
}

function normalizeVisibleTaxToken(raw: string, jurisdiction: string): string {
  const upper = (raw || '').trim().toUpperCase().replace(/[\s-]+/g, '');
  if (!upper) return '';
  const withoutVates = upper.startsWith('VATES') ? upper.slice(5) : upper;
  const withoutVat = /^VAT[A-Z]{2}/.test(withoutVates) ? withoutVates.slice(5) : (withoutVates.startsWith('VAT') ? withoutVates.slice(3) : withoutVates);
  const country = jurisdiction.toUpperCase();
  if (withoutVat.startsWith(country)) return withoutVat.slice(country.length);
  if (withoutVat.startsWith('ES')) return withoutVat.slice(2);
  if (withoutVat.startsWith('PT')) return withoutVat.slice(2);
  return withoutVat;
}

function looksLikeLegalName(value: string): boolean {
  const normalized = (value || '').trim();
  if (normalized.length < 3) return false;
  if (!/[A-ZÁÉÍÓÚÜÑ]/i.test(normalized)) return false;
  const blocked = /digitally\s+signed\s+by|firma(?:do)?\s+digital|date:\s*\d|fecha:\s*\d/i;
  if (blocked.test(normalized)) return false;
  return true;
}

function stripLegalNameLabel(value: string): string {
  return normalizeSpacing(String(value || '').replace(/^(?:Razon|Raz[oó]n|Raz[aã]o)\s+Social\s*[:\-]?\s*/i, ''));
}

function normalizeSpacing(value: string): string {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function normalizeForMatching(value: string): string {
  return normalizeSpacing(value)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function detectDomicileCountryFromLines(lines: string[]): 'PT' | 'ES' | undefined {
  const normalizedLines = lines.map((line) => normalizeForMatching(line));
  const hasDomicilioLabel = normalizedLines.some((line) =>
    line.includes('domicilio fiscal') || line.includes('domiciliofiscal') || line.includes('fiscal address'),
  );
  if (hasDomicilioLabel) {
    if (normalizedLines.some((line) => /\bportugal\b/.test(line) || /\bportuguesa\b/.test(line))) return 'PT';
    if (normalizedLines.some((line) => /\bespana\b/.test(line) || /\bspain\b/.test(line))) return 'ES';
  }

  for (const line of lines) {
    const normalized = normalizeForMatching(line);
    if (!normalized.includes('domicilio fiscal') && !normalized.includes('domiciliofiscal') && !normalized.includes('fiscal address')) {
      continue;
    }
    if (/\bportugal\b/.test(normalized) || /\bportuguesa\b/.test(normalized)) return 'PT';
    if (/\bespana\b|\bspain\b|\bes\b/.test(normalized)) return 'ES';
  }
  return undefined;
}

export function parseOrganizationIdentityFromPlainText(
  text: string,
  verifierVatList: string[],
  jurisdiction = 'ES',
): { taxID?: string; legalName?: string; legalRepresentativeName?: string; warnings: string[] } {
  const warnings: string[] = [];
  const normalizedVerifierVatSet = new Set(
    verifierVatList
      .map((entry) => normalizeVerifierVatToken(entry))
      .filter(Boolean),
  );

  const lines = text
    .split(/\r?\n/)
    .map((line) => normalizeSpacing(line))
    .filter(Boolean);
  if (!lines.length) return { warnings };

  const domicileCountry = detectDomicileCountryFromLines(lines);
  const effectiveJurisdiction = domicileCountry || jurisdiction.toUpperCase();
  const taxLabelRegex = /\b(?:CIF|NIF|NIPC|VAT|TAX\s*ID|TAX\s*NUMBER)\b\s*[:\-]?\s*([A-Z0-9][A-Z0-9\s-]{5,24})/gi;
  const candidateTokens: Array<{ token: string; line: string; lineIndex: number }> = [];
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    let match: RegExpExecArray | null;
    while ((match = taxLabelRegex.exec(line)) !== null) {
      const token = normalizeVisibleTaxToken(match[1] || '', effectiveJurisdiction);
      if (!token) continue;
      candidateTokens.push({ token, line, lineIndex });
    }
    taxLabelRegex.lastIndex = 0;
  }

  const filteredCandidates = candidateTokens.filter((entry) => !normalizedVerifierVatSet.has(entry.token));
  const selectedCandidate = filteredCandidates[0];
  let taxID: string | undefined;
  let legalName: string | undefined;
  if (selectedCandidate) {
    taxID = `VAT${effectiveJurisdiction}-${selectedCandidate.token}`;
    const legalNameFromLabel = stripLegalNameLabel(
      selectedCandidate.line.split(/\b(?:CIF|NIF|NIPC|VAT|TAX\s*ID|TAX\s*NUMBER)\b/i)[0]?.trim() || '',
    );
    if (legalNameFromLabel && looksLikeLegalName(legalNameFromLabel)) {
      legalName = legalNameFromLabel;
    }
    if (!legalName && selectedCandidate.lineIndex > 0) {
      const previousLine = stripLegalNameLabel(lines[selectedCandidate.lineIndex - 1]);
      if (looksLikeLegalName(previousLine)) {
        legalName = previousLine;
      }
    }
  } else if (candidateTokens.length) {
    warnings.push('Visible tax IDs found in PDF text belong only to verifier VATs; counterparty tax ID not detected.');
  }

  if (!legalName) {
    for (const line of lines) {
      const match = /\b(?:Razon|Raz[oó]n|Raz[aã]o)\s+Social\b\s*[:\-]?\s*(.+)$/i.exec(line);
      if (!match) continue;
      const candidate = stripLegalNameLabel(match[1] || '');
      if (looksLikeLegalName(candidate)) {
        legalName = candidate;
        break;
      }
    }
  }

  let legalRepresentativeName: string | undefined;
  for (const line of lines) {
    const match = /\b(?:Representante\s+legal|Legal\s+representative)\b\s*[:\-]?\s*(.+)$/i.exec(line);
    if (!match) continue;
    const candidate = normalizeSpacing(match[1] || '');
    if (candidate && !/^(?:n\/a|na|none)$/i.test(candidate)) {
      legalRepresentativeName = candidate;
      break;
    }
  }

  return {
    ...(taxID ? { taxID } : {}),
    ...(legalName ? { legalName } : {}),
    ...(legalRepresentativeName ? { legalRepresentativeName } : {}),
    warnings,
  };
}

async function runCommand(command: string, args: string[]): Promise<{ ok: true; stdout: string } | { ok: false; message: string }> {
  try {
    const { stdout } = await execFileAsync(command, args, { encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 });
    return { ok: true, stdout };
  } catch (error: unknown) {
    return { ok: false, message: (error as Error)?.message || String(error) };
  }
}

async function extractVisibleTextWithOcr(pdfBytes: Buffer<ArrayBufferLike>): Promise<{ text: string; warnings: string[] }> {
  const warnings: string[] = [];
  const workspaceRoot = path.join(process.cwd(), 'artifacts', 'ocr-tmp');
  await mkdir(workspaceRoot, { recursive: true });
  const workspace = await mkdtemp(path.join(workspaceRoot, 'run-'));
  try {
    const pdfPath = path.join(workspace, 'document.pdf');
    await writeFile(pdfPath, pdfBytes);

    const pdftoppmCheck = await runCommand('pdftoppm', ['-v']);
    if (!pdftoppmCheck.ok) {
      warnings.push('OCR skipped: pdftoppm is not available in runtime.');
      return { text: '', warnings };
    }
    const tesseractCheck = await runCommand('tesseract', ['--version']);
    if (!tesseractCheck.ok) {
      warnings.push('OCR skipped: tesseract is not available in runtime.');
      return { text: '', warnings };
    }

    const imagePrefix = path.join(workspace, 'page');
    const render = await runCommand('pdftoppm', ['-png', pdfPath, imagePrefix]);
    if (!render.ok) {
      warnings.push(`OCR skipped: pdftoppm failed (${render.message}).`);
      return { text: '', warnings };
    }

    const pngFiles = (await readdir(workspace))
      .filter((name) => /^page-\d+\.png$/i.test(name))
      .sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
    if (!pngFiles.length) {
      warnings.push('OCR skipped: no PNG pages were rendered from PDF.');
      return { text: '', warnings };
    }

    const maxPages = Number.parseInt(process.env.ICA_OCR_MAX_PAGES || '3', 10);
    const selectedFiles = pngFiles.slice(0, Number.isFinite(maxPages) && maxPages > 0 ? maxPages : 3);
    const chunks: string[] = [];
    for (const fileName of selectedFiles) {
      const imagePath = path.join(workspace, fileName);
      const ocr = await runCommand('tesseract', [imagePath, 'stdout', '-l', 'spa+por+eng', '--psm', '6']);
      if (!ocr.ok) {
        warnings.push(`OCR warning on ${fileName}: ${ocr.message}`);
        continue;
      }
      chunks.push(ocr.stdout);
    }
    return { text: chunks.join('\n').trim(), warnings };
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

export async function extractVisibleOrganizationIdentityFromPdfText(
  pdfBytes: Buffer<ArrayBufferLike>,
  verifierVatList: string[],
  jurisdiction = 'ES',
): Promise<{ taxID?: string; legalName?: string; legalRepresentativeName?: string; warnings: string[] }> {
  const warnings: string[] = [];
  try {
    const module = await loadPdfParseModule();
    const PDFParse = module?.PDFParse;
    if (typeof PDFParse !== 'function') {
      warnings.push('Visible PDF text extraction skipped: pdf-parse PDFParse class not available.');
      return { warnings };
    }

    const parser = new PDFParse({ data: pdfBytes });
    let text = '';
    try {
      const parsed = await parser.getText();
      text = String(parsed?.text || '');
    } finally {
      try { await parser.destroy?.(); } catch { /* no-op */ }
    }
    const parsedFromVisibleText = parseOrganizationIdentityFromPlainText(text, verifierVatList, jurisdiction);
    warnings.push(...parsedFromVisibleText.warnings);
    if (parsedFromVisibleText.taxID || parsedFromVisibleText.legalName || parsedFromVisibleText.legalRepresentativeName) {
      return {
        ...(parsedFromVisibleText.taxID ? { taxID: parsedFromVisibleText.taxID } : {}),
        ...(parsedFromVisibleText.legalName ? { legalName: parsedFromVisibleText.legalName } : {}),
        ...(parsedFromVisibleText.legalRepresentativeName
          ? { legalRepresentativeName: parsedFromVisibleText.legalRepresentativeName }
          : {}),
        warnings,
      };
    }

    const ocr = await extractVisibleTextWithOcr(pdfBytes);
    warnings.push(...ocr.warnings);
    if (!ocr.text) return { warnings };
    const parsedFromOcr = parseOrganizationIdentityFromPlainText(ocr.text, verifierVatList, jurisdiction);
    warnings.push(...parsedFromOcr.warnings);
    return {
      ...(parsedFromOcr.taxID ? { taxID: parsedFromOcr.taxID } : {}),
      ...(parsedFromOcr.legalName ? { legalName: parsedFromOcr.legalName } : {}),
      ...(parsedFromOcr.legalRepresentativeName ? { legalRepresentativeName: parsedFromOcr.legalRepresentativeName } : {}),
      warnings,
    };
  } catch (error: unknown) {
    warnings.push(`Visible PDF text extraction skipped: ${(error as Error)?.message || String(error)}`);
    return { warnings };
  }
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
