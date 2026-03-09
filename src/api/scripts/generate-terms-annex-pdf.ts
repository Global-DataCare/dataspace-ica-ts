import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { generateTermsAnnexPdf, TERMS_ANNEX_FIELD_SPECS } from '../tools/terms-annex-form.ts';

type ParsedArgs = {
  sourceFile: string;
  outFile: string;
  valuesFile?: string;
  title?: string;
};

function usage(): string {
  return [
    'Usage:',
    '  node ./src/api/scripts/generate-terms-annex-pdf.ts \\',
    '    --text-file ./terms.md \\',
    '    --out ./terms-annex.pdf \\',
    '    [--values-json ./annex-values.json] \\',
    '    [--title "Terms and Conditions - Annex"]',
    '',
    'Required predefined field names:',
    ...TERMS_ANNEX_FIELD_SPECS.map((field) => `  - ${field.name}`),
  ].join('\n');
}

function parseArgs(argv: string[]): ParsedArgs {
  const map = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index] || '';
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      map.set(key, 'true');
      continue;
    }
    map.set(key, next);
    index += 1;
  }

  const sourceFile = (map.get('text-file') || map.get('source-file') || '').trim();
  const outFile = (map.get('out') || '').trim();
  const valuesFile = (map.get('values-json') || '').trim() || undefined;
  const title = (map.get('title') || '').trim() || undefined;

  if (!sourceFile || !outFile) {
    throw new Error(`Missing required args.\n\n${usage()}`);
  }
  return { sourceFile, outFile, valuesFile, title };
}

async function readJsonObject(filePath: string): Promise<Record<string, string>> {
  const raw = await readFile(filePath, 'utf8');
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Invalid values JSON at ${filePath}: expected object.`);
  }
  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== 'string') continue;
    output[key] = value;
  }
  return output;
}

function shouldTreatAsMarkdown(filePath: string, text: string): boolean {
  const extension = path.extname(filePath).toLowerCase();
  if (extension === '.md' || extension === '.markdown') return true;
  return /^\s{0,3}(#{1,6}\s+|[-*+]\s+|\d+\.\s+|>\s+)/m.test(text);
}

function normalizeInlineMarkdown(line: string): string {
  return line
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/_([^_]+)_/g, '$1');
}

function markdownToPlainText(markdown: string): string {
  const lines = markdown.replace(/\r/g, '').split('\n');
  const out: string[] = [];
  let inCodeFence = false;

  for (const rawLine of lines) {
    let line = rawLine;
    const trimmed = line.trim();

    if (/^```/.test(trimmed)) {
      inCodeFence = !inCodeFence;
      continue;
    }
    if (inCodeFence) continue;
    if (/^\s*---+\s*$/.test(trimmed) || /^\s*\*\*\*+\s*$/.test(trimmed)) {
      out.push('');
      continue;
    }

    line = line.replace(/^\s{0,3}#{1,6}\s+/, '');
    line = line.replace(/^\s{0,3}>\s?/, '');
    line = line.replace(/^\s{0,3}[-*+]\s+/, '- ');
    line = line.replace(/^\s*•\s+/, '- ');

    line = normalizeInlineMarkdown(line).trimEnd();
    out.push(line);
  }
  return out.join('\n').trim();
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const sourceText = await readFile(args.sourceFile, 'utf8');
  const termsText = shouldTreatAsMarkdown(args.sourceFile, sourceText)
    ? markdownToPlainText(sourceText)
    : sourceText;
  const initialValues = args.valuesFile ? await readJsonObject(args.valuesFile) : undefined;

  const outPath = path.resolve(args.outFile);
  const result = await generateTermsAnnexPdf({
    outputPath: outPath,
    termsText,
    title: args.title,
    initialValues,
  });

  console.log(`Generated: ${result.outputPath}`);
  console.log('Included field names:');
  for (const field of result.includedFieldNames) {
    console.log(`- ${field}`);
  }
}

main().catch((error: unknown) => {
  const message = (error as Error)?.message || String(error);
  console.error(message);
  process.exitCode = 1;
});
