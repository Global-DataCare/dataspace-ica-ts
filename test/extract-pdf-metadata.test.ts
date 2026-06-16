// @ts-nocheck
// test/extract-pdf-metadata.test.ts
// Extrae y muestra los metadatos de fecha de todos los PDFs prueba* en $HOME/gdc-workspace/examples
import fs from 'fs';
import os from 'os';
import path from 'path';
import assert from 'assert/strict';
import { execFileSync } from 'child_process';

const examplesDir = path.join(os.homedir(), 'GITS', 'gdc-workspace', 'examples');
const pdfs = fs.readdirSync(examplesDir).filter(f => f.startsWith('prueba') && f.endsWith('.pdf'));

function extractPdfMetadata(pdfPath: string): Record<string, string> {
  // Usa exiftool si está disponible, o fallback a pdfinfo
  try {
    const out = execFileSync('exiftool', [pdfPath], { encoding: 'utf8' });
    const meta: Record<string, string> = {};
    for (const line of out.split('\n')) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const key = line.slice(0, idx).trim();
        const value = line.slice(idx + 1).trim();
        meta[key] = value;
      }
    }
    return meta;
  } catch {
    try {
      const out = execFileSync('pdfinfo', [pdfPath], { encoding: 'utf8' });
      const meta: Record<string, string> = {};
      for (const line of out.split('\n')) {
        const idx = line.indexOf(':');
        if (idx > 0) {
          const key = line.slice(0, idx).trim();
          const value = line.slice(idx + 1).trim();
          meta[key] = value;
        }
      }
      return meta;
    } catch {
      return {};
    }
  }
}

describe('Extract PDF metadata from all prueba*.pdf', () => {
  for (const pdf of pdfs) {
    it(`should extract metadata from ${pdf}`, () => {
      const pdfPath = path.join(examplesDir, pdf);
      const meta = extractPdfMetadata(pdfPath);
      console.log(`\nPDF: ${pdf}`);
      for (const k of Object.keys(meta)) {
        if (/date|fecha|mod/i.test(k)) {
          console.log(`  ${k}: ${meta[k]}`);
        }
      }
      assert.ok(Object.keys(meta).length > 0, 'No metadata found');
    });
  }
});
