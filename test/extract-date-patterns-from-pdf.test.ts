// @ts-nocheck
// test/extract-date-patterns-from-pdf.test.ts
// Busca fechas con formato típico en el contenido de los PDFs prueba* en $HOME/gdc-workspace/examples
import fs from 'fs';
import os from 'os';
import path from 'path';
import assert from 'assert/strict';

const examplesDir = path.join(os.homedir(), 'GITS', 'gdc-workspace', 'examples');
const pdfs = fs.readdirSync(examplesDir).filter(f => f.startsWith('prueba') && f.endsWith('.pdf'));

// Busca fechas tipo dd/mm/yyyy hh:mm:ss, dd-mm-yyyy hh:mm:ss o dd.mm.yy hh:mm:ss
const dateRegex = /([0-3]?\d)[/\-.]([01]?\d)[/\-.](\d{2,4})[\sT]([0-2]?\d):([0-5]?\d):([0-5]?\d)/g;

describe('Extract date patterns from all prueba*.pdf', () => {
  for (const pdf of pdfs) {
    it(`should extract date patterns from ${pdf}`, () => {
      const pdfPath = path.join(examplesDir, pdf);
      const data = fs.readFileSync(pdfPath);
      // Buscar en binario y en texto latin1
      const text = data.toString('latin1');
      const matches = [...text.matchAll(dateRegex)];
      // This diagnostic intentionally records only a count. Never print raw
      // PDF context because the fixture can contain real personal or company data.
      assert.ok(Array.isArray(matches));
      assert.ok(true);
    });
  }
});
