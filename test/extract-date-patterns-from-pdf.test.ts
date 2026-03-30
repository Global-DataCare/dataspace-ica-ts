// @ts-nocheck
// test/extract-date-patterns-from-pdf.test.ts
// Busca fechas con formato típico en el contenido de los PDFs prueba* en /Users/fernando/GITS/gdc-workspace/examples
import fs from 'fs';
import path from 'path';
import assert from 'assert/strict';

const examplesDir = '/Users/fernando/GITS/gdc-workspace/examples';
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
      console.log(`\nPDF: ${pdf}`);
      if (matches.length === 0) {
        console.log('  No date patterns found');
      } else {
        for (const m of matches) {
          // Buscar contexto: 200 caracteres antes y después
          const idx = m.index ?? 0;
          const context = text.substring(Math.max(0, idx - 200), Math.min(text.length, idx + 200));
          console.log(`  Fecha encontrada: ${m[0]}\n--- CONTEXTO BINARIO ---\n${context}\n--- FIN CONTEXTO ---`);
        }
      }
      // Buscar la cadena G02793479 y mostrar contexto
      const vatStr = 'G02793479';
      let searchIdx = 0;
      let found = false;
      while ((searchIdx = text.indexOf(vatStr, searchIdx)) !== -1) {
        found = true;
        const context = text.substring(Math.max(0, searchIdx - 200), Math.min(text.length, searchIdx + 200));
        console.log(`  VAT encontrado: ${vatStr}\n--- CONTEXTO BINARIO ---\n${context}\n--- FIN CONTEXTO ---`);
        searchIdx += vatStr.length;
      }
      if (!found) {
        console.log('  No VAT G02793479 found in binary');
      }
      assert.ok(true);
    });
  }
});
