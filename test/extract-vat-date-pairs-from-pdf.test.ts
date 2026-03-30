// @ts-nocheck
// test/extract-vat-date-pairs-from-pdf.test.ts
// Busca VATs y fechas cercanas en PDFs prueba* en /Users/fernando/GITS/gdc-workspace/examples


const fs = require('fs');
const path = require('path');
const assert = require('assert/strict');
const pdfParse = require('pdf-parse');

const examplesDir = '/Users/fernando/GITS/gdc-workspace/examples';
const pdfs = fs.readdirSync(examplesDir).filter(f => f.startsWith('prueba') && f.endsWith('.pdf'));

// Busca (R: <VAT>) donde <VAT> es un número (sin prefijo país) y fechas
const vatRegex = /\(R:\s*([A-Z0-9]+)\)/g;
const dateRegex = /([0-3]?\d)[/\-]([01]?\d)[/\-](\d{2,4})[\sT]([0-2]?\d):([0-5]?\d):([0-5]?\d)/g;

function findVatDatePairs(text) {
  const lines = text.split(/\r?\n/);
  const results = [];
  for (let i = 0; i < lines.length; ++i) {
    const line = lines[i];
    const vats = [...line.matchAll(vatRegex)];
    if (vats.length > 0) {
      // Buscar fechas en la misma línea y en las 2 siguientes
      let found = false;
      for (let j = 0; j <= 2 && i + j < lines.length; ++j) {
        const l = lines[i + j];
        const dates = [...l.matchAll(dateRegex)];
        for (const vat of vats) {
          const vatValue = vat[1] ? vat[1] : vat[0];
          for (const date of dates) {
            results.push({ vat: vatValue, date: date[0], context: l.trim() });
            found = true;
          }
        }
      }
      if (!found) {
        for (const vat of vats) {
          const vatValue = vat[1] ? vat[1] : vat[0];
          results.push({ vat: vatValue, date: '', context: line.trim() });
        }
      }
    }
  }
  return results;
}

describe('Extract VAT-date pairs from all prueba*.pdf (pdf-parse)', () => {
  for (const pdf of pdfs) {
    it(`should extract VAT-date pairs from ${pdf}`, async () => {
      const pdfPath = path.join(examplesDir, pdf);
      const data = fs.readFileSync(pdfPath);
      const parsed = await pdfParse(data);
      const text = parsed.text;
      const pairs = findVatDatePairs(text);
      console.log(`\nPDF: ${pdf}`);
      if (pairs.length === 0) {
        console.log('  No VAT-date pairs found');
      } else {
        for (const p of pairs) {
          console.log(`  VAT: ${p.vat} | Fecha: ${p.date} | Contexto: ${p.context}`);
        }
      }
      assert.ok(true);
    });
  }
});

describe('Extract VAT-date pairs from all prueba*.pdf', () => {
  for (const pdf of pdfs) {
    it(`should extract VAT-date pairs from ${pdf}`, () => {
      const pdfPath = path.join(examplesDir, pdf);
      const data = fs.readFileSync(pdfPath);
      const text = data.toString('latin1');
      const pairs = findVatDatePairs(text);
      console.log(`\nPDF: ${pdf}`);
      if (pairs.length === 0) {
        console.log('  No VAT-date pairs found');
      } else {
        for (const p of pairs) {
          console.log(`  VAT: ${p.vat} | Fecha: ${p.date} | Contexto: ${p.context}`);
        }
      }
      assert.ok(true);
    });
  }
});
