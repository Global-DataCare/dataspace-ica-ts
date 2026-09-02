// scripts/extract-vat-date-pairs-from-pdf.js
// Extrae (R: <VAT>) y fechas cercanas de PDFs de prueba del directorio configurado.
import fs from 'fs';
import path from 'path';
import * as pdfParseNS from 'pdf-parse';

const examplesDir = process.env.ICA_PDF_EXAMPLES_DIR || path.resolve(process.cwd(), '../examples');
const pdfs = fs.readdirSync(examplesDir).filter(f => f.startsWith('prueba') && f.endsWith('.pdf'));

const vatRegex = /\(R:\s*([A-Z0-9]+)\)/g;
const dateRegex = /([0-3]?\d)[/\-]([01]?\d)[/\-](\d{2,4})[\sT]([0-2]?\d):([0-5]?\d):([0-5]?\d)/g;

function findVatDatePairs(text) {
  const lines = text.split(/\r?\n/);
  const results = [];
  for (let i = 0; i < lines.length; ++i) {
    const line = lines[i];
    const vats = [...line.matchAll(vatRegex)];
    if (vats.length > 0) {
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

(async () => {
  for (const pdf of pdfs) {
    const pdfPath = path.join(examplesDir, pdf);
    const data = fs.readFileSync(pdfPath);
    // pdf-parse puede exportar como default o como función directa según entorno
    const parse = pdfParseNS.default ? pdfParseNS.default : pdfParseNS;
    const parsed = await parse(data);
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
  }
})();
