// scripts/extract-signature-visual-dates.cjs
// Extrae todas las fechas visuales de firma (campo /Date(...) cerca de (R: <VAT>)) del binario de PDFs prueba* y muestra la última como signingDate efectiva.
const fs = require('fs');
const path = require('path');

const examplesDir = process.env.ICA_PDF_EXAMPLES_DIR || path.resolve(process.cwd(), '../examples');
const pdfs = fs.readdirSync(examplesDir).filter(f => f.startsWith('prueba') && f.endsWith('.pdf'));

const vatRegex = /\(R: ?([A-Z0-9]+)\)/g;
const dateVisualRegex = /\/Date\(([^)]+)\)/g;

for (const pdf of pdfs) {
  const pdfPath = path.join(examplesDir, pdf);
  const data = fs.readFileSync(pdfPath);
  const text = data.toString('latin1');
  // Buscar todos los bloques con VAT y fechas visuales
  const results = [];
  let idx = 0;
  while ((idx = text.indexOf('/Name(', idx)) !== -1) {
    // Buscar VAT en el bloque /Name(...)
    const nameEnd = text.indexOf(')', idx + 6);
    if (nameEnd === -1) break;
    const nameBlock = text.substring(idx, nameEnd + 1);
    const vatMatch = nameBlock.match(vatRegex);
    if (vatMatch) {
      // Buscar fecha visual cerca (en los siguientes 300 caracteres)
      const after = text.substring(nameEnd, nameEnd + 300);
      const dateMatch = after.match(dateVisualRegex);
      if (dateMatch) {
        results.push({
          vat: vatMatch[0],
          date: dateMatch[0].replace('/Date(', '').replace(')', ''),
          raw: nameBlock + after
        });
      }
    }
    idx = nameEnd + 1;
  }
  // Mostrar resultados
  console.log(`\nPDF: ${pdf}`);
  if (results.length === 0) {
    console.log('  No firmas visuales encontradas');
  } else {
    for (const r of results) {
      console.log(`  VAT: ${r.vat} | Fecha visual: ${r.date}`);
    }
    // Escoger la última fecha como signingDate efectiva
    const last = results[results.length - 1];
    console.log(`  ---> signingDate efectiva: ${last.date}`);
  }
}
