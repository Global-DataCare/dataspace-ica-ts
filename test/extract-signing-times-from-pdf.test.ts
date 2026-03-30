// @ts-nocheck
// test/extract-signing-times-from-pdf.test.ts
// Extrae y muestra el atributo signingTime de todas las firmas CMS de un PDF
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import assert from 'assert/strict';

async function extractCmsFromPdf(pdfPath: string): Promise<Buffer[]> {
  // Busca los objetos de firma (byte range) en el PDF
  const pdfData = fs.readFileSync(pdfPath);
  const pdfText = pdfData.toString('latin1');
  const sigRegex = /\/Type\s*\/Sig[\s\S]*?\/Contents\s*<([0-9A-Fa-f]+)>/g;
  const matches = [...pdfText.matchAll(sigRegex)];
  return matches.map((m) => Buffer.from(m[1], 'hex'));
}

function extractSigningTimeFromCms(cmsDer: Buffer): string | undefined {
  // Escribe la firma DER a un archivo temporal
  const tmpPath = path.join('/tmp', `cms-${Date.now()}-${Math.random()}.der`);
  fs.writeFileSync(tmpPath, cmsDer);
  try {
    const out = execFileSync('openssl', ['cms', '-cmsout', '-print', '-inform', 'DER', '-in', tmpPath], { encoding: 'utf8' });
    const match = /signingTime[\s\S]{0,300}?(?:UTCTIME|GENERALIZEDTIME):([^\r\n]+)/i.exec(out);
    return match?.[1]?.trim();
  } catch (e) {
    return undefined;
  } finally {
    fs.unlinkSync(tmpPath);
  }
}

// Test para todos los PDFs prueba* en /Users/fernando/GITS/gdc-workspace/examples
const examplesDir = '/Users/fernando/GITS/gdc-workspace/examples';
const pdfs = fs.readdirSync(examplesDir).filter(f => f.startsWith('prueba') && f.endsWith('.pdf'));

describe('Extract signingTime from all prueba*.pdf', () => {
  for (const pdf of pdfs) {
    it(`should extract signingTime from all CMS signatures in ${pdf}`, async () => {
      const pdfPath = path.join(examplesDir, pdf);
      const cmsList = await extractCmsFromPdf(pdfPath);
      assert.ok(cmsList.length > 0, 'No CMS signatures found');
      cmsList.forEach((cms, idx) => {
        const signingTime = extractSigningTimeFromCms(cms);
        console.log(`PDF: ${pdf} | Firma #${idx + 1} | signingTime: ${signingTime || 'NO ATTR'}`);
      });
    });
  }
});
