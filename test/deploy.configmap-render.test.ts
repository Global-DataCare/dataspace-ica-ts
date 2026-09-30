// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

test('deployment renderer resolves every ConfigMap placeholder from the environment', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ica-configmap-render-'));
  const manifestPath = join(directory, 'configmap.yaml');
  writeFileSync(
    manifestPath,
    [
      'data:',
      '  ICA_SUPPORTED_JURISDICTIONS: "${ICA_SUPPORTED_JURISDICTIONS}"',
      '  ICA_SUPPORTED_SECTORS: "${ICA_SUPPORTED_SECTORS}"',
      '  VERIFIERS_VAT_LIST: "${VERIFIERS_VAT_LIST}"',
      '  ICA_ALLOW_VERIFICATION_PARTNERS: "${ICA_ALLOW_VERIFICATION_PARTNERS}"',
      '  VERIFICATION_PARTNERS_VAT_LIST: "${VERIFICATION_PARTNERS_VAT_LIST}"',
      '  ICA_KNOWN_ROOT_CERT_URLS: "${ICA_KNOWN_ROOT_CERT_URLS}"',
      '  ICA_KNOWN_INTERMEDIATE_CERT_URLS: "${ICA_KNOWN_INTERMEDIATE_CERT_URLS}"',
      '',
    ].join('\n'),
  );

  const output = execFileSync(
    process.execPath,
    [resolve('scripts/render-k8s-manifest.mjs'), manifestPath],
    {
      cwd: resolve('.'),
      encoding: 'utf8',
      env: {
        ...process.env,
        ICA_SUPPORTED_JURISDICTIONS: 'ES,EU',
        ICA_SUPPORTED_SECTORS: 'health-care,animal-care',
        VERIFIERS_VAT_LIST: 'VATES-A00000000',
        ICA_ALLOW_VERIFICATION_PARTNERS: 'true',
        VERIFICATION_PARTNERS_VAT_LIST: 'VATES-B00000000',
        ICA_KNOWN_ROOT_CERT_URLS: 'https://trust.example/root.crt?version=1&format=der',
        ICA_KNOWN_INTERMEDIATE_CERT_URLS: 'https://trust.example/intermediate.crt',
      },
    },
  );

  assert.doesNotMatch(output, /\$\{[A-Z][A-Z0-9_]*\}/u);
  assert.match(output, /ICA_SUPPORTED_JURISDICTIONS: "ES,EU"/u);
  assert.match(output, /ICA_SUPPORTED_SECTORS: "health-care,animal-care"/u);
  assert.match(output, /VERIFIERS_VAT_LIST: "VATES-A00000000"/u);
  assert.match(output, /ICA_ALLOW_VERIFICATION_PARTNERS: "true"/u);
  assert.match(output, /VERIFICATION_PARTNERS_VAT_LIST: "VATES-B00000000"/u);
  assert.match(output, /version=1&format=der/u);
});

test('deployment renderer fails when a required ConfigMap placeholder is unset', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ica-configmap-render-missing-'));
  const manifestPath = join(directory, 'configmap.yaml');
  writeFileSync(manifestPath, 'data:\n  VALUE: "${ICA_SUPPORTED_JURISDICTIONS}"\n');

  assert.throws(
    () =>
      execFileSync(process.execPath, [resolve('scripts/render-k8s-manifest.mjs'), manifestPath], {
        cwd: resolve('.'),
        encoding: 'utf8',
        env: Object.fromEntries(
          Object.entries(process.env).filter(([key]) => key !== 'ICA_SUPPORTED_JURISDICTIONS'),
        ),
        stdio: 'pipe',
      }),
    /Command failed/u,
  );

  assert.equal(readFileSync(manifestPath, 'utf8').includes('${ICA_SUPPORTED_JURISDICTIONS}'), true);
});
