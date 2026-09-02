// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const expectedCommonUtilsVersion = '2.7.2';

test('pins the current shared contract release for reproducible clean ICA installs', () => {
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    dependencies?: Record<string, string>;
  };
  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8')) as {
    packages?: Record<string, { version?: string }>;
  };

  assert.equal(manifest.dependencies?.['gdc-common-utils-ts'], expectedCommonUtilsVersion);
  assert.equal(lock.packages?.['node_modules/gdc-common-utils-ts']?.version, expectedCommonUtilsVersion);
});
