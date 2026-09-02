// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
/**
 * Journey:
 * 1. A clean public checkout enumerates every tracked source and documentation file.
 * 2. The portability gate rejects developer-specific macOS home-directory paths.
 * Authorization invariant: public instructions never disclose or depend on one operator workstation.
 * Persistence invariant: operational paths are supplied through environment variables or relative checkout paths.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

test('tracked public files contain no developer-specific macOS home path', () => {
  const repositoryRoot = new URL('..', import.meta.url);
  const trackedFiles = execFileSync('git', ['ls-files', '-z'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  }).split('\0').filter(Boolean);
  const forbiddenPrefix = ['', 'Users', ''].join('/');
  const offenders = trackedFiles.filter((file) =>
    readFileSync(new URL(file, repositoryRoot), 'utf8').includes(forbiddenPrefix));

  assert.deepEqual(offenders, []);
});
