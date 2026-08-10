import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { deriveScryptSeparatedEcPemKeyPair, parseDeterministicSeedSalt, parseScryptDerivationProfile } from 'gdc-common-utils-ts/utils/deterministic-seed-key';
import { multibase58MultihashSha3_256 } from 'gdc-common-utils-ts/utils/same-as';

const execFileAsync = promisify(execFile);
const cliPath = path.resolve('bin/ica-cli.js');

test('ica-cli help exposes an extensible generic ICA scope without the historical catalog', async () => {
  const { stdout } = await execFileAsync(process.execPath, [cliPath, '--help']);
  assert.match(stdout, /--scope dataspace:ica/);
  assert.doesNotMatch(stdout, /vet-insurance:reader/);
});

test('controller bootstrap reuses the shared compatibility key and alias contracts', async () => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'ica-cli-controller-'));
  const passphrase = 'controller bootstrap regression secret';
  const salt = 'controller-bootstrap-test-salt';
  await execFileAsync(process.execPath, [
    cliPath,
    'controller:bootstrap',
    '--domain', 'ica.example.org',
    '--email', 'controller@example.org',
    '--jurisdiction', 'ES',
    '--scrypt', '10:8:1:48',
    '--salt', salt,
    '--passphrase', passphrase,
    '--out-dir', outDir,
  ]);

  const actualJwk = JSON.parse(await readFile(path.join(outDir, 'controller-public-jwk.json'), 'utf8'));
  const metadata = JSON.parse(await readFile(path.join(outDir, 'controller-bootstrap.json'), 'utf8'));
  const expected = deriveScryptSeparatedEcPemKeyPair({
    passphrase,
    salt: parseDeterministicSeedSalt(salt, 'unused').salt,
    profile: parseScryptDerivationProfile('10:8:1:48'),
    alg: 'ES384',
    separationTag: 'gdc:v1:ica:controller:es384',
  });
  assert.deepEqual(
    { kty: actualJwk.kty, crv: actualJwk.crv, x: actualJwk.x, y: actualJwk.y },
    expected.publicJwk,
  );
  assert.equal(actualJwk.kid, expected.kidRfc7638);
  assert.equal(metadata.controllerEmailHash, multibase58MultihashSha3_256('controller@example.org'));
});
