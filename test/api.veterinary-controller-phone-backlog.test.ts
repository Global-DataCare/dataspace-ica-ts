// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('records functional-first veterinary controller phone OTP and deferred security review', async () => {
  const [backlog, skill, sync] = await Promise.all([
    readFile(new URL('../docs/adr-0004-veterinary-controller-phone-otp-backlog.md', import.meta.url), 'utf8'),
    readFile(new URL('../.codex/skills/ica-fabric-credential-registry/SKILL.md', import.meta.url), 'utf8'),
    readFile(new URL('../SYNC.md', import.meta.url), 'utf8'),
  ]);

  for (const contract of [backlog, skill, sync]) {
    assert.match(contract, /outbound voice call/i);
    assert.match(contract, /official marketplace telephone/i);
    assert.match(contract, /technical controller/i);
    assert.match(contract, /E\.164/);
    assert.match(contract, /hashed/i);
    assert.match(contract, /sameAs/);
  }
  assert.match(backlog, /Phase 1 - functional MVP/);
  assert.match(backlog, /Phase 2 - security hardening/);
  assert.match(backlog, /existing mobile.*match/i);
  assert.match(backlog, /open decision/i);
  assert.doesNotMatch(backlog, /implemented in the current runtime/i);
});
