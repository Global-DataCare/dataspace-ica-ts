// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('records functional-first veterinary controller phone OTP and deferred security review', async () => {
  const [backlog, invitationBacklog, skill, sync] = await Promise.all([
    readFile(new URL('../docs/adr-0004-veterinary-controller-phone-otp-backlog.md', import.meta.url), 'utf8'),
    readFile(new URL('../docs/adr-0005-professional-invitation-email-otp-backlog.md', import.meta.url), 'utf8'),
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

  for (const contract of [invitationBacklog, skill, sync]) {
    assert.match(contract, /organization verification OTP/i);
    assert.match(contract, /professional invitation OTP/i);
    assert.match(contract, /employee email/i);
    assert.match(contract, /employee phone/i);
    assert.match(contract, /email instead of SMS/i);
    assert.match(contract, /physical-site verification/i);
  }
  assert.match(invitationBacklog, /Veterinary CA\/US/);
  assert.match(invitationBacklog, /Human health CA\/US/);
  assert.match(invitationBacklog, /official marketplace telephone/i);
  assert.match(invitationBacklog, /technical-controller mobile/i);
  assert.match(invitationBacklog, /does not verify the organization/i);
  assert.match(invitationBacklog, /does not complete DCR/i);
  assert.match(invitationBacklog, /organization remains inactive/i);
  assert.match(invitationBacklog, /numeric legal-address code/i);
  assert.match(invitationBacklog, /bound to the hash of the PDF/i);
  assert.match(invitationBacklog, /technical controller submits/i);
  assert.match(invitationBacklog, /runtime transport remains pending/i);
});
