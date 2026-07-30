#!/usr/bin/env node

import { readFileSync } from 'node:fs';

const skillPath = new URL('../.codex/skills/ica-fabric-credential-registry/SKILL.md', import.meta.url);
const skill = readFileSync(skillPath, 'utf8');
const required = [
  'vc.id',
  'JWT jti',
  'credentialSubject.id',
  'JWT sub',
  'NETWORK_MODE=test',
  'networkKind',
  'terms',
  'local-network',
  'test-network',
  'network',
  'identity-local',
  'identity-global',
  'credential-sc',
  'ICA_VC_SIGNING_TRUST_REQUIRED',
  'ICA_ROOT_CA_DID',
  'did:web:ca.member.example',
  'CA:FALSE',
  'CA:TRUE',
  'HostingServiceCredential',
  'MSP',
];
const missing = required.filter((token) => !skill.includes(token));
if (missing.length) {
  throw new Error(`ICA Fabric skill is missing required contract tokens: ${missing.join(', ')}`);
}
console.log('ICA Fabric credential registry skill is synchronized.');
