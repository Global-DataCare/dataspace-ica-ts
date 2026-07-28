#!/usr/bin/env node

import { CredentialLedgerService } from '../src/api/tools/credential-ledger.ts';

const credentialIdIndex = process.argv.indexOf('--credential-id');
const credentialId = credentialIdIndex >= 0 ? String(process.argv[credentialIdIndex + 1] || '').trim() : '';
if (!credentialId) {
  console.error('Usage: npm run fabric:credential:read -- --credential-id <vc.id-or-jwt-jti>');
  process.exit(2);
}

const service = new CredentialLedgerService();
if (!service.config.enabled) {
  console.error(
    `Credential ledger is disabled for NETWORK_MODE=${service.config.networkMode}. `
    + 'Use local-network, or enable ICA_CREDENTIAL_LEDGER_ENABLED=true in test-network/network.',
  );
  process.exit(2);
}

const asset = await service.getCredential(credentialId);
if (!asset) {
  console.error(`Credential not found in ${service.config.channelName}: ${credentialId}`);
  process.exit(1);
}
console.log(JSON.stringify({
  channel: service.config.channelName,
  chaincode: service.config.chaincodeName,
  asset,
}, null, 2));
