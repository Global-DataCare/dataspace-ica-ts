import { deriveDeterministicEcPrivateKeyPem } from '../tools/deterministic-key-material.ts';

const tenantId = process.env.ICA_LOCAL_TENANT_ID || 'ica';
const jurisdiction = process.env.ICA_EXAMPLE_JURISDICTION || 'ES';
const sector = process.env.ICA_EXAMPLE_SECTOR || 'animal-care';
const baseUrl = process.env.ICA_EXAMPLE_BASE_URL || 'http://localhost:3310';
const thid = process.env.ICA_EXAMPLE_THID || 'activate-deterministic-001';

const es384 = deriveDeterministicEcPrivateKeyPem('ica-seed-es384', 'P-384');
const es256k = deriveDeterministicEcPrivateKeyPem('ica-seed-es256k', 'secp256k1');

const activatePath = `/${tenantId}/cds-${jurisdiction}/v1/${sector}/entity/keys/credentials/_activate`;
const activateResponsePath = `/${tenantId}/cds-${jurisdiction}/v1/${sector}/entity/keys/credentials/_activate-response`;

const payload = {
  jti: `msg-${thid}`,
  thid,
  type: 'https://globaldatacare.es/didcomm/ica/signing-keys/activate-request/v1',
  body: {
    data: [
      {
        key: {
          kid: es384.kidRfc7638,
          alg: 'ES384',
          privateKeyPem: es384.privateKeyPem,
        },
      },
      {
        key: {
          kid: es256k.kidRfc7638,
          alg: 'ES256K',
          privateKeyPem: es256k.privateKeyPem,
        },
      },
    ],
  },
};

const output = {
  note: 'TEST ONLY. Never use these deterministic keys in production.',
  endpoint: `${baseUrl}${activatePath}`,
  pollEndpoint: `${baseUrl}${activateResponsePath}?thid=${encodeURIComponent(thid)}`,
  kids: {
    es384: es384.kidRfc7638,
    es256k: es256k.kidRfc7638,
  },
  didcommPayload: payload,
  curl: {
    activate: `curl -i -X POST "${baseUrl}${activatePath}" -H "Content-Type: application/didcomm-plain+json" --data @/tmp/activate-payload.json`,
    poll: `curl -sS -X POST "${baseUrl}${activateResponsePath}?thid=${encodeURIComponent(thid)}" | jq .`,
  },
};

process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
