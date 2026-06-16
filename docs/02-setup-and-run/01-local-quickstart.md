# 01 Local Quickstart

## Requirements

- Node.js 22+
- OpenSSL in `PATH`

## Install

```bash
npm install
```

## Minimum local setup

```bash
cp env.example .env.deploy.dev
echo 'ICA_SUPPORTED_JURISDICTIONS=ES' >> .env.deploy.dev
echo 'ICA_SUPPORTED_SECTORS=animal-care' >> .env.deploy.dev
npm run dev
```

## Optional self-sign bootstrap for local demos

```bash
echo 'ICA_SELF_SIGN_TEST=true' >> .env.deploy.dev
echo 'ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE=replace-with-strong-passphrase' >> .env.deploy.dev
echo 'ICA_VC_PRIVATE_KEY_SEED_CONFIG=17:8:1:48' >> .env.deploy.dev
echo 'ICA_VC_PRIVATE_KEY_SEED_SALT=ica-seed-salt-v1' >> .env.deploy.dev
echo 'ICA_VC_SEED_ALG=ES384' >> .env.deploy.dev
echo 'ICA_SELF_CONTROLLER_KID=ica-controller-es384-001' >> .env.deploy.dev
echo 'ICA_SELF_CONTROLLER_EMAIL=it-director@example.org' >> .env.deploy.dev
echo 'ICA_SELF_CONTROLLER_MEMBER_TYPE=controller' >> .env.deploy.dev
echo 'ICA_SELF_CONTROLLER_ROLE=1120' >> .env.deploy.dev
echo 'ICA_SELF_CONTROLLER_JURISDICTION=ES' >> .env.deploy.dev
echo 'ICA_SELF_CONTROLLER_SECTOR=management' >> .env.deploy.dev
echo 'ICA_SELF_SIGN_TEST_VALID_PROOF=true' >> .env.deploy.dev
npm run dev
```

## First checks

```bash
curl -sS http://localhost:3310/ | jq .
curl -sS http://localhost:3310/openapi.json | jq '.openapi'
curl -sS http://localhost:3310/.well-known/did.json | jq '.id'
curl -i http://localhost:3310/api-docs
```

## Useful commands

```bash
npm run dev
npm run api:local
npm run api:local:gcloud
npm run api:export
npm run api:example:activate
npm run test
npm run typecheck
```

## What to read next

- [`02-configuration.md`](./02-configuration.md)
- [`../03-api-and-flows/01-key-endpoints.md`](../03-api-and-flows/01-key-endpoints.md)
- [`../04-examples-and-tests/01-examples-fixtures-and-tests.md`](../04-examples-and-tests/01-examples-fixtures-and-tests.md)
