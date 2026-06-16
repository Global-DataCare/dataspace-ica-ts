# 02 Configuration

## Configuration model

The service is environment-driven. The common startup files are:

- `.env.deploy.dev`
- `.env.deploy.demo`
- `.env.deploy.prod`
- `.env.local`
- `.env.local.gcloud`

## Minimum environment

At minimum you usually need:

- `ICA_SUPPORTED_JURISDICTIONS`
- `ICA_SUPPORTED_SECTORS`
- host/domain settings appropriate to your environment

## Common local signing options

For local or staging-style bootstrap:

- `ICA_SELF_SIGN_TEST=true`
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE=...`
- `ICA_VC_PRIVATE_KEY_SEED_CONFIG=17:8:1:48`
- `ICA_VC_PRIVATE_KEY_SEED_SALT=...`
- `ICA_VC_SEED_ALG=ES384`

For production-style operation:

- disable self-sign bootstrap
- use CA-issued material
- keep secrets outside plain env where possible

## Secret resolution order

Private key seed/passphrase configuration resolves in this order:

1. `*_FILE`
2. `*_SECRET_ENV`
3. direct env value
4. GCP Secret Manager

Relevant variables:

- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_FILE`
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_SECRET_ENV`
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE`
- `ICA_HOST_SECRET_PROVIDER=gcp-secret-manager`
- `ICA_GCP_PROJECT_ID`
- `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET`

## Production notes

- Do not rely on self-sign fallback in production.
- Prefer Workload Identity over mounted JSON credentials in GKE.
- Keep `fabric-ca`, private enrollment material, and internal CA bridge traffic private.

## Additional references

- GKE/security: [`../05-operations-and-deployment/01-gke-and-security.md`](../05-operations-and-deployment/01-gke-and-security.md)
- Existing security deep dive: [`../security-gke.md`](../security-gke.md)
- Existing staging troubleshooting: [`../troubleshooting-gke-ip-staging.md`](../troubleshooting-gke-ip-staging.md)
