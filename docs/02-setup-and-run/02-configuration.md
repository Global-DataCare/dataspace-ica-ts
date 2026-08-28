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

## Governed hosts without PDF

The data-space governance decision can preauthorize host operators so the ICA
does not require an adhesion PDF from those hosts:

```dotenv
ICA_PREAUTHORIZED_HOST_DOMAINS=globaldatacare.es,member.example
ICA_PREAUTHORIZED_HOST_NETWORK_KINDS=local-network
# Optional for a host approved before its DNS/workload exists:
ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_FILE=/etc/ica/approved-hosts/did-documents.json
```

This is a server policy, not a client-selected shortcut. A PDF-free `_verify`
request is accepted only when:

- its route `networkKind` is configured;
- DIDComm `iss`, `body.data[0].resource.organization.did` and the hostname in
  `org.schema.Service.url` identify the same configured host domain;
- `body.hostAuthorizationProof.jws` signs the exact route scope plus resource
  with ES384; and
- the JWS key is published by that host's resolved `did:web` document.

The successful result includes one `HostingServiceCredential` represented as
both JSON VC and VC-JWT. Its evidence binds the verified JWS digest and is not
labelled as PDF/PAdES/IPFS evidence. The Fabric onboarding authority consumes
that authorization before registering the peer identity with the ICA de
Fabric; the host subsequently generates its MSP and TLS private keys locally
during enrollment.

The ordinary signed-PDF path remains unchanged for organizations and hosts not
preauthorized by governance. `ICA_MEMBER_DISCOVERY_ALLOWED_HOSTS` remains a
different outbound-discovery/SSRF boundary and never grants issuance rights.

`ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_FILE` points to an authoritative JSON
array of public DID documents, normally mounted read-only by the deployment.
ICA verifies the host JWS against the exactly matching document and does not
require host DNS to exist yet. The file must contain exactly one document for
the request issuer and no private JWK members. The older inline
`ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_JSON` form remains supported for local
compatibility; the file takes precedence when both are set. When neither is
configured, ICA resolves the normal public `did:web` document. This bootstrap
option authorizes identity proof only; it does not claim that the host
workload, DNS or TLS is live.

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

Deployment wrappers must scope the external secret resource name by
environment for every product: `{service}-st-signing-seed` in staging and
`{service}-prod-signing-seed` in production. Never rely only on project or
namespace separation, and never use an unscoped `{service}-signing-seed`.
Audited bootstrap configuration pins an exact Secret Manager version rather
than `latest`.

## Production notes

- Do not rely on self-sign fallback in production.
- Prefer Workload Identity over mounted JSON credentials in GKE.
- Keep `fabric-ca`, private enrollment material, and internal CA bridge traffic private.

## Additional references

- GKE/security: [`../05-operations-and-deployment/01-gke-and-security.md`](../05-operations-and-deployment/01-gke-and-security.md)
- Environment-specific security and staging troubleshooting are maintained in
  the operations documentation outside this source repository.
