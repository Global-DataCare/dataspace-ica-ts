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
```

This is a server policy, not a client-selected shortcut. A PDF-free `_verify`
request is accepted only when:

- its route `networkKind` is configured;
- DIDComm `iss`, `body.data[0].resource.organization.did` and the hostname in
  `org.schema.Service.url` identify the same configured host domain;
- `body.hostAuthorizationProof.jws` signs the exact route scope plus resource
  with ES384; and
- the request carries the public JWK and proves possession of its private key
  with the signed JWS; and
- a one-time activation stored only as a hash authorizes the exact domain,
  network, jurisdiction, issuance sector, legal identity, controller and
  service URL carried by the request.

The successful result includes one `HostingServiceCredential` represented as
both JSON VC and VC-JWT. Its evidence binds the verified JWS digest and is not
labelled as PDF/PAdES/IPFS evidence. The Fabric onboarding authority consumes
that authorization before registering the peer identity with the ICA de
Fabric; the host subsequently generates its MSP and TLS private keys locally
during enrollment.

The ordinary signed-PDF path remains unchanged for organizations and hosts not
preauthorized by governance. `ICA_MEMBER_DISCOVERY_ALLOWED_HOSTS` remains a
different outbound-discovery/SSRF boundary and never grants issuance rights.

The operator creates the activation from the running Kubernetes deployment
with `ica-cli host:activation:create`. The command writes the raw value once to
standard output. It reads the approved host JSON from standard input with
`--approval-stdin`; `kubectl exec -i` therefore avoids copying that file into
the pod. The ICA database stores only the activation SHA-256 hash, approved
fields, expiry and consumption state. The shell running `kubectl` redirects
the output into a private file on the operator's computer; the raw code is not
written inside the pod.

`ICA_PREAUTHORIZED_HOST_DID_DOCUMENTS_FILE` and its inline JSON equivalent
remain supported only for compatibility with earlier deployments. New host
onboarding uses the activation code and does not mount a provisional
`did.json`.

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

## PostgreSQL/IPFS migration profile

The migration executable uses separate source and target prefixes and requires
an exact source-project confirmation before `--apply`. Run the synthetic gate
first:

```bash
npm run evidence:migration:postgres-ipfs
```

Production migration configuration must remain in a private inventory. The
public contract and variable list are documented in
[`../06-architecture-and-reference/02-postgres-ipfs-gap.md`](../06-architecture-and-reference/02-postgres-ipfs-gap.md).

## Additional references

- GKE/security: [`../05-operations-and-deployment/01-gke-and-security.md`](../05-operations-and-deployment/01-gke-and-security.md)
- Environment-specific security and staging troubleshooting are maintained in
  the operations documentation outside this source repository.
