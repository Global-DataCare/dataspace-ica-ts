# Root CA and ICA signing trust

## Ownership boundary

The deployment's designated trust operator controls the offline Root CA. Its
public authority is a deployment-configured static `did:web` surface; the Root
private key is never copied to ICA, Kubernetes or an online service.

The ICA operator owns its leaf signing private key. An offline CA workflow
signs the corresponding CSR and returns the leaf, issuing CA and Root
certificates. The complete public chain is loaded beside the ICA private key
during activation.

Every product must make the environment boundary visible in custody resource
names: `{service}-st-signing-seed` and `{service}-st-signing-chain` for
staging; `{service}-prod-signing-seed` and
`{service}-prod-signing-chain` for production. An unscoped name is invalid.
Renaming a deployed staging resource preserves its exact bytes and identity;
production creates independent signing material. Audited deployment inputs
pin exact secret versions and never `latest`.

In staging, `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE` regenerates that ICA-owned
ES384 leaf key with scrypt salt `gdc:ica:vc:seed:v1` and domain separation
`gdc:v1:ica:vc:es384`. It never derives or loads a `dataspace-ca-ts` Root or
issuer key. To request a certificate for the already deployed key, run
`dataspace-ca-ts leaf:request` with
`--key-derivation-profile ica-vc-runtime-v1`; only its public CSR leaves
operator custody. A configured `ICA_VC_SIGNING_PRIVATE_KEY_PEM` takes
precedence over seed derivation.

## Why both X.509 and `ICA_ROOT_CA_DID` exist

The X.509 chain proves that the ICA leaf was signed through the issuing CA by a
specific Root key. The configured SHA-256 pin fixes which Root certificate is
accepted.

`ICA_ROOT_CA_DID=did:web:ca.example.org` resolves that same Root public key as a
governed web identity with public discovery metadata. It does not duplicate or
replace the certificate: startup requires the DID verification JWK and inline
`x5c` to match the pinned terminal Root certificate.

## Required staging cutover inputs

Public ConfigMap values:

```dotenv
ICA_ROOT_CA_DID=did:web:ca.example.org
ICA_ROOT_CA_CERT_SHA256=<fingerprint from https://ca.example.org/.well-known/trust.json>
ICA_VC_SIGNING_X5U=https://ica.example.org/.well-known/x509.pem
ICA_VC_SIGNING_TRUST_REQUIRED=true
```

Secret values:

```dotenv
ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE=<protected ICA leaf seed>
ICA_VC_SIGNING_CERTIFICATE_CHAIN_PEM=<ICA leaf + issuer + Root PEM chain>
ICA_VC_SIGNING_ALG=ES384
ICA_VC_SIGNING_KEY_ID=<RFC 7638 JWK thumbprint>
```

`ICA_VC_SIGNING_PRIVATE_KEY_PEM` may replace the seed when non-deterministic
key custody is used. Do not configure both as if they represented different
keys: the explicit PEM wins and must match the returned leaf certificate.
ICA starts listening only after all bindings validate. The served DID and JWKS
reuse the exact active `x5c` and `x5u`; `/.well-known/x509.pem` serves the
public chain. This change does not provision DNS, static IPs, buckets or
Kubernetes resources.
