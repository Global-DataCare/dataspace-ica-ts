# Root CA and ICA signing trust

## Ownership boundary

Fundación UNID operates the offline Root CA. Its public authority is the static
`did:web:ca.unid.online` surface; the Root private key is never copied to ICA,
GKE or an online service.

Accuro operates ICA at `ica.globaldatacare.es`. ICA owns its leaf signing
private key. An offline CA workflow signs the corresponding CSR and returns the
leaf, issuing CA and Root certificates. The complete public chain is loaded
beside the ICA private key during activation.

## Why both X.509 and `ICA_ROOT_CA_DID` exist

The X.509 chain proves that the ICA leaf was signed through the issuing CA by a
specific Root key. The configured SHA-256 pin fixes which Root certificate is
accepted.

`ICA_ROOT_CA_DID=did:web:ca.unid.online` resolves that same Root public key as a
governed web identity with public discovery metadata. It does not duplicate or
replace the certificate: startup requires the DID verification JWK and inline
`x5c` to match the pinned terminal Root certificate.

## Required staging cutover inputs

Public ConfigMap values:

```dotenv
ICA_ROOT_CA_DID=did:web:ca.unid.online
ICA_ROOT_CA_CERT_SHA256=<fingerprint from https://ca.unid.online/.well-known/trust.json>
ICA_VC_SIGNING_X5U=https://ica.globaldatacare.es/.well-known/x509.pem
ICA_VC_SIGNING_TRUST_REQUIRED=true
```

Secret values:

```dotenv
ICA_VC_SIGNING_PRIVATE_KEY_PEM=<ICA leaf private key>
ICA_VC_SIGNING_CERTIFICATE_CHAIN_PEM=<ICA leaf + issuer + Root PEM chain>
ICA_VC_SIGNING_ALG=ES384
ICA_VC_SIGNING_KEY_ID=<RFC 7638 JWK thumbprint>
```

ICA starts listening only after all bindings validate. The served DID and JWKS
reuse the exact active `x5c` and `x5u`; `/.well-known/x509.pem` serves the
public chain. This change does not provision DNS, static IPs, buckets or
Kubernetes resources.
