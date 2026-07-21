# ICA member autodiscovery authorization

## Current staging contract

The member cache may resolve DID documents, signed Gaia-X VC-JWT artifacts and
DCAT catalogs only from hosts explicitly listed in
`ICA_MEMBER_DISCOVERY_ALLOWED_HOSTS`. Entries are comma-separated static IPs,
DNS names or HTTP(S) origins. An empty list authorizes no remote traversal.

This allowlist is a temporary network authorization boundary. ICA still
requires its own current `OrganizationCredential` and a confirmed DID record
before a member can appear in discovery. Being present in the environment does
not issue a credential and does not prove Gaia-X conformance.

Staging may list static IPs until DNS is assigned. The allowlist compares the
URL hostname, not paths, credentials, queries or fragments, and therefore does
not turn an arbitrary URL supplied by a credential into an SSRF target.

## Canonical host registration

The environment list must later be replaced by a persistent host registry. A
host registration request will present a signed governance
`HostAuthorizationCredential` whose subject is the host DID. The credential is
issued by the data-space governance authority using a chain rooted in the
data-space Root CA and states at least:

- host DID and authorized network endpoint;
- jurisdictions, sectors and tenant-hosting scopes;
- issuer, issuance and expiry times;
- credential status/revocation reference;
- optional limits on which tenants or service capabilities may be hosted.

ICA verifies the VC signature, issuer trust chain, status, expiry, DID binding
and requested scope before persisting the host. The Root CA certificate is the
trust anchor; it is not itself the host authorization. Revocation or expiry
removes the host from traversal even if an obsolete environment entry remains.

The discovery response continues to return source artifacts, not inferred
claims: schema.org credentials in `data[].vc`, the DID document with provenance
in `data[].did`, exact signed Gaia-X VC-JWTs in DIDComm attachments, and the
resolved DCAT catalog with its cache metadata.
