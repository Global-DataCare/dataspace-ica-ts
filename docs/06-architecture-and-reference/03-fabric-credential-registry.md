# ICA credential registry on Hyperledger Fabric

## Implemented model

ICA now registers each successfully issued logical credential in
`credential-sc` on its authoritative identity channel. EU organization,
representative/employee, location, identity-evidence and identity-event
credentials belong to `identity-eu`. Natural-person individual credentials,
identity evidence and identity events belong to `identity-global`. A normal
organization verification
produces:

| Logical asset | JSON representation | JWT representation | Fabric status |
| --- | --- | --- | --- |
| Organization credential | `vc.id` | `jti = vc.id` | one status |
| Legal representative credential | `vc.id` | `jti = vc.id` | one status |

`credentialSubject.id` and JWT `sub` identify the subject. They are not the
credential key.

Consequently, two credentials represented as JSON-LD and JWT produce two
Fabric assets, not four. Each asset contains:

- one canonical SHA3-384 logical-content hash
- an exact hash for the emitted JSON-LD VC
- an exact hash for the emitted compact VC-JWT
- the issuer, subject, credential types and lifecycle status
- compact evidence references with the PDF CID, verifier DID and time, and
  certificate issuer/serial/signature time when present

The exact compact JWT emitted at issuance is also retained in ICA's
confidential credential record, so `_retrieve` does not silently replace it
with a newly signed token that has a different byte hash.

## Meaning of evidence `txn`

The existing value in:

```json
{
  "check_method": "vdig",
  "txn": "zKYrh..."
}
```

is the immutable PDF content reference/CID. It is shared when organization and
representative credentials derive from the same PDF. It is not a Fabric
transaction identifier. The real Fabric transaction ID is returned by the
gateway commit and is operational audit data, separate from VC evidence.

The electronic-signature evidence remains relevant and is projected without
discarding:

- `created_at`
- `issuer`
- `serial_number`
- signature type
- verifier organization and verification time

## Duplicate and tamper rules

Deterministic issuance must use `DETERMINISTIC_VC_BY_CONTRACT=true`. The PDF CID
then participates in the organization and representative `vc.id` values.

- same `vc.id` plus same logical hash: idempotent skip
- same `vc.id` plus different logical hash: fail closed
- same subject with another credential id: a separate credential

Public ICA signing keys prove who signed a VC, but they do not prove that this
specific credential was issued or remains active. Per-credential Fabric status
is therefore still required; revoking a signing key is not a substitute for
revoking one credential.

`credentialStatus.id` is stable as `<vc.id>#status`. ICA `_status` resolves the
logical credential, reads Fabric when enabled, and falls back to the legacy
collection only in non-Fabric mode. `_revoke` updates `credential-sc` and then
the off-ledger record. Revoking the organization credential does not implicitly
revoke the representative credential; callers can submit both ids when policy
requires a cascade.

## Local-network proof

From `dataspace-ica-ts`:

```bash
GATEWAY_REPOSITORY=../path-to-gateway-repository
npm --prefix "$GATEWAY_REPOSITORY" run local:fabric:stack -- --prepare-only
npm run test:fabric:credential
npm run fabric:credential:smoke:local
npm run api:local:fabric
```

The sibling bootstrap creates `identity-local` and deploys `credential-sc`.
The ICA command loads its normal local configuration plus the Fabric client
identity generated in `$GATEWAY_REPOSITORY/.env.local-fabric`.
It replaces the container-only peer name with `localhost:7051` and keeps
`peer0-org1` as the TLS certificate server-name override.
The smoke writes and revokes one fixed synthetic credential, so repeated runs
are idempotent and leave a visible Fabric history entry.

Run the existing PDF lifecycle in another terminal. After polling the
successful response, use each `body.data[].resource.id`:

```bash
npm run fabric:credential:read:local -- \
  --credential-id 'urn:<namespace>:<sector>:organization:vc:<pdf-cid>'

npm run fabric:credential:read:local -- \
  --credential-id 'urn:<namespace>:<sector>:organization-representative:vc:<pdf-cid>'
```

Expected result: two active assets. Repeating the same deterministic PDF keeps
the same two asset ids. Revoking one id changes that asset once and covers both
of its representations.

## Route context migration: test to test-network

Do not reinterpret the current `NETWORK_MODE=test` deployment. It remains the
legacy no-Fabric default. The canonical PDF path carries a typed
`networkKind`:

```text
/{tenantId}/cds-{jurisdiction}/v1/{sector}/{networkKind}/pdf/{resourceType}/_verify
```

`test` is no-Fabric, `local-network` anchors locally, `test-network` anchors in
staging, and `network` anchors in production. `terms` remains an accepted alias
for `test`, but response locations are canonicalized to `test`. This path
value selects the VC signing/registration context; checking the electronic
signatures in the PDF is a separate operation.

Use a parallel staging deployment and progress through these gates:

1. Deploy `credential-sc` on `identity-eu` for the organization profile and
   on `identity-global` for the individual profile. Provision an ICA Fabric
   client certificate/private key with the required endorsement policy.
2. Set:

   ```dotenv
   NETWORK_MODE=test-network
   ICA_CREDENTIAL_LEDGER_ENABLED=true
   ICA_CREDENTIAL_LEDGER_REQUIRED=true
   ICA_CREDENTIAL_LEDGER_CHANNEL=identity-eu
   ICA_CREDENTIAL_LEDGER_CHAINCODE=credential-sc
   ICA_FABRIC_MSP_ID=<ICA_MSP_ID>
   HLF_CONNECTION_PEER=<peer-host:port>
   HLF_CONNECTION_PEM=<peer-tls-root-pem>
   HLF_CERTIFICATE=<ica-fabric-client-certificate-pem>
   HLF_PRIVATE_KEY=<ica-fabric-client-private-key-pem>
   ```

3. Keep all PEM/key values in the Kubernetes Secret, never the ConfigMap.
4. Issue a synthetic organization/representative pair through the
   `identity-eu` profile and prove both assets,
   both hashes, idempotent re-submission, `_status`, and `_revoke`.
   Inside the configured staging pod, `npm run fabric:credential:smoke`
   provides the lower-level `credential-sc` commit/read/revoke gate.
5. Only after that proof, move traffic from the existing `test` deployment to
   the parallel `test-network` deployment.

The current ICA runtime accepts one configured channel per deployment. A
separate individual profile uses `ICA_CREDENTIAL_LEDGER_CHANNEL=identity-global`
until typed server-side multi-channel routing is implemented. A request may
choose the typed anchoring context but may never choose the Fabric channel,
MSP, peer, ACL or endorsement policy.

There is no automatic backfill in this change. Existing credentials issued in
legacy `test` should be inventoried and either reissued deterministically or
backfilled by a separately reviewed migration that verifies their original
signatures and evidence before calling `CreateCredential`.

## Root CA boundary

`dataspace-ca-ts` is not the issuer of organization or representative VCs and
must not create these two credential assets. Its future Fabric responsibility
is the trust-anchor/ICA authorization lifecycle (CA certificates, ICA signing
keys and revocation), in a separate typed asset model. X.509 material in an ICA
or organization DID document supports key validation; it does not replace the
per-credential issuance and revocation registry described here.

The ICA has two public X.509 roles which must not share a certificate:

- an ES384 `CA:FALSE` leaf signs VCs and is published through
  `/.well-known/x509.pem`;
- a dedicated ES384 `CA:TRUE`, `pathLen=0` subordinate issues organization and
  tenant leaves and is published through
  `/.well-known/organization-ca.pem`.

Neither certificate is a Fabric MSP identity. A host that operates a peer must
first present its signed `HostingServiceCredential` and a Root governance
decision. It then generates the MSP and TLS private keys and CSRs locally and
enrolls against Fabric CA; no tenant receives a Fabric private key merely by
being registered in ICA. Multiple governed dataspace ICAs are supported, and
each tenant certificate retains the chain of the ICA that issued it.

For a server-preauthorized `local-network` host, the dataspace ICA emits that
`HostingServiceCredential` as JSON VC plus VC-JWT from the verified host JWS.
The credential evidence contains the authorization digest only: it must not
claim that a PDF, PAdES signature, terms document or IPFS object existed. Run
`npm run test:host-preauthorization` to reproduce this issuance contract.
