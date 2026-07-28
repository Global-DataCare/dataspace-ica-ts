# Fabric channel and chaincode evidence — 2026-07-28

## Scope and provenance

The raw capture is available in
[`2026-07-28-fabric-identity-global-peer.log`](./2026-07-28-fabric-identity-global-peer.log).
It was obtained read-only from:

- Kubernetes context:
  `gke_uhc-unid_europe-west4_fabric-uhc-unid-staging`
- namespace: `staging-fabric-v3`
- pod: `peer0-0`
- MSP: `UNIDMSP`
- Fabric image: `hyperledger/fabric-peer:3.1.3`

No private key, certificate body, Kubernetes Secret or bearer credential is
included in the capture.

## Evidence demonstrated

The peer reports membership of `identity-global` and five additional channels.
For `identity-global`, the captured ledger state was:

- height: `18`
- current block hash:
  `OCoMSAHi/ydVD8NeK7Lw2c7dXRgEEFeuRptluUaaa+I=`
- previous block hash:
  `9BW92wqcd317M4TsL92FQ7fI8r+q/ugRh7hJz/V2rRU=`

The committed chaincode definitions on that channel include:

- `credential-sc`, version `1.0`, sequence `1`
- `organization-sc`
- `subjectkeybinding-sc`
- `artifact-sc`
- `artifactevent-sc`
- `cryptographickey-sc`

This proves that the inspected UNID peer had joined `identity-global`, retained
its block ledger, and could resolve the committed `credential-sc` definition
at capture time. It does not by itself prove that ICA had submitted a real
credential transaction; that requires a separate transaction/readback
evidence containing a credential id and Fabric commit transaction id.

It also does not satisfy the organization identity design. EU organizations,
employees/controllers, locations, identity evidence and identity events belong
to `identity-eu`; natural-person individuals and their identity
evidence/events belong to `identity-global`. The captured peer had not joined
`identity-eu`, so Fundación UNID organization registration remains blocked.

## Endpoint correlation limitation

At capture time, `managing-orderer.member.example` resolved to `34.175.67.249`,
the LoadBalancer of the separate Kubernetes context
`gke_uhc-unid_europe-southwest1_fabric-uhc-unid-test`, namespace
`test-fabric-v3`.

The peer in that environment reported channels `identity`, `animal-pet-eu`
and `health-care-eu`. It rejected `identity-global` as an invalid channel and
its committed definitions on `identity` did not include `credential-sc`.

Therefore this annex must not be used to claim that
`managing-orderer.member.example` currently orders the captured
`identity-global` ledger. A production claim requires the production DNS,
orderer and peer to be correlated to the same channel configuration and
verified again after deployment.

## Accuro peer and ICA correlation

The explicitly inspected Accuro Fabric peer is:

- context: `gke_uhc-accuro_europe-southwest1_fabric-uhc-accuro-test`
- namespace: `test-fabric-v3`
- peer: `peer0-0`
- MSP used by the Accuro staging GW: `ACCUROMSP`

It has joined `identity`, `animal-pet-eu` and `health-care-eu`. Its committed
definitions on `identity` do not include `credential-sc`, and
`identity-global` is not present. Separately, both live GlobalDataCare ICA
deployments have credential-ledger/Fabric environment variables unset.
Consequently, current ICA issuance is Firestore/GCS-only; it is not submitting
credential assets through the Accuro peer.

## Reproducible commands

The peer's configured TLS root was stale for its own client command. The
read-only capture succeeded by selecting the ICA TLS CA already mounted in the
peer container:

```bash
CTX=gke_uhc-unid_europe-west4_fabric-uhc-unid-staging
NS=staging-fabric-v3

kubectl --context "$CTX" -n "$NS" exec -c peer peer0-0 -- env \
  FABRIC_LOGGING_SPEC=ERROR \
  CORE_PEER_ADDRESS=peer0:7051 \
  CORE_PEER_TLS_SERVERHOSTOVERRIDE=peer0 \
  CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/msp/tlscacerts/ica-tls-ca.pem \
  peer channel list

kubectl --context "$CTX" -n "$NS" exec -c peer peer0-0 -- env \
  FABRIC_LOGGING_SPEC=ERROR \
  CORE_PEER_ADDRESS=peer0:7051 \
  CORE_PEER_TLS_SERVERHOSTOVERRIDE=peer0 \
  CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/msp/tlscacerts/ica-tls-ca.pem \
  peer channel getinfo -c identity-global

kubectl --context "$CTX" -n "$NS" exec -c peer peer0-0 -- env \
  FABRIC_LOGGING_SPEC=ERROR \
  CORE_PEER_ADDRESS=peer0:7051 \
  CORE_PEER_TLS_SERVERHOSTOVERRIDE=peer0 \
  CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/msp/tlscacerts/ica-tls-ca.pem \
  peer lifecycle chaincode querycommitted -C identity-global
```
