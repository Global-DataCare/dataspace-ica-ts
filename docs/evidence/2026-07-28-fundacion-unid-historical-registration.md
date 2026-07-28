# Fundación UNID historical registration evidence — 2026-07-28

## Canonical tenant identity

- tenant: `VATES-G02793479`
- historical sector: `onehealth-research`
- target staging DID document:
  `https://uhc-gw.member.example/VATES-G02793479/cds-ES/v1/onehealth-research/.well-known/did.json`
- signed legal representative: Nuria Sala Cano (`nuriasala@unid.es`)
- contract technical contact and non-production controller: `cto@unid.es`
- optional separate Google administrator: `fernandolatorre@unid.es`

The isolated professional portal may authenticate `cto@unid.es` with a
verified Firebase Email/Password identity. Its controller wallet may be created
only after exact email verification. This supplemental controller binding must
not be represented as content signed in the contract. Password authentication
is disabled for production.

## Countersigned PDF

Source:

```text
discovery/globaldatacare-ica-dev/pdfs/VATES-G02793479/CONTRATO FIRMADO GLOBALDATACARE- FUNDACION UNID.pdf
```

- SHA-256:
  `592f1a663dda3456ab5a7d6f6d29c1a2eb2e19552c6d875c06e9f3bd4ae5945c`
- SHA-384:
  `d9d930293fac7c208b0a7ceb730daae630a583cfbafda3d801ddbb91aeff9af3561f87d9e240c8118eaa1a6edd3c716d`
- UNID signature: Nuria Sala, signing time `2026-03-30T07:24:09+02:00`
- Accuro signature: Iván Becerro, signing time `2026-03-30T11:06:30+02:00`

`pdfsig` validated both detached PDF signatures. Its local NSS certificate
validation reported an unknown trust-database issue, so current chain and
revocation validity must be checked through the normal ICA verifier rather than
inferred from this local command alone.

## Existing Firestore records

Authoritative source:
`globaldatacare-ica-dev/(default)/dev_issued_credentials`.

Both logical credentials preserve:

- VC `validFrom`, proof creation and evidence time:
  `2026-03-30T09:06:30.000Z`
- record `createdAt`: `2026-03-30T17:21:00.956Z`
- Firestore system `createTime`: `2026-03-30T17:21:01.039656Z`
- PDF CID:
  `zKYrhSD4zDMjXLaCjHapZc1VD37xcC2aaGGcHa9pGZiMxRjaomBr1ZtxRV2sjhAach8hH5n`

Logical credential ids:

```text
urn:globaldatacare:onehealth-research:organization:vc:zKYrhSD4zDMjXLaCjHapZc1VD37xcC2aaGGcHa9pGZiMxRjaomBr1ZtxRV2sjhAach8hH5n
urn:globaldatacare:onehealth-research:organization-representative:vc:zKYrhSD4zDMjXLaCjHapZc1VD37xcC2aaGGcHa9pGZiMxRjaomBr1ZtxRV2sjhAach8hH5n
```

A Firestore copy can preserve the stored `createdAt`, VC and evidence
timestamps exactly. Firestore assigns a new immutable system `createTime` to a
new destination document; migration must therefore also retain the original
system value as explicit provenance if that timestamp is required.

## Current Fabric status

The live `dataspace-ica-api` (`dev`) and `dataspace-ica-api-st-v2` deployments
have no `NETWORK_MODE`, credential-ledger flags, HLF connection or Fabric MSP
configured. Both currently use Firestore/GCS and do not anchor credentials in
Fabric.

The Accuro peer uses `ACCUROMSP`, has joined `identity`, `animal-pet-eu` and
`health-care-eu`, and has no `identity-global` channel or committed
`credential-sc`. It cannot receive the historical credential backfill in its
current state.

The inspected UNID staging peer has `identity-global` and `credential-sc`, but
it has not joined the required `identity-eu` organization plane. Fundación
UNID's organization and representative/controller credential backfill must not
be written to `identity-global`. It remains blocked until `identity-eu` exists
with the required chaincodes, ICA has an explicitly provisioned Fabric client
identity, and a reviewed backfill verifies the existing VC
signatures/evidence before calling `CreateCredential`.
