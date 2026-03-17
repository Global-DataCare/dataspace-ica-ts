# Organization Terms Remove V2

## Goal

`_remove` terminates the current accepted-terms state of one organization for one dataspace scope:

- tenant
- jurisdiction
- sector
- resourceType

It is not a generic hard-delete endpoint. It means:

- the organization no longer accepts those terms
- the organization is no longer active in that dataspace scope
- the organization must complete onboarding again before it can become active again

## Planned Endpoint

```text
POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_remove
POST /{tenantId}/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_remove-response
```

## Authorization Model

The request must be authorized by the controller message-signing key that was bound during onboarding.

- didactic mode:
  - `didcomm-plain`
  - controller binding key may still be surfaced as `meta.jws.protected.jwk`
- hardened mode:
  - require `didcomm-signed`
  - optionally wrap it in `didcomm-encrypted`

`meta.jws.protected.jwk` is only acceptable as transport metadata for the didactic mode. It must not be treated as sufficient authorization by itself in production.

## Request Contract

Minimal request:

```json
{
  "jti": "req-remove-org-001",
  "thid": "thid-remove-org-001",
  "type": "https://globaldatacare.es/didcomm/ica/terms/pdf/remove-request/v1",
  "body": {
    "data": [
      {
        "resource": {
          "organization": {
            "taxID": "VATES-B00000000"
          },
          "controller": {
            "sameAs": "urn:multibase:zControllerHash"
          },
          "reason": "organization-requested-removal"
        }
      }
    ]
  },
  "meta": {
    "jws": {
      "protected": {
        "alg": "ES384",
        "kid": "controller-es384-001",
        "jwk": {
          "kty": "EC",
          "crv": "P-384",
          "x": "<controller-x>",
          "y": "<controller-y>"
        }
      }
    }
  }
}
```

Recommended lookup fields:

- `organization.taxID` required
- `controller.sameAs` recommended
- optional `organization.identifier` if the caller wants to pin the expected DID
- optional `reason`

Validation rules:

1. a confirmed organization DID document must exist for that `taxID`
2. a confirmed controller binding must exist for that `taxID`
3. if `meta.jws.protected.jwk` is present, it must match the stored controller binding
4. if `controller.sameAs` is present, it must match the stored controller identity for that organization
5. if `organization.identifier` is present, it must match the confirmed DID document being removed

## Response Contract

Accepted:

- `202 Accepted`
- poll `_remove-response` with the same `thid`

Succeeded response resource:

```json
{
  "resourceType": "TermsRemoval-v1.0",
  "thid": "thid-remove-org-001",
  "tenantId": "ica",
  "jurisdiction": "ES",
  "sector": "animal-care",
  "resourceTypeScope": "contract",
  "status": "removed",
  "organizationTaxId": "VATES-B00000000",
  "did": "did:web:globaldatacare.es:animal-care:organization:taxid:VATES-B00000000",
  "removedAt": "2026-03-17T12:00:00.000Z",
  "reason": "organization-requested-removal",
  "effects": {
    "didBindings": "revoked",
    "didDocument": "removed",
    "catalogMembership": "removed",
    "organizationKeys": "revoked"
  }
}
```

## State Effects

### did_bindings

Planned effect:

- mark organization/controller binding state as revoked or removed
- preserve validity window:
  - `createdAt`
  - `confirmedAt`
  - `removedAt`

### did_documents

Planned effect:

- remove the active published DID document snapshot from normal resolution
- optionally keep a non-public tombstone record for audit/legal retention

### Catalog / DCAT

Planned effect:

- the organization must no longer appear in the active ICA catalog
- datasets/DDOs depending on active membership should no longer be published as active

### Keys

Planned effect:

- revoke all organization public keys that were active for that confirmed DID state
- the organization leaf certificates should be treated as no longer active from `removedAt`

### Credentials

Recommended policy:

- do not hard-delete verified onboarding evidence by default
- do not publish the organization as active anymore
- credentials whose validity depends on active membership should be revoked or treated as inactive by policy

This is different from blindly deleting all historical records.

## Re-enrollment Rule

If an organization is removed and later wants to return:

1. it must submit a new `_verify`
2. it must bootstrap/bind keys again
3. it must call `_create` again

In other words, removal closes one lifecycle. A later return starts a new lifecycle.

## Why `_remove` Instead Of `_delete`

`_remove` is better because it describes the business event:

- accepted terms are removed / terminated
- active dataspace participation ends

It avoids implying that every historical record is physically erased everywhere, which would be false for immutable logs or legally retained audit records.
