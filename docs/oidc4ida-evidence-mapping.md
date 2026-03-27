# OIDC4IDA Evidence Mapping (ICA Verification)

## Scope

This document describes how the ICA verification flow encodes evidence in OIDC4IDA Verified Claims, and how current implementation maps to the specification sections mentioned in OpenID Identity Assurance (`openid-ida-verified-claims-1_0`).

Focus areas:
- `evidence` element structure (`5.4.4` / `5.4.4.1`)
- evidence `type` usage (`document`, `electronic_signature`)
- `check_method` usage (`vdig`, `vcrypt`)
- assurance semantics (`source` and `assuranceLevel`) used by ICA

---

## Short answer: Are we using OIDC4IDA standards?

Yes, partially and intentionally:
- We use OIDC4IDA evidence objects with valid `type` members (`electronic_signature`, `document`).
- We use `check_details.check_method` with predefined values (`vdig`, `vcrypt`).
- We include verifier metadata and digest details for auditability.

And we also add ICA-specific extension payload in the signature attachment:
- `profile: "oidc4ida-evidence-v1"`
- `source: "qualified_certification" | "visible_pdf_fields"`
- `assuranceLevel: "low" | "medium" | "high"`

This extension is compatible as embedded JSON attachment but is not itself a standardized OIDC4IDA top-level field.

---

## Compliance matrix (audit format)

Status legend:
- **Compliant**: implemented and aligned with the final model intent.
- **Partial**: implemented with caveat, extension, or migration pending.
- **Gap**: not implemented yet or not aligned.

| Requirement / Spec reference | Current implementation | Status | Evidence in code/payload | Action |
|---|---|---|---|---|
| `evidence[]` object structure (`5.4.4.1`) | Uses evidence array with typed members | Compliant | `type=electronic_signature` + `type=document` objects in VC evidence | Keep |
| `evidence.type=document` | Implemented | Compliant | `document` evidence includes verifier, check details, digest, document details | Keep |
| `evidence.type=electronic_signature` | Implemented | Compliant | `electronic_signature` evidence includes issuer, serial, created_at, attachment | Keep |
| `check_details.check_method` predefined values | Uses `vdig` and `vcrypt` | Compliant | `document.check_details[]` includes both checks | Keep |
| Distinguish identity source (cert DN vs visible PDF fields) | Implemented via extension `source` | Partial | Attachment JSON: `source=qualified_certification|visible_pdf_fields` | Keep extension; document as ICA profile |
| Assurance level semantics | Implemented via extension `assuranceLevel` | Partial | Attachment JSON: `assuranceLevel=low|medium|high` | Optionally add OpenID URI mapping field |
| OpenID assurance URI form | Not emitted today | Gap | No URI-level assurance claim in payload | Add companion field (e.g. `assuranceUri`) |
| Deprecated `method` handling in document evidence | Emits `method=eid` for backward compatibility | Partial | `document.method=eid` currently present | Plan deprecation/removal or feature flag |
| Avoid false positive qualified source due to issuer DN | Fixed | Compliant | Source decision now based on signer cert organization tax ID extraction | Keep regression tests |

---

## Current implementation (code locations)

Main code:
- `src/api/tools/vc-bundle.ts`

Relevant functions:
- `determineEvidenceSource(...)`
- `determineAssuranceLevel(...)`
- `buildOidc4IdaEvidence(...)`
- `buildVerificationVcBundle(...)`

### Evidence source decision implemented

Current rule:
- `source = qualified_certification` only if organization tax ID was extracted from signer certificate DN (`certificateOrganizationTaxId`).
- `source = visible_pdf_fields` when organization identity came from visible PDF fields fallback.

This avoids false positives where the CA issuer is qualified but signer certificate does not contain organization identity attributes.

---

## Mapping to OIDC4IDA evidence structure

### 1) `type: electronic_signature`

Encoded as:
- `type: "electronic_signature"`
- `signature_type: "pades"`
- `issuer`, `serial_number`, `created_at`
- `attachments[]` with `content_type: "application/json"`
- attachment `content` is a `data:application/json;base64,...` URI

The decoded attachment JSON includes ICA profile metadata:

```json
{
  "profile": "oidc4ida-evidence-v1",
  "source": "qualified_certification",
  "assuranceLevel": "high",
  "verificationResult": "valid",
  "signatureValid": true,
  "chainValid": true,
  "revocationStatus": "good",
  "signerSubject": "...",
  "signerIssuer": "...",
  "verificationTrace": {
    "cmsSignatureValidated": true,
    "chainValidated": true
  }
}
```

### 2) `type: document`

Encoded as:
- `type: "document"`
- `method: "eid"` (see compliance note below)
- `verifier.organization`
- `check_details[]` with:
  - `check_method: "vdig"`
  - `check_method: "vcrypt"`
- `attachments.digest.alg/value`
- `document_details` (`type`, `document_number`, `issuer`, etc.)

---

## `check_method` alignment

Used values:
- `vdig` → validation of digital/electronic evidence properties/content
- `vcrypt` → validation of cryptographic security features

These are aligned with predefined check method identifiers listed by OpenID (ekyc-ida identifiers page).

---

## Assurance semantics used in ICA

ICA currently encodes assurance in extension field `assuranceLevel` with values:
- `high`
- `medium`
- `low`

Decision logic:
- If `source = qualified_certification` and signature+chain+template+revocation are good → `high`
- If `source = visible_pdf_fields` with valid cryptographic checks → max `medium`
- Failures degrade to `low`

### Why this distinction matters

Not equivalent evidence strength:
- Organization identity from X.509 signer DN (qualified certificate attributes) is stronger identity proof.
- Organization identity from visible PDF fields (even with verifier/promoter signature over result) is process/audit trust, not the same identity attestation strength.

---

## Compliance notes and gaps

### A) `method` field on document evidence

Current payload includes `method: "eid"` in `type=document` evidence.

Per latest final spec direction, `methods` are deprecated/removed and should not be relied on for long-term interoperability.

Recommendation:
1. Keep `check_details.check_method` as primary normative signal (`vdig`, `vcrypt`).
2. Add a roadmap to deprecate/remove `method` from emitted payload (or gate behind compatibility flag).
3. If needed for backward compatibility, document explicit deprecation date.

### B) Assurance URI normalization

OpenID ecosystem also defines assurance URIs (e.g., `.../low`, `.../substantial`, `.../high`, `.../ial2`, etc.).

Current ICA emits short labels (`low|medium|high`) in extension payload.

Recommendation:
- Keep existing short labels for internal compatibility.
- Optionally add a companion field with URI form, e.g.:
  - `assuranceUri: "https://openid.net/identity_assurnace_level/high"`

---

## Practical examples

### Case 1: Organization from signer certificate DN

- Signer cert contains organization attributes (`O`, `organizationIdentifier`, etc.)
- `source = qualified_certification`
- Potential `assuranceLevel = high` when full cryptographic/trust checks pass

### Case 2: Organization from PDF visible fields fallback

- Signer cert is personal and does not carry organization tax ID
- Organization legal name/tax ID come from PDF form fields
- `source = visible_pdf_fields`
- `assuranceLevel` capped at `medium` (not equal to DN-backed organizational identity)

---

## Operational verification checklist (local-first)

1. Run local verification flow.
2. Decode `electronic_signature.attachments[].content` (base64 JSON data URI).
3. Confirm:
   - `profile = oidc4ida-evidence-v1`
   - `source` matches actual data origin (DN vs PDF fields)
   - `assuranceLevel` matches policy
4. Confirm `document.check_details` contains `vdig` and `vcrypt`.
5. Confirm no false positive `qualified_certification` caused only by qualified CA issuer DN.

---

## Conclusion

The implementation is aligned with OIDC4IDA evidence model for core structure and check methods, while using a controlled ICA extension to express source-sensitive assurance semantics.

Key policy now encoded correctly:
- qualified signer-certificate organization attributes ≠ visible PDF organization fields.
- verifier/promoter signature adds process trust but does not replace DN-level organizational attestation strength.
