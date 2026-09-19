# ADR-0004 backlog: veterinary technical-controller phone OTP

Status: accepted functional direction; Connect ICA implementation and security
policy remain pending.

This backlog applies to CA/US veterinary legal-organization onboarding. It does
not change human-health postal verification and it is not a licence,
`Token/_exchange` or DCR activation code.

## Phase 1 - functional MVP

1. Connect ICA resolves the clinic from the authoritative marketplace record.
2. The default challenge is a numeric OTP delivered by outbound voice call to
   the official marketplace telephone. Inbound caller ID is never proof.
3. The application form may nominate a private mobile belonging to the
   technical controller as the OTP destination. Connect ICA, not the portal or
   GW, performs the outbound voice call and confirms the submitted OTP.
4. After successful verification, Connect ICA normalizes that mobile to E.164,
   derives the governed non-reversible hashed alias and associates it with the
   technical controller in `sameAs`. The raw mobile must not enter the VC,
   DID document, public response, logs or ledger.
5. `sameAs` may already carry a hashed email. The current flat representation
   is a comma-separated list, so the implementation must preserve existing
   aliases, de-duplicate normalized values and append the verified telephone
   hash without replacing the email alias.
6. The official marketplace telephone proves control of the clinic contact;
   the nominated mobile proves reachability of the technical controller. They
   remain distinct evidence and may be different numbers.

The immediate objective is to make this route work through Connect ICA. No
portal, assistant or gateway may fabricate a successful callback or write a
telephone alias before Connect ICA confirms the outbound call OTP.

## Phase 2 - security hardening

Review and test the authorization rules after the functional route is proven:

- If `sameAs` already contains a mobile-derived alias, decide whether the newly
  nominated E.164 mobile must match it exactly. This existing mobile match is
  an open decision and must be resolved in a separate security thread.
- Define an explicit re-verification and replacement ceremony for a changed or
  lost controller mobile; never silently overwrite an established alias.
- Decide who may nominate the private mobile: legal representative, already
  bound technical controller, marketplace administrator, or a combination.
- Add attempt limits, resend delay, expiry, replay protection, destination-change
  cooldown, abuse monitoring and auditable evidence retention.
- Define whether the official marketplace telephone must always be challenged
  before the private technical-controller mobile becomes eligible.
- Specify hash normalization/versioning, collision-safe alias prefixes and
  migration of legacy comma-separated `sameAs` values.
- Add denial tests for unverified mobiles, mismatched existing aliases, changed
  marketplace records, cross-organization reuse and unauthorized recovery.

Until Phase 2 is approved, this document records direction and implementation
order; it does not authorize broad production enrollment or weaken existing
Connect ICA verification checks.
