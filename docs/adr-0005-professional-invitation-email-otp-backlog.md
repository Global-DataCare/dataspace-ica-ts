# ADR-0005 backlog: professional invitation OTP delivery

Status: accepted functional direction; Connect ICA runtime transport and the
remaining security policy are pending.

This decision separates the organization verification OTP from the professional
invitation OTP. They prove different facts and neither one is a licence or DCR
activation code.

## Common invitation contract

1. The organization controller supplies both the employee email and the
   employee phone when inviting a professional. The invitation must preserve
   both values as separate contact inputs; it must not collapse them into one
   generic identifier.
2. For the initial functional route, Connect ICA may deliver the professional
   invitation OTP to the employee email instead of SMS to the employee phone.
   The email destination must be the normalized address recorded in that exact
   invitation.
3. A successful email challenge proves reachability of the invited
   professional at that invitation address. It does not verify the organization
   or confer a professional role. It does not activate a licence. It does not complete DCR.
4. The invitation email and phone must not be copied into an organization or
   controller `sameAs`. Any later association with the professional identity is
   a separate, authenticated sector `_issue`/DCR decision.

## Veterinary CA/US

The professional invitation OTP is eligible only after Connect ICA has verified
the veterinary organization contact using the organization verification OTP:

- by outbound voice call to the official marketplace telephone; or
- by outbound voice call to a nominated technical-controller mobile, after
  which its governed hashed alias is associated with the technical controller
  for that organization as defined by ADR-0004.

That earlier organization evidence permits the functional email delivery of the
professional invitation OTP; it does not turn the employee email or employee
phone into organization evidence.

## Human health CA/US production gate

The organization remains inactive after the controller completes the form and
the form PDF is generated. Connect ICA must keep the numeric legal-address code
bound to the hash of the PDF produced from that form. The technical controller submits
that code. Production activation succeeds only when the code, organization,
controller and PDF hash match the pending verification ceremony.

This completed physical-site verification and resulting organization activation
are mandatory before Connect ICA may issue or deliver a professional invitation
OTP, including delivery by email. Merely generating the PDF, sending the postal
code or having a marketplace entry is not sufficient.

## Runtime and security work

The runtime transport remains pending: the current Connect ICA codebase has no
email, SMS or outbound-call OTP provider or invitation endpoint. The first
implementation must make the rules above executable and prove delivery and
confirmation without allowing portals, gateways or assistants to mint success.

After that functional route works, add expiry, resend and attempt limits,
single-use enforcement, destination-change rules, anti-enumeration behavior,
auditing, recovery and denial tests. Channel preference or SMS fallback must
not weaken either sector-specific organization gate.
