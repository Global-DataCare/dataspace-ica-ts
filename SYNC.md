# Connect ICA product synchronization

CA/US veterinary onboarding uses a numeric OTP delivered by Connect ICA through
an outbound voice call to the official marketplace telephone. The form may also
nominate an E.164 private mobile for the technical controller. After Connect ICA
verifies that destination, only its governed hashed alias is appended to the
controller `sameAs`, preserving a pre-existing hashed email in the current
comma-separated representation.

This is a functional-first backlog. Whether an existing mobile alias must match
a newly nominated mobile remains an open decision for Phase 2 security
hardening, together with replacement/recovery authority, throttling, replay and
abuse controls. See
[`docs/adr-0004-veterinary-controller-phone-otp-backlog.md`](docs/adr-0004-veterinary-controller-phone-otp-backlog.md).

The official clinic telephone, technical-controller mobile, login contact,
legal-representative evidence and later licence/DCR code are separate axes.
Portal, GW and telephone assistants consume the result; they never mint the OTP
or claim that an unverified telephone has been associated.
