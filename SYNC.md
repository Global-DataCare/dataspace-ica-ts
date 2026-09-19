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

Organization verification OTP and professional invitation OTP are also
separate. An invitation records both employee email and employee phone. The
initial route may use email instead of SMS for delivery to the employee email.
In veterinary CA/US this is allowed only after the organization contact was
verified by outbound call to the official marketplace telephone or the verified
technical-controller mobile described above.

In human health CA/US production, physical-site verification is a hard
activation gate. The organization remains inactive until the technical
controller submits the numeric legal-address code bound to the hash of the PDF
generated from the form. Only after that match activates the organization may
Connect ICA issue or deliver the professional invitation OTP. The invitation
OTP does not verify the organization and does not complete DCR. Runtime email,
SMS and voice transports remain pending. See
[`docs/adr-0005-professional-invitation-email-otp-backlog.md`](docs/adr-0005-professional-invitation-email-otp-backlog.md).
