# TODO - dataspace-ica-ts

## NOW
1. Define the ICA-backed suspension/revocation backlog for authoritative credentials consumed by GW/SDK consent and access flows:
   - explicit suspension credential/status semantics
   - clear distinction between suspension vs revocation vs local GW disable
   - payload/route contract that GW can consume as authoritative lifecycle input
   - do not absorb normal employee/professional lifecycle owned by GW
2. Define the payment/licensing evidence verification contract consumed by GW for paid `offer` / `order` activation:
   - accepted evidence shape from frontend/backend handoff
   - verification result DTO
   - failure reasons stable enough for portal/BFF display
3. Extend ICA discovery/autodiscovery inputs needed by SDK/GW layers:
   - hosting-operator identification
   - index-provider and digital-twin-provider discovery semantics
   - compatibility with cross-operator/cross-ICA aggregation
4. Define credential/evidence semantics needed by consent lifecycle anchoring:
   - what ICA emits for consent-adjacent suspension or status changes
   - what metadata GW/common-utils need to hash and later anchor deterministically
5. Keep repo boundaries explicit:
   - ICA owns authoritative credential lifecycle semantics for organizational/network credentials
   - GW owns local operational disable state and the normal employee/professional lifecycle
   - SDK/common-utils must not invent ICA status contracts ad hoc

## NEXT
1. Add repository-local roadmap/doc references for suspension credentials, payment-proof verification, and discovery semantics.
2. Add examples/tests for authoritative lifecycle status payloads consumed by GW.
3. Add examples/tests for discovery records that can feed SDK/GW resolver layers without private tenant-host shortcuts.

## LATER
1. Expand the same lifecycle contract family to additional credential classes as onboarding and provider catalogs converge.
