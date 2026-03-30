# Backend Auth Migration Notes

## Scope
This migration adds backend authentication lifecycle endpoints in ICA aligned with DataConv flow:

1. Controller bootstrap exchange (`organization/dataspace/auth/_exchange` + `_exchange-response`)
2. Controller API key lifecycle (`api-key/org.schema/action/_create|_disable|_remove|_search` + `*_response`)
3. Identity DCR binding (`identity/auth/_dcr` + `_dcr-response`)
4. PKCE code (`identity/auth/_code` + `_code-response`)
5. PKCE token (`identity/auth/_token` + `_token-response`)
6. Identity exchange (`identity/auth/_exchange` + `_exchange-response`)

## Contract Behavior
- Async submit/poll pattern is enforced for all endpoints above.
- Submit endpoints return `202` with `Location` including `?thid=...` and `Retry-After`.
- Poll endpoints return:
  - `202` while pending
  - `200` when completed (DIDComm `application/didcomm-plain+json`)
- DCR/PKCE/identity exchange profile is DIDComm plain (`application/didcomm-plain+json`).

## Security and DEMO_MODE
- Bearer token is required for submit and poll on all new backend auth endpoints.
- `DEMO_MODE=true`: Bearer required, signature validation bypassed.
- `DEMO_MODE=false`: Bearer required, HS256 signature + temporal claim validation enforced.

## Binding State
- API key `_create` returns resources in `bindingStatus: pending_dcr`.
- Successful DCR transitions technical identity to `bindingStatus: bound`.
- `_search` exposes binding details per API key.

## Compatibility Notes
- Existing ICA endpoints and flows are unchanged.
- New backend auth endpoints are additive.
- DCR payload must not include `api_key`; `client_id` is the backend API key value.
- When `meta.jws.protected.jwk` is present, duplicating the same key in attachments is rejected.

## Contract Tests Added
- `test/api.backend-auth.test.ts`
  - End-to-end flow: `_create -> _dcr -> _code -> _token -> _exchange`
  - Route parser coverage for controller exchange.
