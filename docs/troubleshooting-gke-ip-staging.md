# Troubleshooting for GKE IP-First Staging

This note captures the real problems hit while bringing `st-v2` live behind a GCE `Ingress` with a public IP and TLS, and the fixes that worked.

It is written so the same checklist can be reused in other repos, not only `dataspace-ica-ts`.

## Scope

This document covers:

- split-project deployments
- GCE `Ingress` with public IP
- self-managed TLS for IP-first staging
- CORS failures from frontend development hosts
- end-to-end remote verification with `curl`
- common script-level failures seen during smoke tests

It does not cover domain-based Google-managed certificates. For that mode, use a real host and `ManagedCertificate`.

## Reference topology

The working `st-v2` setup used:

- cluster project: `globaldatacare-test`
- runtime/artifact project: `globaldatacare-ica-dev`
- Kubernetes context: `gke_globaldatacare-test_europe-southwest1-a_gdc-unid-southwest`
- environment: `st-v2`
- ingress IP: `34.36.211.126`
- TLS mode: GCP pre-shared self-managed SSL certificate

Important distinction:

- the **cluster project** owns the GKE cluster, global static IP, forwarding rule, HTTPS proxy, and GCE ingress resources
- the **runtime project** owns Firestore, GCS bucket, Artifact Registry image, and often the runtime GSA

If those projects differ, many errors look random until you separate which resource belongs to which project.

## Working deployment pattern

`st-v2` now works with:

- `Service` type `NodePort`
- GCE `Ingress`
- reserved **global** static IP
- GCP self-managed SSL certificate uploaded in the **cluster project**
- API exposed by HTTPS directly on the IP

Relevant env in `.env.deploy.st-v2`:

```env
K8S_INGRESS_ENABLED=true
K8S_SERVICE_TYPE=NodePort
K8S_INGRESS_HOST=
K8S_INGRESS_STATIC_IP_NAME=ica-st-v2-ip
K8S_PRE_SHARED_CERT_NAME=ica-st-v2-ip-cert
K8S_MANAGED_CERT_NAME=
K8S_TLS_SECRET_NAME=
K8S_DISABLE_HTTP=false
ICA_CORS_ALLOW_ORIGINS=*
```

Why this matters:

- `K8S_INGRESS_HOST=` empty means IP-first staging, not host-based staging
- `K8S_PRE_SHARED_CERT_NAME` is what makes TLS work over the IP
- `ICA_CORS_ALLOW_ORIGINS=*` is what makes browser preflight work from frontend dev origins such as `http://localhost:8081`

## Minimum verification checklist

After deploy, do not assume HTTPS is ready just because TCP `443` opens.

Check these in order:

1. `kubectl -n dataspace-ica get ingress dataspace-ica-api-st-v2 -o wide`
2. `kubectl -n dataspace-ica describe ingress dataspace-ica-api-st-v2`
3. `gcloud compute forwarding-rules describe <https-forwarding-rule> --global --project <cluster-project>`
4. `gcloud compute target-https-proxies describe <https-proxy> --project <cluster-project>`
5. `gcloud compute backend-services get-health <backend-service> --global --project <cluster-project>`
6. `curl -vk https://<ip>/openapi.json`

Only after all of those line up should you trust the HTTPS endpoint.

## Symptoms and fixes

### 1) `curl` connects to `443` but TLS handshake dies

Symptom:

```text
* Connected to 34.36.211.126 port 443
* LibreSSL SSL_connect: SSL_ERROR_SYSCALL
```

Cause:

- the ingress had already allocated the IP
- but the GCE HTTPS frontend had not fully finished provisioning
- or the certificate/proxy attachment had not propagated yet

What confirmed the fix:

- `Ingress` showed `ADDRESS`
- `targetHttpsProxy` existed
- `sslCertificates` included the pre-shared cert
- backend health was `HEALTHY`

Lesson:

- IP allocated is not the same as HTTPS ready
- wait until proxy + forwarding rule + backend health are all present

### 2) GCP resource exists but `gcloud` says it does not exist

Symptom:

```text
ERROR: ... sslCertificates/... was not found
ERROR: ... addresses/... was not found
```

Cause:

- `gcloud` active project was the runtime project
- but the ingress IP and SSL certificate belonged to the cluster project

Fix:

```bash
gcloud config set project globaldatacare-test
```

Lesson:

- for ingress/IP/TLS debugging, first identify the cluster project
- for Firestore/GCS/image/runtime debugging, identify the runtime project

### 3) Browser blocks frontend requests with CORS

Symptom from frontend:

```text
Access to fetch at 'http://34.36.211.126/.../_verify' from origin 'http://localhost:8081'
has been blocked by CORS policy:
No 'Access-Control-Allow-Origin' header is present on the requested resource.
```

Observed root cause:

- backend was running in production mode
- CORS logic in `server.ts` only allows `*` automatically outside production
- `st-v2` had no explicit `ICA_CORS_ALLOW_ORIGINS`

Fix used:

```env
ICA_CORS_ALLOW_ORIGINS=*
```

Verified with:

```bash
curl -sk -X OPTIONS 'https://34.36.211.126/ica/cds-ES/v1/animal-care/terms/pdf/contract/_verify' \
  -H 'Origin: http://localhost:8081' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type' \
  -D -
```

Expected after fix:

```text
HTTP/2 204
access-control-allow-origin: *
access-control-allow-methods: GET, POST, OPTIONS
access-control-allow-headers: content-type
```

Lesson:

- if staging should be callable from web frontends, set CORS explicitly in the deployed env
- do not rely on non-production fallbacks once the pod runs with production-like env

### 4) Firestore rejects documents with `undefined`

Symptom:

```text
Verification collections persistence failed:
Cannot use "undefined" as a Firestore value
(found in field "controllerSameAs")
```

Cause:

- onboarding persistence stored optional fields directly
- Firestore rejects `undefined` unless configured to ignore them

Fix used in repo:

- sanitize documents recursively before write
- enable Firestore client option `ignoreUndefinedProperties: true`

Lesson:

- every Firestore adapter should either strip `undefined` or ban it before persistence
- optional workflow fields like `sameAs` are common sources of this problem

### 5) HTTP/2 returns `location:` but script looks for `Location:`

Symptom:

```text
Missing Location header in ...headers
HTTP/2 202
location: /.../_verify-response?thid=...
```

Cause:

- the smoke script parsed `Location:` with a case-sensitive assumption
- HTTP/2 header casing came back lower-case

Fix:

- parse `location:` case-insensitively

Lesson:

- do not parse headers with case-sensitive assumptions
- especially for shell scripts used against proxies, ingress, or HTTP/2

### 6) Smoke script fails even though `_verify-response` is valid

Observed case:

- `_verify-response` returned valid organization and representative credentials
- but the representative credential did not contain `credentialSubject.sameAs`
- the script assumed it was always present

Fix:

- treat `controller.sameAs` as optional unless runtime flag `ICA_CREATE_DID_REQUIRE_CONTROLLER_SAMEAS_MATCH=true` is actually part of the scenario

Lesson:

- smoke scripts should reflect the real contract, not the strictest optional branch

### 7) `_create` returns `400` because generated payload is empty

Symptom:

```text
DID document create payload requires body.data[] with at least one item.
```

Cause:

- the smoke script built `jq` payloads incorrectly when optional controller fields were missing
- output became `body.data: []`

Fix:

- build optional object fragments with `+ (if ... then {...} else {} end)` rather than trying to emit dynamic keys inside object literals in a brittle way

Lesson:

- inspect the actual generated request file, not only the response body
- for shell-based JSON generation, optional fields are often the first thing that breaks

## Remote end-to-end validation that passed

The full remote lifecycle that passed against `st-v2` was:

```text
cycle1: _verify -> _create -> _remove
cycle2: _verify -> _create -> _remove
```

Current npm entrypoint:

```bash
npm run remote:fullcycle:st-v2
```

That command uses:

- `API_BASE_URL=https://34.36.211.126`
- `CURL_INSECURE=true`

Why `CURL_INSECURE=true` is needed:

- current staging TLS is self-managed/self-signed for the IP
- browser/curl trust is not automatic

Artifacts are stored under:

```text
artifacts/smoke/org-lifecycle/<timestamp>/
```

This is useful for:

- request/response inspection
- reproducing failed payloads
- comparing onboarding cycles

## Generic recommendations for future repos

### Use separate docs for:

- cluster/runtime identity and IAM
- ingress/IP/TLS setup
- staging smoke scripts
- browser CORS expectations

Putting all of that only inside a long README makes failures harder to diagnose.

### For IP-first staging:

- prefer GCE `Ingress` + static global IP
- use `NodePort` behind ingress, not `LoadBalancer` behind ingress
- keep a short checklist for:
  - IP reserved
  - cert uploaded
  - ingress address assigned
  - target HTTPS proxy created
  - backend healthy
  - preflight `OPTIONS` successful

### For split projects:

Document explicitly:

- cluster project
- runtime project
- artifact project
- which commands must target which project

Many “resource not found” errors are just wrong-project errors.

### For frontend integration:

- decide CORS explicitly per env
- keep staging permissive if needed
- do not expect frontend developers to infer why production-like pods have no wildcard CORS

### For smoke scripts:

- save generated requests and responses
- support HTTPS with insecure mode for IP-self-signed staging
- parse headers case-insensitively
- assume optional fields may be absent

## Fast command set

### Inspect ingress

```bash
kubectl -n dataspace-ica get ingress dataspace-ica-api-st-v2 -o wide
kubectl -n dataspace-ica describe ingress dataspace-ica-api-st-v2
```

### Inspect GCE HTTPS frontend

```bash
gcloud config set project globaldatacare-test
gcloud compute forwarding-rules describe <https-forwarding-rule> --global
gcloud compute target-https-proxies describe <https-proxy>
gcloud compute backend-services get-health <backend-service> --global
```

### Test CORS preflight

```bash
curl -sk -X OPTIONS 'https://34.36.211.126/ica/cds-ES/v1/animal-care/terms/pdf/contract/_verify' \
  -H 'Origin: http://localhost:8081' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type' \
  -D -
```

### Test API over HTTPS IP

```bash
curl -vk https://34.36.211.126/openapi.json
curl -vk https://34.36.211.126/.well-known/did.json
```

### Run full remote lifecycle

```bash
npm run remote:fullcycle:st-v2
```
