# 01 GKE and Security

## Production posture

- public ICA API may be exposed
- DID/JWKS/discovery artifacts may be exposed
- internal CA and private enrollment infrastructure should stay private
- prefer Workload Identity over mounted long-lived JSON credentials

## Kubernetes frontdoor options

- public IP with `Service` type `LoadBalancer`
- GCE `Ingress` with TLS

## Naming rule

- keep canonical staging/production resource names under `dataspace-ica-*`
- use coexistence suffixes only for parallel lines such as `st-v2`
- image tag carries the release line; Kubernetes resource naming and release version are different concerns

## Existing deployment references

- Kubernetes assets:
  [`../../deploy/k8s`](../../deploy/k8s)
- GKE/security deep dive:
  [`../security-gke.md`](../security-gke.md)
- IP-first staging troubleshooting:
  [`../troubleshooting-gke-ip-staging.md`](../troubleshooting-gke-ip-staging.md)

## Operational note

The API-facing service and the internal CA bridge should be treated as distinct trust boundaries.
Do not collapse them into a single public surface just because both belong to the ICA domain.
