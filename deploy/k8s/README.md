# ICA Kubernetes templates

This directory contains environment-neutral Kubernetes templates for ICA.
Deployment-specific projects, clusters, namespaces, public addresses, service
accounts, buckets, certificate names and release-line coexistence procedures do
not belong in this repository.

Provide those values through the deployment environment or a private operations
inventory. At minimum, resolve:

- image registry, repository and immutable tag;
- Kubernetes context and namespace;
- workload identity and cloud project bindings;
- database and audit-storage providers;
- public hostname or reserved address;
- TLS issuer/certificate references;
- ICA signing and Root trust configuration.

Before applying these templates, render them for the target environment and
review the resulting diff. Verify rollout status and public health/discovery
endpoints after deployment. Never commit credential files, private keys,
tokens, real project identifiers or tenant-specific evidence here.
