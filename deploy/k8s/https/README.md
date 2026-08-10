# Generic HTTPS profile

These manifests are examples only. Replace `ica.example.org`, the TLS secret,
namespace, service name and load-balancer settings when rendering a deployment.
Keep real domains, reserved addresses, certificate inventory and cluster
topology in private operations documentation.

Apply `issuer.yaml`, render `ica-ingress.yaml` for the target hostname and
configure the ingress controller through `ingress-nginx-values.yaml`.
