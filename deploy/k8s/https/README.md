# HTTPS on the existing ICA staging IP

This profile keeps `ica.globaldatacare.es` on `34.175.75.120`. The regional
address is reserved in `globaldatacare-test` as `ica-staging-ip`.

The public `ingress-nginx` service owns ports 80 and 443 on that address. The
ICA `dataspace-ica-api` service remains `ClusterIP`, and the namespaced
`letsencrypt-production` issuer renews `ica-globaldatacare-es-tls` through an
HTTP-01 challenge.

The deployment environment must contain:

```env
K8S_SERVICE_TYPE=ClusterIP
ICA_EXTERNAL_DOMAIN=ica.globaldatacare.es
ICA_OPENAPI_SERVER_URL=https://ica.globaldatacare.es
```

Install or reconcile the controllers and ICA resources with:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add jetstack https://charts.jetstack.io
helm repo update

helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.21.0 \
  --set crds.enabled=true \
  --wait

helm upgrade --install ica-ingress ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --create-namespace \
  --version 4.15.1 \
  --values deploy/k8s/https/ingress-nginx-values.yaml \
  --wait

kubectl apply -f deploy/k8s/https/issuer.yaml
kubectl apply -f deploy/k8s/https/ica-ingress.yaml
```

Verify the public contract with:

```bash
curl -sS https://ica.globaldatacare.es/.well-known/did.json | jq '.id'
curl -sS https://ica.globaldatacare.es/openapi.json | jq '.servers'
kubectl -n dataspace-ica get certificate ica-globaldatacare-es-tls
```
