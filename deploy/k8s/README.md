# Deploy to Kubernetes (GKE)

## 1) Build image locally

```bash
docker build -t dataspace-ica:local .
```

Run and test:

```bash
docker run --rm -p 3310:3310 --name dataspace-ica-local dataspace-ica:local
curl -sS http://localhost:3310/ | jq .
```

## 2) Push to Artifact Registry

Set your values:

```bash
PROJECT_ID="<gcp-project-id>"
REGION="europe-southwest1"
REPOSITORY_ID="<artifact-repo>"
IMAGE_NAME="dataspace-ica"
IMAGE_TAG="v0.1.0"
IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY_ID}/${IMAGE_NAME}:${IMAGE_TAG}"
```

Authenticate and push:

```bash
gcloud auth configure-docker "${REGION}-docker.pkg.dev"
docker tag dataspace-ica:local "${IMAGE_URI}"
docker push "${IMAGE_URI}"
```

## 3) Deploy to your existing cluster

Select cluster context and namespace:

```bash
kubectl config use-context <your-gke-context>
kubectl create namespace dataspace-ica --dry-run=client -o yaml | kubectl apply -f -
kubectl config set-context --current --namespace=dataspace-ica
```

Create secret from template:

```bash
cp deploy/k8s/secret.example.yaml /tmp/dataspace-ica-secret.yaml
# edit values before apply
kubectl apply -f /tmp/dataspace-ica-secret.yaml
```

Apply base manifests:

```bash
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/deployment.yaml
```

Set image:

```bash
kubectl set image deployment/dataspace-ica-api api="${IMAGE_URI}"
kubectl rollout status deployment/dataspace-ica-api --timeout=180s
```

Validate:

```bash
kubectl get pods -o wide
kubectl get svc dataspace-ica-api
kubectl logs deploy/dataspace-ica-api --tail=100
```

## 4) Optional quick local access from cluster

```bash
kubectl port-forward svc/dataspace-ica-api 3310:80
curl -sS http://localhost:3310/ | jq .
```
