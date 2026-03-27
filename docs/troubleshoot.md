**Cómo mirar los logs**

Primero necesitas reautenticar `gcloud` en tu terminal, porque ahora mismo falla al pedir token:

```bash
gcloud auth login
gcloud auth application-default login
```

Después, para cada servicio:

### 1. ProcureData ICA v2

```bash
gcloud config set project procuredata-test
gcloud container clusters get-credentials procuredata-southwest --zone europe-southwest1-a --project procuredata-test

kubectl -n dataspace-ica get pods -l app=dataspace-ica-api-st-v2
kubectl -n dataspace-ica logs -l app=dataspace-ica-api-st-v2 -c api --since=24h --tail=200
```

Cloud Logging:

```bash
gcloud logging read '
resource.type="k8s_container"
resource.labels.project_id="procuredata-test"
resource.labels.location="europe-southwest1-a"
resource.labels.cluster_name="procuredata-southwest"
resource.labels.namespace_name="dataspace-ica"
resource.labels.container_name="api"
labels."k8s-pod/app"="dataspace-ica-api-st-v2"
' --limit=200 --format='table(timestamp,severity,textPayload)'
```

### 2. GDC ICA v2

```bash
gcloud config set project globaldatacare-test
gcloud container clusters get-credentials gdc-unid-southwest --zone europe-southwest1-a --project globaldatacare-test

kubectl -n dataspace-ica get pods -l app=dataspace-ica-api-st-v2
kubectl -n dataspace-ica logs -l app=dataspace-ica-api-st-v2 -c api --since=24h --tail=200
```

Cloud Logging equivalente:

```bash
gcloud logging read '
resource.type="k8s_container"
resource.labels.project_id="globaldatacare-test"
resource.labels.location="europe-southwest1-a"
resource.labels.cluster_name="gdc-unid-southwest"
resource.labels.namespace_name="dataspace-ica"
resource.labels.container_name="api"
labels."k8s-pod/app"="dataspace-ica-api-st-v2"
' --limit=200 --format='table(timestamp,severity,textPayload)'
```

### 3. GDC ICA v1

```bash
gcloud config set project globaldatacare-test
gcloud container clusters get-credentials gdc-unid-southwest --zone europe-southwest1-a --project globaldatacare-test

kubectl -n dataspace-ica get pods -l app=dataspace-ica-api
kubectl -n dataspace-ica logs -l app=dataspace-ica-api -c api --since=24h --tail=200
```

Cloud Logging:

```bash
gcloud logging read '
resource.type="k8s_container"
resource.labels.project_id="globaldatacare-test"
resource.labels.location="europe-southwest1-a"
resource.labels.cluster_name="gdc-unid-southwest"
resource.labels.namespace_name="dataspace-ica"
resource.labels.container_name="api"
labels."k8s-pod/app"="dataspace-ica-api"
' --limit=200 --format='table(timestamp,severity,textPayload)'
```


**Cómo saber cuál ICA están usando en las verificaciones**

Si el fallo te lo reportan “con algunos PDFs”, el dato clave no es sólo la IP, sino qué endpoint `_verify` están golpeando.

Las rutas de verificación de ICA están en v1 bajo:

[dataspace-ica-ts/src/api/server.ts](dataspace-ica-ts/src/api/server.ts#L598)

Eso significa que, en logs, debes buscar especialmente requests a:

```text
/ica/cds-ES/v1/.../terms/pdf/.../_verify
/ica/cds-ES/v1/.../terms/pdf/.../_verify-response
```

Filtros rápidos:

```bash
kubectl -n dataspace-ica logs -l app=dataspace-ica-api-st-v2 -c api --since=24h | grep '_verify'
kubectl -n dataspace-ica logs -l app=dataspace-ica-api -c api --since=24h | grep '_verify'
kubectl -n animal logs -l app=preconversion-api -c api --since=24h | grep -Ei 'pdf|upload|verify|error|exception'
```

**Plan de acción**

1. Reautenticar `gcloud`
2. Consultar primero `globaldatacare-test`, porque es el candidato más fuerte para los fallos de verificación GDC
3. Filtrar logs por `_verify` y por nombre del PDF o por `thid`/request id si lo tienes
4. Si no aparece nada en GDC v2, revisar GDC v1
