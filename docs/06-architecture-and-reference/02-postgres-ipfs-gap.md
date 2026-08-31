# Migración reproducible de Firestore/GCS a PostgreSQL/IPFS

## Resultado implementado

ICA incluye un flujo open source para migrar sus cuatro colecciones de
verificación desde Firestore a PostgreSQL y los contratos PDF de auditoría
desde un export GCS descargado a IPFS/Kubo.

El flujo:

- lee todas las páginas de Firestore;
- carga cada objeto en Kubo con pin y CIDv1;
- calcula SHA-256 de los bytes sin incluirlos en el manifiesto;
- sustituye referencias gobernadas `provider: gcs` por `ipfs://<cid>`;
- copia credenciales, evidencias, DID bindings y DID documents a PostgreSQL;
- vuelve a leer PostgreSQL sin el antiguo límite de 200 registros;
- compara un digest canónico de origen transformado y destino;
- falla si queda una referencia GCS sin resolver;
- produce manifiesto, informe y checksums sin claves ni contenido documental.

El punto de entrada es:

```bash
node src/api/scripts/migrate-firestore-gcs-to-postgres-ipfs.ts --apply
```

## Prueba local open source

```bash
npm ci
npm run test:migration:postgres-ipfs
npm run evidence:migration:postgres-ipfs
```

La prueba ejecuta límites reales, no mocks: Firebase Firestore Emulator,
PostgreSQL y Kubo. Si Firebase no encuentra Java 21 automáticamente, configure:

```bash
export ICA_MIGRATION_JAVA_HOME='<ruta-al-jdk-21>'
npm run evidence:migration:postgres-ipfs
```

La evidencia queda bajo `artifacts/postgres-ipfs-migration-<fecha>/` y contiene:

```text
PASS
SHA256SUMS
audit-ipfs-manifest.json
postgres-migration-report.json
```

Las fixtures son sintéticas. El software, esquema, configuración, pruebas y
manifiestos de ejemplo son open source; los datos reales, PDF firmados,
credenciales, claves, seeds y contraseñas nunca se publican.

## Ejecución sobre un entorno privado

Variables obligatorias:

```dotenv
FIRESTORE_PROJECT_ID=<proyecto-origen>
ICA_MIGRATION_CONFIRM_SOURCE_PROJECT=<mismo-proyecto-origen>
ICA_MIGRATION_SOURCE_COLLECTIONS_PREFIX=<prefijo-origen>
ICA_MIGRATION_TARGET_COLLECTIONS_PREFIX=<prefijo-destino>
ICA_MIGRATION_AUDIT_SOURCE_DIR=/secure/migration/gcs
ICA_MIGRATION_OUTPUT_DIR=/secure/migration/evidence/run-001
POSTGRES_URL=postgresql://<usuario>:<password>@<host>:5432/<database>
IPFS_API_URL=http://<kubo-interno>:5001
ICA_MIGRATION_IPFS_CUSTODY=private-encrypted
ICA_MIGRATION_DATA_PROTECTION_CONFIRMED=true
```

`ICA_MIGRATION_AUDIT_SOURCE_DIR` debe ser el directorio padre de
`ica-audit/`, de modo que las claves relativas coincidan con las referencias
persistidas, por ejemplo `ica-audit/<sector>/.../document.pdf`.

El Kubo de producción debe pertenecer a una red privada y los documentos deben
estar cifrados antes de su incorporación. El CLI rechaza cualquier modo de
custodia distinto de `private-encrypted`. IPFS aporta direccionamiento por
contenido; no convierte datos personales en datos abiertos ni sustituye el
cifrado, el control de acceso o una copia de seguridad.

El export administrado de Firestore almacenado en GCS no es JSON ni SQL. Para
recuperarlo sin acceso a la base viva, impórtelo primero en una base Firestore
temporal privada y ejecute el mismo migrador contra esa base. Para el corte
normal se ejecuta contra Firestore en modo solo lectura durante una ventana de
escritura congelada.

## Gates antes del corte

1. Ejecutar la prueba local desde un checkout limpio.
2. Ejecutar una migración de ensayo sobre una copia privada.
3. Exigir cero referencias GCS sin resolver.
4. Exigir igualdad entre los digests de origen transformado y PostgreSQL.
5. Recuperar por CID una muestra y comparar SHA-256.
6. Arrancar ICA con `DB_PROVIDER=postgres` y `STORAGE_PROVIDER=ipfs`.
7. Probar emisión, consulta, revocación y recuperación de documento.
8. Ensayar rollback antes de cambiar DNS.

Este repositorio prueba el motor de migración y sus límites PostgreSQL/Kubo. Un
despliegue real y la migración de datos privados siguen siendo operaciones
controladas: no se presentan como realizadas hasta conservar su informe y las
evidencias del entorno destino.
