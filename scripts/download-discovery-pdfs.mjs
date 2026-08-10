#!/usr/bin/env node
/**
 * Descarga PDFs referenciados en VCs exportadas en discovery/.
 * Si el PDF ya existe, no lo vuelve a descargar.
 *
 * Fuente:
 * - analiza ficheros JSON bajo:
 *   discovery/<namespace>/ica/organization/**.json
 *   discovery/<namespace>/ica/organization-representative/**.json
 *   discovery/<namespace>/ica/vN/organization/**.json
 *   discovery/<namespace>/ica/vN/organization-representative/**.json
 * - extrae evidence[type=document].attachments.url
 *
 * Salida:
 * - discovery/<project>/pdfs/VATES-<VAT>/contract-<timestamp>-<hash8>.pdf
 * - logs en discovery/logs/<project>/
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

function parseArgs(argv) {
  const args = {
    discoveryRoot: 'discovery',
    project: 'default',
    namespace: '',
    pdfOut: '',
    overwrite: false,
    timeoutMs: 30000,
    gcsBucket: process.env.GCS_BUCKET_NAME || '',
    gcsAuditPrefix: process.env.ICA_AUDIT_STORAGE_GCS_PREFIX || 'ica-audit',
    gcsIpfsPrefix: process.env.ICA_IPFS_GCS_PREFIX || 'ipfs',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--discovery-root') { args.discoveryRoot = argv[++i] || args.discoveryRoot; continue; }
    if (arg === '--project') { args.project = argv[++i] || args.project; continue; }
    if (arg === '--namespace') { args.namespace = argv[++i] || ''; continue; }
    if (arg === '--pdf-out') { args.pdfOut = argv[++i] || ''; continue; }
    if (arg === '--overwrite') { args.overwrite = true; continue; }
    if (arg === '--gcs-bucket') { args.gcsBucket = argv[++i] || ''; continue; }
    if (arg === '--gcs-audit-prefix') { args.gcsAuditPrefix = argv[++i] || args.gcsAuditPrefix; continue; }
    if (arg === '--gcs-ipfs-prefix') { args.gcsIpfsPrefix = argv[++i] || args.gcsIpfsPrefix; continue; }
    if (arg === '--timeout-ms') {
      const raw = Number(argv[++i]);
      if (!Number.isNaN(raw) && raw > 0) args.timeoutMs = raw;
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }
  return args;
}

function printHelp() {
  console.log([
    'Usage:',
    '  node scripts/download-discovery-pdfs.mjs --project <project> [options]',
    '',
    'Options:',
    '  --discovery-root <path>  Discovery root (default: discovery)',
    '  --project <name>         Project label for output/log subfolders',
    '  --namespace <name>       Discovery namespace (default: inferred from project)',
    '  --pdf-out <path>         Output pdf root (default: <discovery-root>/<project>/pdfs)',
    '  --overwrite              Re-download even if file already exists',
    '  --timeout-ms <n>         HTTP timeout ms (default: 30000)',
    '  --gcs-bucket <name>      GCS bucket to resolve urn:uuid / ipfs links',
    '  --gcs-audit-prefix <p>   GCS prefix for audit PDFs (default: ICA_AUDIT_STORAGE_GCS_PREFIX|ica-audit)',
    '  --gcs-ipfs-prefix <p>    GCS prefix for deterministic ipfs CIDs (default: ICA_IPFS_GCS_PREFIX|ipfs)',
  ].join('\n'));
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : undefined;
}

function asString(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function sanitizeTimestamp(input) {
  const ms = Date.parse(asString(input));
  if (Number.isNaN(ms)) return '00000000000000';
  const d = new Date(ms);
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mi = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${yyyy}${mm}${dd}${hh}${mi}${ss}`;
}

function hash8(input) {
  return createHash('sha256').update(input).digest('hex').slice(0, 8);
}

function walkJsonFiles(rootDir) {
  const results = [];
  function walk(current) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const next = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(next);
        continue;
      }
      if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) {
        results.push(next);
      }
    }
  }
  walk(rootDir);
  return results;
}

function extractPdfLinksFromCredential(credential) {
  const evidence = Array.isArray(credential?.evidence) ? credential.evidence : [];
  const documentEvidence = evidence.find((entry) => asString(entry?.type) === 'document');
  const url = asString(documentEvidence?.attachments?.url);
  const time = asString(documentEvidence?.time);
  return { url, time };
}

function normalizeGcsPrefix(value) {
  const raw = asString(value).replace(/^\/+|\/+$/g, '');
  return raw;
}

function extractUrnUuid(url) {
  const match = asString(url).match(/^urn:uuid:([0-9a-f-]{36})$/i);
  return match ? match[1].toLowerCase() : '';
}

function extractIpfsCid(url) {
  const trimmed = asString(url);
  if (!trimmed) return '';
  if (trimmed.startsWith('ipfs://')) {
    const rest = trimmed.slice('ipfs://'.length).replace(/^\/+/, '');
    return rest.split('/')[0] || '';
  }
  // tolerate direct CID value
  if (/^[zb][a-zA-Z0-9]{20,}$/.test(trimmed)) return trimmed;
  return '';
}

function resolveDiscoveryNamespace(_project, explicitNamespace) {
  const normalizedExplicit = asString(explicitNamespace).toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
  if (normalizedExplicit) return normalizedExplicit;
  return 'dataspace';
}

function listCredentialRoots(vcRoot) {
  const roots = [];
  const directOrganizationRoot = path.join(vcRoot, 'organization');
  const directRepresentativeRoot = path.join(vcRoot, 'organization-representative');
  if (fs.existsSync(directOrganizationRoot)) roots.push(directOrganizationRoot);
  if (fs.existsSync(directRepresentativeRoot)) roots.push(directRepresentativeRoot);

  if (!fs.existsSync(vcRoot)) return roots;
  const entries = fs.readdirSync(vcRoot, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (!/^v\d+$/i.test(entry.name)) continue;
    const versionRoot = path.join(vcRoot, entry.name);
    const organizationRoot = path.join(versionRoot, 'organization');
    const representativeRoot = path.join(versionRoot, 'organization-representative');
    if (fs.existsSync(organizationRoot)) roots.push(organizationRoot);
    if (fs.existsSync(representativeRoot)) roots.push(representativeRoot);
  }

  return [...new Set(roots)];
}

function extractVatFromPath(filePath) {
  const match = filePath.match(/\/(VATES-[A-Z0-9-]+)\//i);
  return match ? match[1].toUpperCase() : 'VATES-UNKNOWN';
}

function parseCredentialFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw);
  const credential = asObject(parsed) || {};
  const { url, time } = extractPdfLinksFromCredential(credential);
  const vat = extractVatFromPath(filePath);
  return { vat, url, time, filePath };
}

function writeTextFile(filePath, lines) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, 'utf8');
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function looksLikePdf(buffer) {
  const head = buffer.subarray(0, Math.min(buffer.length, 1024)).toString('latin1');
  return head.includes('%PDF-');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const discoveryRoot = path.resolve(args.discoveryRoot);
  const discoveryNamespace = resolveDiscoveryNamespace(args.project, args.namespace);
  const vcRoot = path.join(discoveryRoot, discoveryNamespace, 'ica');
  const credentialRoots = listCredentialRoots(vcRoot);
  const pdfOutRoot = path.resolve(args.pdfOut || path.join(discoveryRoot, args.project, 'pdfs'));
  const logRoot = path.join(discoveryRoot, 'logs', args.project);
  const gcsBucket = asString(args.gcsBucket);
  const gcsAuditPrefix = normalizeGcsPrefix(args.gcsAuditPrefix);
  const gcsIpfsPrefix = normalizeGcsPrefix(args.gcsIpfsPrefix);

  ensureDir(pdfOutRoot);
  ensureDir(logRoot);

  const jsonFiles = credentialRoots.flatMap((rootDir) => walkJsonFiles(rootDir));

  const parsedEntries = [];
  for (const filePath of jsonFiles) {
    try {
      const parsed = parseCredentialFile(filePath);
      if (!parsed.url) continue;
      parsedEntries.push(parsed);
    } catch {
      // ignora parse errors; quedan fuera del download
    }
  }

  // Dedup por VAT + URL (si está en org y representative solo baja una vez)
  const dedupMap = new Map();
  for (const entry of parsedEntries) {
    const key = `${entry.vat}::${entry.url}`;
    if (!dedupMap.has(key)) dedupMap.set(key, entry);
  }
  const targets = [...dedupMap.values()];

  let storage = null;
  let bucket = null;
  let auditObjectById = new Map();
  let gcsIndexError = '';
  if (gcsBucket) {
    try {
      const require = createRequire(import.meta.url);
      const { Storage } = require('@google-cloud/storage');
      storage = new Storage();
      bucket = storage.bucket(gcsBucket);
      const prefix = gcsAuditPrefix ? `${gcsAuditPrefix}/` : '';
      const [files] = await bucket.getFiles({ prefix });
      auditObjectById = new Map(
        files
          .map((file) => {
            const base = path.basename(file.name);
            const match = base.match(/^([0-9a-f-]{36})(?:-[0-9a-f]+)?\.pdf$/i);
            if (!match) return null;
            return [match[1].toLowerCase(), file.name];
          })
          .filter(Boolean),
      );
    } catch (error) {
      // si falla GCS, se registrará en failed por target no resoluble
      storage = null;
      bucket = null;
      auditObjectById = new Map();
      gcsIndexError = `gcs_index_build_failed:${error?.message || String(error)}`;
    }
  }

  const runTag = sanitizeTimestamp(new Date().toISOString());
  const downloaded = [];
  const skipped = [];
  const failed = [];
  const unresolved = [];

  async function downloadFromHttp(url) {
    const response = await fetchWithTimeout(url, args.timeoutMs);
    if (!response.ok) return { ok: false, error: `HTTP_${response.status}` };
    const bytes = Buffer.from(await response.arrayBuffer());
    if (!looksLikePdf(bytes)) return { ok: false, error: 'not_pdf' };
    return { ok: true, bytes };
  }

  async function downloadFromGcsObject(objectKey) {
    if (!bucket) return { ok: false, error: 'gcs_not_configured' };
    const file = bucket.file(objectKey);
    const [exists] = await file.exists();
    if (!exists) return { ok: false, error: 'gcs_object_not_found' };
    const [bytes] = await file.download();
    if (!looksLikePdf(bytes)) return { ok: false, error: 'not_pdf' };
    return { ok: true, bytes };
  }

  function resolveIpfsCandidates(cid) {
    const candidates = [];
    const prefix = gcsIpfsPrefix ? `${gcsIpfsPrefix}/` : '';
    candidates.push(`${prefix}${cid}.pdf`);
    candidates.push(`${prefix}${cid}`);
    candidates.push(`${cid}.pdf`);
    candidates.push(`${cid}`);
    return [...new Set(candidates)];
  }

  for (const target of targets) {
    const vatDir = path.join(pdfOutRoot, target.vat);
    ensureDir(vatDir);
    const ts = sanitizeTimestamp(target.time);
    const hash = hash8(target.url);
    const filePath = path.join(vatDir, `contract-${ts}-${hash}.pdf`);

    if (!args.overwrite && fs.existsSync(filePath)) {
      skipped.push(`${target.vat}\t${target.url}\t${filePath}\texists`);
      continue;
    }

    try {
      const link = asString(target.url);
      if (/^https?:\/\//i.test(link)) {
        const httpResult = await downloadFromHttp(link);
        if (!httpResult.ok) {
          failed.push(`${target.vat}\t${target.url}\t${httpResult.error}`);
          continue;
        }
        fs.writeFileSync(filePath, httpResult.bytes);
        downloaded.push(`${target.vat}\t${target.url}\t${filePath}\t${httpResult.bytes.length}\thttp`);
        continue;
      }

      const urnId = extractUrnUuid(link);
      if (urnId) {
        const objectKey = auditObjectById.get(urnId);
        if (!objectKey) {
          unresolved.push(`${target.vat}\t${target.url}\turn_not_found_in_gcs_index`);
          continue;
        }
        const gcsResult = await downloadFromGcsObject(objectKey);
        if (!gcsResult.ok) {
          failed.push(`${target.vat}\t${target.url}\t${gcsResult.error}\t${objectKey}`);
          continue;
        }
        fs.writeFileSync(filePath, gcsResult.bytes);
        downloaded.push(`${target.vat}\t${target.url}\t${filePath}\t${gcsResult.bytes.length}\tgcs:${objectKey}`);
        continue;
      }

      const cid = extractIpfsCid(link);
      if (cid) {
        if (!bucket) {
          unresolved.push(`${target.vat}\t${target.url}\tipfs_without_gcs_bucket`);
          continue;
        }
        let found = false;
        for (const objectKey of resolveIpfsCandidates(cid)) {
          const gcsResult = await downloadFromGcsObject(objectKey);
          if (!gcsResult.ok) continue;
          fs.writeFileSync(filePath, gcsResult.bytes);
          downloaded.push(`${target.vat}\t${target.url}\t${filePath}\t${gcsResult.bytes.length}\tgcs:${objectKey}`);
          found = true;
          break;
        }
        if (!found) {
          unresolved.push(`${target.vat}\t${target.url}\tipfs_not_found_in_gcs`);
        }
        continue;
      }

      unresolved.push(`${target.vat}\t${target.url}\tunsupported_link_scheme`);
    } catch (error) {
      failed.push(`${target.vat}\t${target.url}\t${error?.message || String(error)}`);
    }
  }

  writeTextFile(path.join(logRoot, `download-pdfs-downloaded-${runTag}.txt`), downloaded.length ? downloaded : ['']);
  writeTextFile(path.join(logRoot, `download-pdfs-skipped-${runTag}.txt`), skipped.length ? skipped : ['']);
  writeTextFile(path.join(logRoot, `download-pdfs-failed-${runTag}.txt`), failed.length ? failed : ['']);
  writeTextFile(path.join(logRoot, `download-pdfs-unresolved-${runTag}.txt`), unresolved.length ? unresolved : ['']);
  writeTextFile(path.join(logRoot, `download-pdfs-summary-${runTag}.txt`), [
    `discoveryRoot=${discoveryRoot}`,
    `project=${args.project}`,
    `namespace=${discoveryNamespace}`,
    `credentialRoots=${credentialRoots.length ? credentialRoots.join(',') : '-'}`,
    `pdfOutRoot=${pdfOutRoot}`,
    `jsonFilesScanned=${jsonFiles.length}`,
    `linkTargets=${targets.length}`,
    `gcsBucket=${gcsBucket || '-'}`,
    `gcsAuditPrefix=${gcsAuditPrefix || '-'}`,
    `gcsIpfsPrefix=${gcsIpfsPrefix || '-'}`,
    `gcsIndexEntries=${auditObjectById.size}`,
    `gcsIndexError=${gcsIndexError || '-'}`,
    `downloaded=${downloaded.length}`,
    `skipped=${skipped.length}`,
    `failed=${failed.length}`,
    `unresolved=${unresolved.length}`,
  ]);

  console.log('PDF download completed.');
  console.log(`  Project:           ${args.project}`);
  console.log(`  PDF output root:   ${pdfOutRoot}`);
  console.log(`  Targets:           ${targets.length}`);
  console.log(`  Downloaded:        ${downloaded.length}`);
  console.log(`  Skipped:           ${skipped.length}`);
  console.log(`  Failed:            ${failed.length}`);
  console.log(`  Unresolved:        ${unresolved.length}`);
  console.log(`  Logs:              ${logRoot}`);
}

main().catch((error) => {
  console.error(`ERROR: ${error?.message || String(error)}`);
  process.exit(1);
});
