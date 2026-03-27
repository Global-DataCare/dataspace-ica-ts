#!/usr/bin/env node
/**
 * verify-and-create.mjs
 *
#!/usr/bin/env node
/**
 * verify-and-create.mjs
 *
 * Smoke test: _verify + _create contra ICA v1 (o cualquier instancia),
 * con limpieza opcional de Firestore antes y/o después.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID, generateKeyPairSync } from 'node:crypto';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const parsed = {
    base: 'http://34.175.75.120',
    tenant: 'ica',
    jur: 'ES',
    sector: 'health-care',
    resource: 'contract',
    pdf: '',
    vat: '',
    project: 'globaldatacare-ica-dev',
    prefix: 'dev',
    cleanupBefore: false,
    cleanupAfter: false,
    cleanupAlways: false,
    skipCreate: false,
    out: '',
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--base') { parsed.base = argv[++index] ?? parsed.base; continue; }
    if (arg === '--tenant') { parsed.tenant = argv[++index] ?? parsed.tenant; continue; }
    if (arg === '--jur') { parsed.jur = argv[++index] ?? parsed.jur; continue; }
    if (arg === '--sector') { parsed.sector = argv[++index] ?? parsed.sector; continue; }
    if (arg === '--resource') { parsed.resource = argv[++index] ?? parsed.resource; continue; }
    if (arg === '--pdf') { parsed.pdf = argv[++index] ?? ''; continue; }
    if (arg === '--vat') { parsed.vat = argv[++index] ?? ''; continue; }
    if (arg === '--project') { parsed.project = argv[++index] ?? parsed.project; continue; }
    if (arg === '--prefix') { parsed.prefix = argv[++index] ?? parsed.prefix; continue; }
    if (arg === '--cleanup-before') { parsed.cleanupBefore = true; continue; }
    if (arg === '--cleanup-after') { parsed.cleanupAfter = true; continue; }
    if (arg === '--cleanup-always') { parsed.cleanupAlways = true; continue; }
    if (arg === '--skip-create') { parsed.skipCreate = true; continue; }
    if (arg === '--out') { parsed.out = argv[++index] ?? ''; continue; }
  }

  if (parsed.cleanupAlways) {
    parsed.cleanupBefore = true;
    parsed.cleanupAfter = true;
  }

  return parsed;
}

const args = parseArgs(process.argv.slice(2));

if (!args.pdf) {
  console.error('ERROR: --pdf is required (local path or direct download URL)');
  process.exit(1);
}

const baseUrl = args.base.replace(/\/+$/, '');
const verifyUrl = `${baseUrl}/${args.tenant}/cds-${args.jur}/v1/${args.sector}/terms/pdf/${args.resource}/_verify`;
const createBaseUrl = `${baseUrl}/${args.tenant}/cds-${args.jur}/v1/${args.sector}/entity/did/document`;

async function postDidcomm(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/didcomm-plain+json' },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, headers: Object.fromEntries(response.headers.entries()), text, json };
}

async function poll(url, maxAttempts = 40, delayMs = 1000) {
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    process.stdout.write(`  polling (${attempt}/${maxAttempts})...\r`);
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/didcomm-plain+json' },
      body: '{}',
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (response.status === 202) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      continue;
    }
    process.stdout.write('\n');
    return { status: response.status, json, text };
  }
  process.stdout.write('\n');
  return { status: 599, json: null, text: 'timeout polling' };
}

function resolveLocation(location) {
  if (!location) return '';
  return location.startsWith('http') ? location : `${baseUrl}${location}`;
}

function getDiagnostics(result) {
  const data = result?.json?.body?.data ?? [];
  const diagnostics = [];
  for (const entry of data) {
    const issues = entry?.response?.outcome?.issue ?? [];
    for (const issue of issues) {
      const message = issue?.diagnostics || issue?.details?.text || '';
      if (message) diagnostics.push(`[${issue.severity}] ${message}`);
    }
  }
  const topLevel = result?.json?.body?.issues?.issue?.[0]?.diagnostics;
  if (topLevel && !diagnostics.includes(topLevel)) diagnostics.unshift(topLevel);
  return diagnostics;
}

function extractOrganizationInfo(verifyResponse) {
  const data = verifyResponse?.json?.body?.data ?? [];
  for (const entry of data) {
    if (entry?.type !== 'Organization-verification-v1.0') continue;
    const subject = entry?.resource?.credentialSubject;
    if (!subject) continue;
    const taxId = String(subject.taxID || subject.taxId || '').trim();
    const did = String(subject.id || '').trim();
    if (taxId) return { taxId, did: did || null };
  }
  return null;
}

function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicJwk = publicKey.export({ format: 'jwk' });
  privateJwk.alg = 'ES384';
  publicJwk.alg = 'ES384';
  return { privateJwk, publicJwk };
}

async function loadPdf(pdfArg) {
  if (pdfArg.startsWith('http://') || pdfArg.startsWith('https://')) {
    console.log(`  Downloading PDF from: ${pdfArg}`);
    const response = await fetch(pdfArg);
    if (!response.ok) throw new Error(`HTTP ${response.status} fetching PDF`);
    return Buffer.from(await response.arrayBuffer());
  }
  return fs.readFile(pdfArg);
}

async function runVatCleanup(vat, phase) {
  const normalizedVat = String(vat || '').trim().toUpperCase();
  if (!normalizedVat) {
    return { phase, skipped: true, reason: 'VAT not available' };
  }
  console.log(`\n[cleanup:${phase}] deleting Firestore documents for ${normalizedVat}`);
  const cleanupScript = path.join(scriptDir, 'firestore-vat-manager.mjs');
  const cleanupArgs = [
    cleanupScript,
    '--vat', normalizedVat,
    '--project', args.project,
    '--prefix', args.prefix,
    '--delete',
    '--yes',
  ];
  const { stdout, stderr } = await execFileAsync(process.execPath, cleanupArgs, {
    cwd: path.dirname(scriptDir),
  });
  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);
  return { phase, vat: normalizedVat, deleted: true };
}

async function saveReport(outFile, report) {
  await fs.mkdir(path.dirname(outFile), { recursive: true });
  await fs.writeFile(outFile, JSON.stringify(report, null, 2));
  console.log(`\nReport saved: ${outFile}`);
}

async function main() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const defaultOut = path.join(scriptDir, `../artifacts/smoke/verify-create-${timestamp}.json`);
  const outFile = args.out || defaultOut;
  const report = {
    ts: timestamp,
    base: baseUrl,
    sector: args.sector,
    resource: args.resource,
    verifyUrl,
    pdf: args.pdf,
    cleanup: {
      requested: {
        before: args.cleanupBefore,
        after: args.cleanupAfter,
      },
      before: null,
      after: null,
    },
    verify: null,
    create: null,
  };

  let exitCode = 0;
  let resolvedVat = String(args.vat || '').trim().toUpperCase() || null;

  try {
    if (args.cleanupBefore) {
      report.cleanup.before = await runVatCleanup(resolvedVat, 'before');
    }

    console.log(`\n[1] POST _verify`);
    console.log(`    URL: ${verifyUrl}`);
    const pdfBuffer = await loadPdf(args.pdf);
    console.log(`    PDF loaded: ${pdfBuffer.length} bytes`);

    const verifyThid = `th-${randomUUID()}`;
    const verifyPayload = {
      jti: `req-${randomUUID()}`,
      thid: verifyThid,
      type: 'application/bundle-api+json',
      body: {},
      attachments: [{
        id: 'signed-terms',
        media_type: 'application/pdf',
        data: { base64: pdfBuffer.toString('base64') },
      }],
    };

    const verifySubmit = await postDidcomm(verifyUrl, verifyPayload);
    console.log(`    Submit HTTP: ${verifySubmit.status}`);
    console.log(`    thid: ${verifyThid}`);
    if (verifySubmit.status !== 202) {
      report.verify = { submitStatus: verifySubmit.status, error: verifySubmit.text?.slice(0, 500) };
      throw new Error(`_verify submit failed with HTTP ${verifySubmit.status}`);
    }

    const verifyLocation = resolveLocation(verifySubmit.headers.location);
    console.log(`    Poll URL: ${verifyLocation}`);
    const verifyFinal = await poll(verifyLocation);
    console.log(`    Final HTTP: ${verifyFinal.status}`);
    const verifyDiagnostics = getDiagnostics(verifyFinal);
    verifyDiagnostics.forEach((entry) => console.log(`    ${entry}`));

    const organizationInfo = extractOrganizationInfo(verifyFinal);
    resolvedVat = organizationInfo?.taxId || resolvedVat;
    console.log(`    organizationTaxId: ${organizationInfo?.taxId ?? '(not found)'}`);
    console.log(`    organizationDid:   ${organizationInfo?.did ?? '(not found)'}`);

    report.verify = {
      thid: verifyThid,
      submitStatus: verifySubmit.status,
      pollUrl: verifyLocation,
      finalStatus: verifyFinal.status,
      diagnostics: verifyDiagnostics,
      organizationTaxId: organizationInfo?.taxId ?? null,
      organizationDid: organizationInfo?.did ?? null,
      response: verifyFinal.json,
    };

    if (verifyFinal.status !== 200) {
      throw new Error('_verify did not return HTTP 200');
    }

    if (args.skipCreate) {
      console.log('\n[2] _create skipped (--skip-create)');
      return { outFile, report, exitCode };
    }

    if (!organizationInfo?.taxId || !organizationInfo?.did) {
      throw new Error('Could not extract organization taxID and DID from _verify response');
    }

    console.log(`\n[2] POST _create`);
    const controllerKeys = generateKeyPair();
    const organizationKeys = generateKeyPair();
    console.log(`    controller.publicKeyJwk generated (crv=${controllerKeys.publicJwk.crv})`);
    console.log(`    organization.publicKeyJwk generated (crv=${organizationKeys.publicJwk.crv})`);

    report.controllerPublicKeyJwk = controllerKeys.publicJwk;
    report.controllerPrivateKeyJwk = controllerKeys.privateJwk;
    report.organizationPublicKeyJwk = organizationKeys.publicJwk;
    report.organizationPrivateKeyJwk = organizationKeys.privateJwk;

    const createUrl = `${createBaseUrl}/_create`;
    const createThid = `th-create-${randomUUID()}`;
    const createPayload = {
      jti: `req-${randomUUID()}`,
      thid: createThid,
      type: 'application/bundle-api+json',
      body: {
        data: [{
          organization: {
            identifier: organizationInfo.did,
            taxID: organizationInfo.taxId,
            publicKeyJwk: organizationKeys.publicJwk,
          },
          controller: {
            publicKeyJwk: controllerKeys.publicJwk,
          },
        }],
      },
    };

    console.log(`    URL: ${createUrl}`);
    console.log(`    organization.identifier: ${organizationInfo.did}`);
    console.log(`    organization.taxID:      ${organizationInfo.taxId}`);

    const createSubmit = await postDidcomm(createUrl, createPayload);
    console.log(`    Submit HTTP: ${createSubmit.status}`);
    if (createSubmit.status !== 202) {
      report.create = { submitStatus: createSubmit.status, error: createSubmit.text?.slice(0, 500) };
      throw new Error(`_create submit failed with HTTP ${createSubmit.status}`);
    }

    const createLocation = resolveLocation(createSubmit.headers.location);
    console.log(`    Poll URL: ${createLocation}`);
    const createFinal = await poll(createLocation);
    console.log(`    Final HTTP: ${createFinal.status}`);
    const createDiagnostics = getDiagnostics(createFinal);
    createDiagnostics.forEach((entry) => console.log(`    ${entry}`));

    report.create = {
      thid: createThid,
      url: createUrl,
      organizationTaxID: organizationInfo.taxId,
      organizationDid: organizationInfo.did,
      submitStatus: createSubmit.status,
      pollUrl: createLocation,
      finalStatus: createFinal.status,
      diagnostics: createDiagnostics,
      response: createFinal.json,
    };

    if (createFinal.status !== 200) {
      throw new Error('_create did not return HTTP 200');
    }

    console.log('\nResult: SUCCESS');
    return { outFile, report, exitCode };
  } catch (error) {
    exitCode = 1;
    report.error = error instanceof Error ? error.message : String(error);
    console.error(`\nERROR: ${report.error}`);
    return { outFile, report, exitCode };
  } finally {
    if (args.cleanupAfter) {
      try {
        report.cleanup.after = await runVatCleanup(resolvedVat, 'after');
      } catch (cleanupError) {
        report.cleanup.after = {
          phase: 'after',
          vat: resolvedVat,
          error: cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
        };
        exitCode = 1;
        console.error(`\nCleanup after failed: ${report.cleanup.after.error}`);
      }
    }
    await saveReport(outFile, report);
    process.exit(exitCode);
  }
}

await main();
