// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { FnmtPdfVerificationService } from '../src/api/cert-pdf-verifier.ts';
import type { FnmtVerifierConfig } from '../src/api/types.ts';

function createRootPem(): Buffer {
  const workspace = mkdtempSync(path.join(tmpdir(), 'ica-root-retry-'));
  const keyPath = path.join(workspace, 'root.key');
  const certPath = path.join(workspace, 'root.pem');
  try {
    execFileSync('openssl', [
      'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=Test Root CA',
    ], { stdio: 'ignore' });
    return readFileSync(certPath);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

function verifierConfig(rootUrl: string): FnmtVerifierConfig {
  return {
    fnmtRootCertPath: '',
    fnmtIntermediateCertPath: '',
    fnmtIntermediateCertUrls: [],
    fnmtIntermediateCertPinsSha256: [],
    fnmtIntermediateCertPinsSha1: [],
    fnmtAutoDownload: true,
    knownRootCertUrls: [rootUrl],
    knownIntermediateCertUrls: [],
    templateUrlPattern: 'https://example.test/{resourceVersion}.pdf',
    strictRevocation: true,
    strictTemplateMatch: true,
    templateMatchMode: 'strict-bytes',
    verifierVatList: [],
    allowVerificationPartners: false,
    verificationPartnersVatList: [],
    digestAlgorithm: 'sha256',
    templateCacheTtlSeconds: 0,
    templateCacheMaxEntries: 0,
    templatePreloadEnabled: false,
    templatePreloadTenantId: 'ica',
    templatePreloadJurisdictions: ['ES'],
    templatePreloadSectors: ['health-care'],
    templatePreloadResourceTypes: [],
    templateUseTestPrefix: false,
  };
}

test('a transient CA download failure is retried by the next verification request', async () => {
  const rootPem = createRootPem();
  const rootUrl = 'https://ca.example.test/root.pem';
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async (input) => {
    assert.equal(String(input), rootUrl);
    fetchCalls += 1;
    return fetchCalls === 1
      ? new Response('temporarily unavailable', { status: 503 })
      : new Response(rootPem.toString('utf8'), { status: 200 });
  };

  try {
    const service = new FnmtPdfVerificationService(verifierConfig(rootUrl));
    const preloadAttempt = (service as any).trustAnchorsPromise as Promise<unknown>;
    const route = {
      tenantId: 'ica',
      jurisdiction: 'ES',
      sector: 'health-care' as const,
      section: 'test' as const,
      format: 'pdf' as const,
      resourceType: 'contract',
      action: '_verify' as const,
    };
    const submission = {
      thid: 'urn:uuid:00000000-0000-4000-8000-000000000001',
      pdfBytes: Buffer.from('%PDF-1.4\n%%EOF'),
      contentType: 'application/pdf',
    };

    await assert.rejects(preloadAttempt, /certificate download failed/i);
    await assert.rejects(
      () => service.verify(route, submission),
      (error: unknown) => {
        assert.doesNotMatch(String(error), /certificate download failed/i);
        return true;
      },
    );
    assert.equal(fetchCalls, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('the Kubernetes ConfigMap propagates all configured CA URL sets', () => {
  const manifest = readFileSync(path.resolve('deploy/k8s/configmap.yaml'), 'utf8');
  assert.match(manifest, /ICA_KNOWN_ROOT_CERT_URLS:\s*"\$\{ICA_KNOWN_ROOT_CERT_URLS\}"/);
  assert.match(manifest, /ICA_KNOWN_INTERMEDIATE_CERT_URLS:\s*"\$\{ICA_KNOWN_INTERMEDIATE_CERT_URLS\}"/);
  const rendered = execFileSync(
    process.execPath,
    [path.resolve('scripts/render-k8s-manifest.mjs'), path.resolve('deploy/k8s/configmap.yaml')],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        K8S_CONFIGMAP_NAME: 'ica-config',
        ICA_SUPPORTED_JURISDICTIONS: 'ES',
        ICA_SUPPORTED_SECTORS: 'health-care',
        VERIFIERS_VAT_LIST: '',
        ICA_ALLOW_VERIFICATION_PARTNERS: 'false',
        VERIFICATION_PARTNERS_VAT_LIST: '',
        ICA_KNOWN_CERTS_AUTO_DOWNLOAD: 'true',
        ICA_KNOWN_ROOT_CERT_URLS: 'https://ca.example.test/root.pem',
        ICA_KNOWN_INTERMEDIATE_CERT_URLS: 'https://ca.example.test/intermediate.pem',
        DB_PROVIDER: 'firestore',
        STORAGE_PROVIDER: 'gcs',
        FIRESTORE_PROJECT_ID: 'ica-staging-project',
        GCS_BUCKET_NAME: 'ica-staging-audit',
      },
    },
  );
  assert.match(rendered, /ICA_KNOWN_ROOT_CERT_URLS:\s*"https:\/\/ca\.example\.test\/root\.pem"/u);
  assert.match(
    rendered,
    /ICA_KNOWN_INTERMEDIATE_CERT_URLS:\s*"https:\/\/ca\.example\.test\/intermediate\.pem"/u,
  );
});
