#!/usr/bin/env node

import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const requirePersistentProviders = args.includes('--require-persistent-providers');
const manifestPath = args.find((argument) => !argument.startsWith('--'));
if (!manifestPath) {
  process.stderr.write(
    'Usage: render-k8s-manifest.mjs [--require-persistent-providers] <manifest-path>\n',
  );
  process.exit(2);
}

const placeholderPattern = /\$\{([A-Z][A-Z0-9_]*)\}/gu;
const source = readFileSync(manifestPath, 'utf8');
const rendered = source.replace(placeholderPattern, (placeholder, variableName) =>
  Object.hasOwn(process.env, variableName) ? String(process.env[variableName] ?? '') : placeholder,
);

const unresolved = new Set();
for (const line of rendered.split(/\r?\n/u)) {
  if (line.trimStart().startsWith('#')) {
    continue;
  }
  for (const match of line.matchAll(placeholderPattern)) {
    unresolved.add(match[1]);
  }
}

if (unresolved.size > 0) {
  process.stderr.write(
    `ERROR: unresolved Kubernetes manifest variables: ${[...unresolved].sort().join(', ')}\n`,
  );
  process.exit(1);
}

if (requirePersistentProviders) {
  const readDataValue = (name) => {
    const match = rendered.match(new RegExp(`^\\s{2}${name}:\\s*["']?([^"'\\n]+)["']?\\s*$`, 'mu'));
    return match?.[1]?.trim().toLowerCase() ?? '';
  };
  const databaseProvider = readDataValue('DB_PROVIDER');
  const storageProvider = readDataValue('STORAGE_PROVIDER');
  if (!['firestore', 'postgres'].includes(databaseProvider)) {
    process.stderr.write(
      `ERROR: Kubernetes deployment requires persistent DB_PROVIDER, received "${databaseProvider || 'unset'}"\n`,
    );
    process.exit(1);
  }
  if (!['gcs', 'ipfs'].includes(storageProvider)) {
    process.stderr.write(
      `ERROR: Kubernetes deployment requires persistent STORAGE_PROVIDER, received "${storageProvider || 'unset'}"\n`,
    );
    process.exit(1);
  }
}

process.stdout.write(rendered);
