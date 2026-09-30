#!/usr/bin/env node

import { readFileSync } from 'node:fs';

const manifestPath = process.argv[2];
if (!manifestPath) {
  process.stderr.write('Usage: render-k8s-manifest.mjs <manifest-path>\n');
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

process.stdout.write(rendered);
