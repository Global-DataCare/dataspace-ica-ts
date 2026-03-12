import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { buildIcaVerifyOpenApiSpec } from '../openapi.ts';

const outputPath = path.resolve(process.argv[2] || process.env.ICA_OPENAPI_OUTPUT || 'openapi.json');
const serverUrl = (process.env.ICA_OPENAPI_SERVER_URL || '').trim() || undefined;

const openApiSpec = buildIcaVerifyOpenApiSpec({ serverUrl });

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(openApiSpec, null, 2)}\n`, 'utf8');

process.stdout.write(`${outputPath}\n`);
