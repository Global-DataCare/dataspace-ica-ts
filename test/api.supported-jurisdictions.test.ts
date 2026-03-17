import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { createIcaApiServer } from '../src/api/server.ts';
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import { parseActivateRoute, parseVerifyRoute } from '../src/api/path.ts';

async function withSupportedJurisdictionsEnv<T>(
  value: string | undefined,
  run: () => Promise<T> | T,
): Promise<T> {
  const previousValue = process.env.ICA_SUPPORTED_JURISDICTIONS;
  if (value === undefined) {
    delete process.env.ICA_SUPPORTED_JURISDICTIONS;
  } else {
    process.env.ICA_SUPPORTED_JURISDICTIONS = value;
  }
  try {
    return await run();
  } finally {
    if (previousValue === undefined) {
      delete process.env.ICA_SUPPORTED_JURISDICTIONS;
    } else {
      process.env.ICA_SUPPORTED_JURISDICTIONS = previousValue;
    }
  }
}

function buildMockRequest(url: string, method = 'GET'): IncomingMessage {
  const req = Readable.from([]) as IncomingMessage & Readable;
  req.method = method;
  req.url = url;
  req.headers = {};
  return req;
}

function buildMockResponse() {
  const headers = new Map<string, string | number | readonly string[]>();
  let body = '';
  return {
    res: {
      statusCode: 200,
      setHeader(name: string, value: string | number | readonly string[]) {
        headers.set(name.toLowerCase(), value);
      },
      end(chunk?: string | Buffer) {
        if (chunk) {
          body += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk;
        }
      },
    } as unknown as ServerResponse,
    getBody() {
      return body;
    },
  };
}

test('routes use ICA_SUPPORTED_JURISDICTIONS from env', async () => {
  await withSupportedJurisdictionsEnv('ES,PT', async () => {
    const verifyAccepted = parseVerifyRoute('/acme/cds-PT/v1/animal-care/terms/pdf/contract/_verify');
    assert.ok(verifyAccepted);
    assert.equal(verifyAccepted?.ok, true);
    if (!verifyAccepted || !verifyAccepted.ok) return;
    assert.equal(verifyAccepted.context.jurisdiction, 'PT');

    const activateAccepted = parseActivateRoute('/acme/cds-ES/v1/animal-care/entity/keys/credentials/_activate');
    assert.ok(activateAccepted);
    assert.equal(activateAccepted?.ok, true);

    const rejected = parseVerifyRoute('/acme/cds-FR/v1/animal-care/terms/pdf/contract/_verify');
    assert.ok(rejected);
    assert.equal(rejected?.ok, false);
    if (!rejected || rejected.ok) return;
    assert.match(rejected.message, /ES, PT/i);
  });
});

test('createIcaApiServer exposes supported jurisdictions in ICA configuration', async () => {
  await withSupportedJurisdictionsEnv('ES,PT', async () => {
    const server = createIcaApiServer();
    const handler = server.listeners('request')[0] as ((req: IncomingMessage, res: ServerResponse) => Promise<void> | void);
    const req = buildMockRequest('/.well-known/ica-configuration');
    const { res, getBody } = buildMockResponse();
    await handler(req, res);

    assert.equal(res.statusCode, 200);
    const payload = JSON.parse(getBody()) as {
      jurisdictions?: string[];
    };
    assert.deepEqual(payload.jurisdictions, ['ES', 'PT']);
  });
});

test('buildIcaVerifyOpenApiSpec documents supported jurisdictions', async () => {
  await withSupportedJurisdictionsEnv('ES,PT', async () => {
    const openApi = buildIcaVerifyOpenApiSpec();
    const supportedJurisdictionsExample = openApi.paths['/.well-known/ica-configuration']
      ?.get
      ?.responses?.['200']
      ?.content?.['application/json']
      ?.examples?.icaConfiguration?.value as {
        jurisdictions?: string[];
      } | undefined;
    assert.deepEqual(supportedJurisdictionsExample?.jurisdictions, ['ES', 'PT']);

    const verifyJurisdictionParam = openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify']
      ?.post
      ?.parameters
      ?.find((parameter: any) => parameter?.name === 'jurisdiction') as { schema?: { enum?: string[] } } | undefined;
    assert.deepEqual(verifyJurisdictionParam?.schema?.enum, ['ES', 'PT']);
  });
});
