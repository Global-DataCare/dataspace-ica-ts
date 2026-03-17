import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { createIcaApiServer } from '../src/api/server.ts';
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import { parseVerifyRoute } from '../src/api/path.ts';

async function withSupportedSectorsEnv<T>(
  value: string | undefined,
  run: () => Promise<T> | T,
): Promise<T> {
  const previousValue = process.env.ICA_SUPPORTED_SECTORS;
  if (value === undefined) {
    delete process.env.ICA_SUPPORTED_SECTORS;
  } else {
    process.env.ICA_SUPPORTED_SECTORS = value;
  }
  try {
    return await run();
  } finally {
    if (previousValue === undefined) {
      delete process.env.ICA_SUPPORTED_SECTORS;
    } else {
      process.env.ICA_SUPPORTED_SECTORS = previousValue;
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
    headers,
    getBody() {
      return body;
    },
  };
}

test('parseVerifyRoute uses ICA_SUPPORTED_SECTORS from env', async () => {
  await withSupportedSectorsEnv('custom-sector', async () => {
    const accepted = parseVerifyRoute('/acme/cds-ES/v1/custom-sector/terms/pdf/contract/_verify');
    assert.ok(accepted);
    assert.equal(accepted?.ok, true);
    if (!accepted || !accepted.ok) return;
    assert.equal(accepted.context.sector, 'custom-sector');

    const rejected = parseVerifyRoute('/acme/cds-ES/v1/animal-care/terms/pdf/contract/_verify');
    assert.ok(rejected);
    assert.equal(rejected?.ok, false);
    if (!rejected || rejected.ok) return;
    assert.match(rejected.message, /custom-sector/i);
  });
});

test('createIcaApiServer exposes ICA configuration well-known document', async () => {
  await withSupportedSectorsEnv('health-care,onehealth-insurance', async () => {
    const server = createIcaApiServer();
    const handler = server.listeners('request')[0] as ((req: IncomingMessage, res: ServerResponse) => Promise<void> | void);
    const req = buildMockRequest('/.well-known/ica-configuration');
    const { res, getBody } = buildMockResponse();
    await handler(req, res);

    assert.equal(res.statusCode, 200);
    const payload = JSON.parse(getBody()) as {
      language?: string;
      sectors?: Array<{ code?: string; display?: string }>;
    };
    assert.equal(payload.language, 'es-ES');
    assert.deepEqual(payload.sectors, [
      { code: 'health-care', display: 'Salud humana' },
      { code: 'onehealth-insurance', display: 'Seguros de salud y entorno (One Health)' },
    ]);
  });
});

test('buildIcaVerifyOpenApiSpec documents ICA configuration discovery', async () => {
  await withSupportedSectorsEnv('health-care,animal-care,onehealth-care', async () => {
    const openApi = buildIcaVerifyOpenApiSpec();
    assert.ok(openApi.paths['/.well-known/ica-configuration']);
    const supportedSectorsExample = openApi.paths['/.well-known/ica-configuration']
      ?.get
      ?.responses?.['200']
      ?.content?.['application/json']
      ?.examples?.icaConfiguration?.value as {
        language?: string;
        sectors?: Array<{ code?: string }>;
      } | undefined;
    assert.equal(supportedSectorsExample?.language, 'es-ES');
    assert.deepEqual(
      supportedSectorsExample?.sectors?.map((sector) => sector.code),
      ['health-care', 'animal-care', 'onehealth-care'],
    );

    const versionDoc = openApi.paths['/.well-known/dspace-version']
      ?.get
      ?.responses?.['200']
      ?.content?.['application/json']
      ?.examples?.versionDoc?.value as { icaConfiguration?: string } | undefined;
    assert.equal(versionDoc?.icaConfiguration, '/.well-known/ica-configuration');

    const verifySectorParam = openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify']
      ?.post
      ?.parameters
      ?.find((parameter: any) => parameter?.name === 'sector') as { schema?: { enum?: string[] } } | undefined;
    assert.deepEqual(verifySectorParam?.schema?.enum, [
      'health-care',
      'animal-care',
      'onehealth-care',
    ]);
  });
});
