import assert from 'node:assert/strict';
import test from 'node:test';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { createIcaApiServer } from '../src/api/server.ts';
import { buildIcaVerifyOpenApiSpec } from '../src/api/openapi.ts';
import { parseVerifyRoute } from '../src/api/path.ts';
import { getConfiguredSupportedSectorIds } from '../src/api/supported-sectors.ts';

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

async function withDataspaceTitleEnv<T>(
  value: string | undefined,
  run: () => Promise<T> | T,
): Promise<T> {
  const previousValue = process.env.DATASPACE_TITLE;
  if (value === undefined) {
    delete process.env.DATASPACE_TITLE;
  } else {
    process.env.DATASPACE_TITLE = value;
  }
  try {
    return await run();
  } finally {
    if (previousValue === undefined) {
      delete process.env.DATASPACE_TITLE;
    } else {
      process.env.DATASPACE_TITLE = previousValue;
    }
  }
}

function buildMockRequest(url: string, method = 'GET', headers: Record<string, string> = {}): IncomingMessage {
  const req = Readable.from([]) as IncomingMessage & Readable;
  req.method = method;
  req.url = url;
  req.headers = headers;
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

test('ICA defaults to the animal and health sector matrix', async () => {
  await withSupportedSectorsEnv(undefined, () => {
    assert.deepEqual(getConfiguredSupportedSectorIds(), [
      'animal-care',
      'animal-tech',
      'animal-research',
      'animal-insurance',
      'health-care',
      'health-tech',
      'health-research',
      'health-insurance',
    ]);
  });
});

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

test('parseVerifyRoute accepts any non-empty sector when ICA_SUPPORTED_SECTORS is wildcard', async () => {
  await withSupportedSectorsEnv('*', async () => {
    const accepted = parseVerifyRoute('/acme/cds-ES/v1/any-custom-sector/terms/pdf/contract/_verify');
    assert.ok(accepted);
    assert.equal(accepted?.ok, true);
    if (!accepted || !accepted.ok) return;
    assert.equal(accepted.context.sector, 'any-custom-sector');
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

test('createIcaApiServer exposes host service discovery catalog well-known document', async () => {
  const server = createIcaApiServer();
  const handler = server.listeners('request')[0] as ((req: IncomingMessage, res: ServerResponse) => Promise<void> | void);
  const req = buildMockRequest('/.well-known/dcat3/catalog', 'GET', { host: 'localhost:3310' });
  const { res, getBody } = buildMockResponse();
  await handler(req, res);

  assert.equal(res.statusCode, 200);
  const payload = JSON.parse(getBody()) as {
    '@type'?: string;
    'dcat:service'?: Array<{ '@id'?: string; '@type'?: string; 'dcat:endpointURL'?: string }>;
  };
  assert.equal(payload['@type'], 'dcat:Catalog');
  assert.equal(Array.isArray(payload['dcat:service']), true);
  assert.equal(
    payload['dcat:service']?.some((service) =>
      service['@id'] === 'did:web:localhost%3A3310#dsp-catalog-service'
      && service['@type'] === 'dcat:DataService'
      && service['dcat:endpointURL'] === 'http://localhost:3310/.well-known/dcat3/catalog'),
    true,
  );
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

test('buildIcaVerifyOpenApiSpec leaves sector as free-form string when ICA_SUPPORTED_SECTORS is wildcard', async () => {
  await withSupportedSectorsEnv('*', async () => {
    await withDataspaceTitleEnv('PROCUREDATA', async () => {
      const openApi = buildIcaVerifyOpenApiSpec();
    const verifySectorParam = openApi.paths['/ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify']
      ?.post
      ?.parameters
      ?.find((parameter: any) => parameter?.name === 'sector') as { schema?: { type?: string; enum?: string[]; example?: string } } | undefined;

    assert.equal(verifySectorParam?.schema?.type, 'string');
    assert.equal(verifySectorParam?.schema?.enum, undefined);
    assert.equal(verifySectorParam?.schema?.example, 'retail');
      assert.equal(openApi.info.title, 'PROCUREDATA ICA Verification API');

    const serializedOpenApi = JSON.stringify(openApi);
    assert.equal(serializedOpenApi.includes('https://globaldatacare.es/didcomm/'), false);
    assert.equal(serializedOpenApi.includes('"type":"application/bundle-api+json"'), true);
    });
  });
});
