import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import test from 'node:test';
import { Readable } from 'node:stream';
import { InMemoryEntityJobStore } from '../src/api/entity-job-store.ts';
import {
  parseApiKeyProvisioningRoute,
  parseControllerExchangeRoute,
  parseIdentityAuthRoute,
} from '../src/api/path.ts';
import { BackendAuthRequestManager } from '../src/api/managers/backend-auth-request-manager.ts';
import { BackendAuthResponseManager } from '../src/api/managers/backend-auth-response-manager.ts';
import { BackendAuthService } from '../src/api/tools/backend-auth-service.ts';
import type {
  ApiKeyProvisioningRouteContext,
  ControllerExchangeRouteContext,
  IdentityAuthRouteContext,
} from '../src/api/types.ts';

type BackendRoute = ControllerExchangeRouteContext | ApiKeyProvisioningRouteContext | IdentityAuthRouteContext;

test('backend auth flow supports api-key provisioning, DCR, PKCE and identity exchange', async () => {
  const previousSecret = process.env.ICA_EXCHANGE_SESSION_TOKEN_SECRET;
  const previousDemo = process.env.DEMO_MODE;
  process.env.ICA_EXCHANGE_SESSION_TOKEN_SECRET = 'test-secret-backend-auth';
  process.env.DEMO_MODE = 'false';

  const authService = new BackendAuthService();
  const store = new InMemoryEntityJobStore<BackendRoute, Record<string, unknown>>(120);
  const requestManager = new BackendAuthRequestManager(store, authService);
  const responseManager = new BackendAuthResponseManager(store);

  const controllerToken = authService.issueAccessToken({
    subject: 'controller:acme',
    organization: 'acme',
    scopes: ['dataconv.tenant.keys.manage', 'ica.backend.read', 'ica.catalog.read'],
  }).accessToken;

  const authHeader = `Bearer ${controllerToken}`;

  const createParsed = parseApiKeyProvisioningRoute('/acme/cds-ES/v1/animal-care/api-key/org.schema/action/_create');
  assert.ok(createParsed && createParsed.ok);
  if (!createParsed || !createParsed.ok) return;

  const createReqPayload = Buffer.from(JSON.stringify({
    thid: 'thid-create-key-001',
    data: [
      {
        resource: {
          agent: { email: 'backend.operator@example.org' },
          scope: ['ica.backend.read', 'ica.catalog.read'],
          target: 'animal-care/backend',
        },
      },
    ],
  }));

  const createReq = Readable.from([createReqPayload]) as unknown as IncomingMessage;
  (createReq as any).method = 'POST';
  (createReq as any).url = '/acme/cds-ES/v1/animal-care/api-key/org.schema/action/_create';
  (createReq as any).headers = {
    host: 'localhost:3310',
    authorization: authHeader,
    'content-type': 'application/json',
    'content-length': String(createReqPayload.length),
  };

  const createSubmit = await requestManager.submit(createParsed.context, createReq);
  assert.equal(createSubmit.type, 'accepted');
  if (createSubmit.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const createPollParsed = parseApiKeyProvisioningRoute('/acme/cds-ES/v1/animal-care/api-key/org.schema/action/_create-response');
  assert.ok(createPollParsed && createPollParsed.ok);
  if (!createPollParsed || !createPollParsed.ok) return;

  const createPollReq = { method: 'POST', headers: { host: 'localhost:3310', authorization: authHeader } } as unknown as IncomingMessage;
  const createPollUrl = new URL('http://localhost/acme/cds-ES/v1/animal-care/api-key/org.schema/action/_create-response?thid=thid-create-key-001');
  const createPoll = await responseManager.poll(createPollParsed.context, createPollReq, createPollUrl);
  assert.equal(createPoll.type, 'succeeded');
  if (createPoll.type !== 'succeeded') return;

  const createdApiKey = String((createPoll.payload as any)?.body?.data?.[0]?.resource?.apiKey || '');
  assert.ok(createdApiKey.startsWith('ica_k_'));

  const dcrParsed = parseIdentityAuthRoute('/acme/cds-ES/v1/animal-care/identity/auth/_dcr');
  assert.ok(dcrParsed && dcrParsed.ok);
  if (!dcrParsed || !dcrParsed.ok) return;

  const dcrPayload = Buffer.from(JSON.stringify({
    thid: 'thid-dcr-001',
    type: 'application/bundle-api+json',
    body: {},
    client_id: createdApiKey,
    meta: {
      jws: {
        protected: {
          alg: 'ES384',
          jwk: { kty: 'EC', crv: 'P-384', x: 'x', y: 'y' },
        },
      },
    },
  }));

  const dcrReq = Readable.from([dcrPayload]) as unknown as IncomingMessage;
  (dcrReq as any).method = 'POST';
  (dcrReq as any).url = '/acme/cds-ES/v1/animal-care/identity/auth/_dcr';
  (dcrReq as any).headers = {
    host: 'localhost:3310',
    authorization: authHeader,
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(dcrPayload.length),
  };
  const dcrSubmit = await requestManager.submit(dcrParsed.context, dcrReq);
  assert.equal(dcrSubmit.type, 'accepted');
  if (dcrSubmit.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const dcrPollParsed = parseIdentityAuthRoute('/acme/cds-ES/v1/animal-care/identity/auth/_dcr-response');
  assert.ok(dcrPollParsed && dcrPollParsed.ok);
  if (!dcrPollParsed || !dcrPollParsed.ok) return;

  const dcrPollReq = { method: 'POST', headers: { host: 'localhost:3310', authorization: authHeader } } as unknown as IncomingMessage;
  const dcrPollUrl = new URL('http://localhost/acme/cds-ES/v1/animal-care/identity/auth/_dcr-response?thid=thid-dcr-001');
  const dcrPoll = await responseManager.poll(dcrPollParsed.context, dcrPollReq, dcrPollUrl);
  assert.equal(dcrPoll.type, 'succeeded');

  const verifier = 'pkce-verifier-001';
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url');

  const codeParsed = parseIdentityAuthRoute('/acme/cds-ES/v1/animal-care/identity/auth/_code');
  assert.ok(codeParsed && codeParsed.ok);
  if (!codeParsed || !codeParsed.ok) return;

  const codePayload = Buffer.from(JSON.stringify({
    thid: 'thid-code-001',
    type: 'application/bundle-api+json',
    body: {
      client_id: createdApiKey,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    },
    meta: {
      jws: {
        protected: {
          alg: 'ES384',
          jwk: { kty: 'EC', crv: 'P-384', x: 'x', y: 'y' },
        },
      },
    },
  }));

  const codeReq = Readable.from([codePayload]) as unknown as IncomingMessage;
  (codeReq as any).method = 'POST';
  (codeReq as any).url = '/acme/cds-ES/v1/animal-care/identity/auth/_code';
  (codeReq as any).headers = {
    host: 'localhost:3310',
    authorization: authHeader,
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(codePayload.length),
  };
  const codeSubmit = await requestManager.submit(codeParsed.context, codeReq);
  assert.equal(codeSubmit.type, 'accepted');
  if (codeSubmit.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const codePollParsed = parseIdentityAuthRoute('/acme/cds-ES/v1/animal-care/identity/auth/_code-response');
  assert.ok(codePollParsed && codePollParsed.ok);
  if (!codePollParsed || !codePollParsed.ok) return;

  const codePollReq = { method: 'POST', headers: { host: 'localhost:3310', authorization: authHeader } } as unknown as IncomingMessage;
  const codePollUrl = new URL('http://localhost/acme/cds-ES/v1/animal-care/identity/auth/_code-response?thid=thid-code-001');
  const codePoll = await responseManager.poll(codePollParsed.context, codePollReq, codePollUrl);
  assert.equal(codePoll.type, 'succeeded');
  if (codePoll.type !== 'succeeded') return;
  const code = String((codePoll.payload as any)?.body?.code || '');
  assert.ok(code.length > 10);

  const tokenParsed = parseIdentityAuthRoute('/acme/cds-ES/v1/animal-care/identity/auth/_token');
  assert.ok(tokenParsed && tokenParsed.ok);
  if (!tokenParsed || !tokenParsed.ok) return;

  const tokenPayload = Buffer.from(JSON.stringify({
    thid: 'thid-token-001',
    type: 'application/bundle-api+json',
    body: {
      client_id: createdApiKey,
      code,
      code_verifier: verifier,
    },
    meta: {
      jws: {
        protected: {
          alg: 'ES384',
          jwk: { kty: 'EC', crv: 'P-384', x: 'x', y: 'y' },
        },
      },
    },
  }));

  const tokenReq = Readable.from([tokenPayload]) as unknown as IncomingMessage;
  (tokenReq as any).method = 'POST';
  (tokenReq as any).url = '/acme/cds-ES/v1/animal-care/identity/auth/_token';
  (tokenReq as any).headers = {
    host: 'localhost:3310',
    authorization: authHeader,
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(tokenPayload.length),
  };
  const tokenSubmit = await requestManager.submit(tokenParsed.context, tokenReq);
  assert.equal(tokenSubmit.type, 'accepted');
  if (tokenSubmit.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const tokenPollParsed = parseIdentityAuthRoute('/acme/cds-ES/v1/animal-care/identity/auth/_token-response');
  assert.ok(tokenPollParsed && tokenPollParsed.ok);
  if (!tokenPollParsed || !tokenPollParsed.ok) return;

  const tokenPollReq = { method: 'POST', headers: { host: 'localhost:3310', authorization: authHeader } } as unknown as IncomingMessage;
  const tokenPollUrl = new URL('http://localhost/acme/cds-ES/v1/animal-care/identity/auth/_token-response?thid=thid-token-001');
  const tokenPoll = await responseManager.poll(tokenPollParsed.context, tokenPollReq, tokenPollUrl);
  assert.equal(tokenPoll.type, 'succeeded');
  if (tokenPoll.type !== 'succeeded') return;
  const idToken = String((tokenPoll.payload as any)?.body?.id_token || '');
  assert.ok(idToken.split('.').length === 3);

  const exchangeParsed = parseIdentityAuthRoute('/acme/cds-ES/v1/animal-care/identity/auth/_exchange');
  assert.ok(exchangeParsed && exchangeParsed.ok);
  if (!exchangeParsed || !exchangeParsed.ok) return;

  const exchangePayload = Buffer.from(JSON.stringify({
    thid: 'thid-identity-exchange-001',
    type: 'application/bundle-api+json',
    body: {
      client_id: createdApiKey,
      subject_token: idToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    },
  }));

  const exchangeReq = Readable.from([exchangePayload]) as unknown as IncomingMessage;
  (exchangeReq as any).method = 'POST';
  (exchangeReq as any).url = '/acme/cds-ES/v1/animal-care/identity/auth/_exchange';
  (exchangeReq as any).headers = {
    host: 'localhost:3310',
    authorization: authHeader,
    'content-type': 'application/didcomm-plain+json',
    'content-length': String(exchangePayload.length),
  };
  const exchangeSubmit = await requestManager.submit(exchangeParsed.context, exchangeReq);
  assert.equal(exchangeSubmit.type, 'accepted');
  if (exchangeSubmit.type !== 'accepted') return;
  await new Promise((resolve) => setImmediate(resolve));

  const exchangePollParsed = parseIdentityAuthRoute('/acme/cds-ES/v1/animal-care/identity/auth/_exchange-response');
  assert.ok(exchangePollParsed && exchangePollParsed.ok);
  if (!exchangePollParsed || !exchangePollParsed.ok) return;

  const exchangePollReq = { method: 'POST', headers: { host: 'localhost:3310', authorization: authHeader } } as unknown as IncomingMessage;
  const exchangePollUrl = new URL('http://localhost/acme/cds-ES/v1/animal-care/identity/auth/_exchange-response?thid=thid-identity-exchange-001');
  const exchangePoll = await responseManager.poll(exchangePollParsed.context, exchangePollReq, exchangePollUrl);
  assert.equal(exchangePoll.type, 'succeeded');
  if (exchangePoll.type !== 'succeeded') return;

  const backendAccessToken = String((exchangePoll.payload as any)?.body?.access_token || '');
  assert.ok(backendAccessToken.split('.').length === 3);

  if (previousSecret === undefined) delete process.env.ICA_EXCHANGE_SESSION_TOKEN_SECRET;
  else process.env.ICA_EXCHANGE_SESSION_TOKEN_SECRET = previousSecret;
  if (previousDemo === undefined) delete process.env.DEMO_MODE;
  else process.env.DEMO_MODE = previousDemo;
});

test('parseControllerExchangeRoute accepts _exchange path', () => {
  const parsed = parseControllerExchangeRoute('/ica/cds-ES/v1/animal-care/organization/dataspace/auth/_exchange');
  assert.ok(parsed);
  assert.equal(parsed?.ok, true);
  if (!parsed || !parsed.ok) return;
  assert.equal(parsed.context.action, '_exchange');
});
