import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import {
  buildApiKeyProvisioningResponseLocation,
  buildControllerExchangeResponseLocation,
  buildIdentityAuthResponseLocation,
} from '../path.ts';
import type {
  ApiKeyProvisioningRouteContext,
  ControllerExchangeRouteContext,
  IdentityAuthRouteContext,
} from '../types.ts';
import {
  BackendAuthService,
  parseDidcommPlainPayload,
  readIncomingBufferFromReq,
  resolveDidcommBody,
  resolveDidcommDataEntries,
  resolveStringField,
} from '../tools/backend-auth-service.ts';

type JsonObject = Record<string, unknown>;

export type BackendAuthRouteContext =
  | ControllerExchangeRouteContext
  | ApiKeyProvisioningRouteContext
  | IdentityAuthRouteContext;

export type BackendAuthSubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toStatusCode(errorMessage: string): number {
  if (errorMessage.startsWith('Unsupported Content-Type') || errorMessage.startsWith('Unsupported Content-Encoding')) {
    return 415;
  }
  if (errorMessage.toLowerCase().includes('bearer')) return 401;
  if (
    errorMessage.toLowerCase().includes('invalid session token')
    || errorMessage.toLowerCase().includes('expired')
    || errorMessage.toLowerCase().includes('mismatch')
    || errorMessage.toLowerCase().includes('not bound')
    || errorMessage.toLowerCase().includes('does not match')
  ) {
    return 401;
  }
  return 400;
}

function extractThreadId(parsed: JsonObject, body: JsonObject): string {
  return (
    asNonEmptyString(parsed.thid)
    || asNonEmptyString(body.thid)
    || asNonEmptyString(parsed.id)
    || asNonEmptyString(body.id)
    || asNonEmptyString(parsed.jti)
    || asNonEmptyString(body.jti)
    || `thid-${randomUUID()}`
  );
}

function hasJwkAttachment(parsed: JsonObject): boolean {
  const attachments = Array.isArray(parsed.attachments) ? parsed.attachments : [];
  return attachments.some((entry) => {
    const attachment = asObject(entry);
    if (!attachment) return false;
    const mediaType = asNonEmptyString(attachment.media_type).toLowerCase();
    if (mediaType !== 'application/jwk+json' && mediaType !== 'application/json') return false;
    const data = asObject(attachment.data);
    const json = asObject(data?.json);
    if (!json) return false;
    return Boolean(json.kty || json.crv || json.x || json.n);
  });
}

function parseJsonBody(rawBody: Buffer): JsonObject {
  if (!rawBody.length) return {};
  try {
    const parsed = JSON.parse(rawBody.toString('utf8')) as JsonObject;
    return asObject(parsed) || {};
  } catch (error: unknown) {
    throw new Error(`Invalid JSON body: ${(error as Error).message}`);
  }
}

function buildResponseLocation(route: BackendAuthRouteContext, thid: string): string {
  if (route.section === 'organization') {
    return buildControllerExchangeResponseLocation(route, { thid });
  }
  if (route.section === 'api-key') {
    return buildApiKeyProvisioningResponseLocation(route, { thid });
  }
  return buildIdentityAuthResponseLocation(route, { thid });
}

function normalizeApiKeySelectors(entries: JsonObject[]): Array<{ identifier?: string; emailHash?: string }> {
  return entries
    .map((entry) => {
      const resource = asObject(entry.resource) || entry;
      const identifier = asNonEmptyString(resource.identifier) || undefined;
      const agent = asObject(resource.agent);
      const emailHash = asNonEmptyString(agent?.sameAs) || asNonEmptyString(agent?.email) || undefined;
      return {
        ...(identifier ? { identifier } : {}),
        ...(emailHash ? { emailHash } : {}),
      };
    })
    .filter((selector) => Boolean(selector.identifier || selector.emailHash));
}

function normalizeApiKeyCreateActions(entries: JsonObject[]): Array<{
  email: string;
  scopes: string[];
  target?: string;
  instrument?: JsonObject;
  expiresInSeconds?: number;
}> {
  return entries.map((entry) => {
    const resource = asObject(entry.resource) || entry;
    const agent = asObject(resource.agent) || {};
    const email = asNonEmptyString(agent.email);
    const rawScope = resource.scope;
    const scopes = Array.isArray(rawScope)
      ? rawScope.map((item) => asNonEmptyString(item)).filter(Boolean)
      : [asNonEmptyString(rawScope)].filter(Boolean);
    const target = asNonEmptyString(resource.target) || undefined;
    const instrument = asObject(resource.instrument) || undefined;
    const expiresInSecondsRaw = Number(resource.expires_in_seconds || resource.expiresInSeconds);
    const expiresInSeconds = Number.isFinite(expiresInSecondsRaw) && expiresInSecondsRaw > 0
      ? Math.trunc(expiresInSecondsRaw)
      : undefined;
    return {
      email,
      scopes,
      ...(target ? { target } : {}),
      ...(instrument ? { instrument } : {}),
      ...(expiresInSeconds ? { expiresInSeconds } : {}),
    };
  });
}

export class BackendAuthRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<BackendAuthRouteContext, JsonObject>;
  private readonly authService: BackendAuthService;

  constructor(
    jobStore: InMemoryEntityJobStore<BackendAuthRouteContext, JsonObject>,
    authService: BackendAuthService,
  ) {
    this.jobStore = jobStore;
    this.authService = authService;
  }

  async submit(route: BackendAuthRouteContext, req: IncomingMessage): Promise<BackendAuthSubmitOutcome> {
    try {
      const claims = this.authService.validateBearerAccess(req, route.tenantId);
      const rawBody = await readIncomingBufferFromReq(req);

      let thid = `thid-${randomUUID()}`;
      let resultPayload: JsonObject = {};

      if (route.section === 'organization') {
        const parsed = parseDidcommPlainPayload(req, rawBody, route.action);
        const parsedBody = resolveDidcommBody(parsed);
        thid = extractThreadId(parsed, parsedBody);
        resultPayload = this.authService.exchangeControllerBootstrap({
          tenantId: route.tenantId,
          jurisdiction: route.jurisdiction,
          sector: route.sector,
          subject: claims.sub,
        });
      } else if (route.section === 'api-key') {
        const parsed = parseJsonBody(rawBody);
        const parsedBody = asObject(parsed.body) || parsed;
        thid = extractThreadId(parsed, parsedBody);
        const entries = resolveDidcommDataEntries(parsed, parsedBody);
        if (route.action === '_create') {
          const actions = normalizeApiKeyCreateActions(entries.length ? entries : [parsedBody]);
          const created = this.authService.createApiKeys({
            tenantId: route.tenantId,
            actorSubject: claims.sub,
            actions,
          });
          resultPayload = {
            status: 'ok',
            action: '_create',
            data: created,
          };
        } else if (route.action === '_disable' || route.action === '_remove') {
          const selectors = normalizeApiKeySelectors(entries.length ? entries : [parsedBody]);
          const mutated = this.authService.mutateApiKeys({
            tenantId: route.tenantId,
            action: route.action,
            selectors,
          });
          resultPayload = {
            status: 'ok',
            action: route.action,
            data: mutated,
          };
        } else {
          resultPayload = {
            status: 'ok',
            action: '_search',
            data: this.authService.listApiKeysWithBindings(route.tenantId),
          };
        }
      } else {
        const parsed = parseDidcommPlainPayload(req, rawBody, route.action);
        const parsedBody = resolveDidcommBody(parsed);
        thid = extractThreadId(parsed, parsedBody);

        if (route.action === '_dcr') {
          if (asNonEmptyString(parsed.api_key) || asNonEmptyString(parsedBody.api_key)) {
            throw new Error('DCR does not allow api_key field; use client_id as backend API key identifier.');
          }
          const controllerJwk = BackendAuthService.extractDidcommControllerJwk(parsed.meta);
          if (!controllerJwk) {
            throw new Error('meta.jws.protected.jwk is required for didcomm-plain auth flow.');
          }
          if (hasJwkAttachment(parsed)) {
            throw new Error('Do not duplicate controller key in attachments when meta.jws.protected.jwk is provided.');
          }
          resultPayload = this.authService.bindDcr({
            tenantId: route.tenantId,
            clientId: resolveStringField(parsed, parsedBody, 'client_id'),
            controllerPublicKeyJwk: controllerJwk,
            metadata: parsedBody,
            device: this.authService.buildDeviceMetadata(req),
          });
        } else if (route.action === '_code') {
          resultPayload = this.authService.issuePkceCode({
            tenantId: route.tenantId,
            clientId: resolveStringField(parsed, parsedBody, 'client_id'),
            codeChallenge: resolveStringField(parsed, parsedBody, 'code_challenge'),
            codeChallengeMethod: resolveStringField(parsed, parsedBody, 'code_challenge_method') || 'S256',
          });
        } else if (route.action === '_token') {
          resultPayload = this.authService.issuePkceIdToken({
            tenantId: route.tenantId,
            clientId: resolveStringField(parsed, parsedBody, 'client_id'),
            code: resolveStringField(parsed, parsedBody, 'code'),
            codeVerifier: resolveStringField(parsed, parsedBody, 'code_verifier'),
          });
        } else {
          const subjectToken = resolveStringField(parsed, parsedBody, 'subject_token') || resolveStringField(parsed, parsedBody, 'id_token');
          resultPayload = this.authService.exchangeIdentityToken({
            tenantId: route.tenantId,
            clientId: resolveStringField(parsed, parsedBody, 'client_id'),
            idToken: subjectToken,
          });
        }
      }

      this.jobStore.enqueue(thid, route);
      setImmediate(async () => {
        this.jobStore.markRunning(thid);
        try {
          this.jobStore.markSucceeded(thid, resultPayload);
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          this.jobStore.markFailed(thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildResponseLocation(route, thid),
        retryAfter: 2,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid backend auth request.';
      return {
        type: 'error',
        statusCode: toStatusCode(message),
        message,
      };
    }
  }
}
