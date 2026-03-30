import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parsePollingThreadId } from '../request-parsing.ts';
import {
  buildApiKeyProvisioningResponseLocation,
  buildControllerExchangeResponseLocation,
  buildIdentityAuthResponseLocation,
} from '../path.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import type {
  ApiKeyProvisioningRouteContext,
  ControllerExchangeRouteContext,
  DidcommPlaintextMessage,
  IdentityAuthRouteContext,
} from '../types.ts';

type JsonObject = Record<string, unknown>;

type BackendAuthRouteContext =
  | ControllerExchangeRouteContext
  | ApiKeyProvisioningRouteContext
  | IdentityAuthRouteContext;

export type BackendAuthPollOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'pending'; location: string; retryAfter: number }
  | { type: 'failed'; payload: unknown }
  | { type: 'succeeded'; payload: unknown };

function toSubmitAction(action: string): string {
  return action.endsWith('-response') ? action.slice(0, -9) : action;
}

function sameRoute(a: BackendAuthRouteContext, b: BackendAuthRouteContext): boolean {
  return (
    a.tenantId === b.tenantId
    && a.jurisdiction.toLowerCase() === b.jurisdiction.toLowerCase()
    && a.sector === b.sector
    && a.section === b.section
    && toSubmitAction(a.action) === toSubmitAction(b.action)
  );
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

function buildPayload(
  req: IncomingMessage,
  route: BackendAuthRouteContext,
  thid: string,
  body: JsonObject,
): DidcommPlaintextMessage<JsonObject> {
  return buildDidcommMessage(req, body, {
    route,
    thid,
    type: DIDCOMM_BUNDLE_TYPE,
  });
}

export class BackendAuthResponseManager {
  private readonly jobStore: InMemoryEntityJobStore<BackendAuthRouteContext, JsonObject>;

  constructor(jobStore: InMemoryEntityJobStore<BackendAuthRouteContext, JsonObject>) {
    this.jobStore = jobStore;
  }

  async poll(route: BackendAuthRouteContext, req: IncomingMessage, requestUrl: URL): Promise<BackendAuthPollOutcome> {
    const thid = await parsePollingThreadId(req, requestUrl);
    if (!thid) {
      return {
        type: 'error',
        statusCode: 400,
        message: `Missing thid for ${route.action} polling.`,
      };
    }

    const job = this.jobStore.get(thid);
    if (!job) {
      return {
        type: 'error',
        statusCode: 404,
        message: `Backend auth job not found for thid=${thid}.`,
      };
    }
    if (!sameRoute(job.route, route)) {
      return {
        type: 'error',
        statusCode: 404,
        message: 'Job exists but does not belong to this route.',
      };
    }

    if (job.status === 'queued' || job.status === 'running') {
      return {
        type: 'pending',
        location: buildResponseLocation(route, thid),
        retryAfter: 2,
      };
    }

    if (job.status === 'failed') {
      const body: JsonObject = {
        status: 'failed',
        action: toSubmitAction(route.action),
        error: job.error || 'Unknown backend auth failure.',
      };
      return {
        type: 'failed',
        payload: buildPayload(req, route, thid, body),
      };
    }

    if (!job.result) {
      return {
        type: 'error',
        statusCode: 500,
        message: `Backend auth job ${thid} finished without result payload.`,
      };
    }

    return {
      type: 'succeeded',
      payload: buildPayload(req, route, thid, {
        status: 'ok',
        ...job.result,
      }),
    };
  }
}
