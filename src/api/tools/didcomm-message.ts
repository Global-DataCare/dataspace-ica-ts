import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { DidcommPlaintextMessage } from '../types.ts';
import { resolveIcaIssuerDid } from './ica-identity.ts';

type RouteWithTenant = {
  tenantId: string;
};

export const DIDCOMM_BUNDLE_TYPE = 'application/bundle-api+json';

function firstHeaderValue(header: string | string[] | undefined): string {
  if (Array.isArray(header)) {
    return (header.find((value) => value && value.trim()) || '').trim();
  }
  return (header || '').trim();
}

function normalizeAuthority(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      return new URL(trimmed).host.toLowerCase();
    } catch {
      return '';
    }
  }
  return trimmed.split('/')[0].trim().toLowerCase();
}

function configuredLocalTenantId(): string {
  return (process.env.ICA_LOCAL_TENANT_ID || '').trim().toLowerCase();
}

export function resolveDidcommIssuerDid(req: IncomingMessage): string {
  return resolveIcaIssuerDid(req);
}

export function resolveDidcommAudienceDid(
  req: IncomingMessage,
  route: RouteWithTenant | undefined,
  issuerDid: string,
): string {
  const configuredAudienceDid = (process.env.ICA_DIDCOMM_AUDIENCE_DID || '').trim();
  if (configuredAudienceDid) {
    return configuredAudienceDid;
  }

  if (route) {
    const localTenantId = configuredLocalTenantId();
    if (localTenantId && route.tenantId.toLowerCase() === localTenantId) {
      return issuerDid;
    }

    const externalDomain = normalizeAuthority(process.env.ICA_EXTERNAL_DOMAIN || '');
    if (externalDomain && externalDomain !== 'localhost' && !externalDomain.includes(':')) {
      return `did:web:${route.tenantId.toLowerCase()}.${externalDomain}`;
    }
  }

  return issuerDid;
}

export function extractDidcommThreadId(req: IncomingMessage): string | undefined {
  try {
    const host = firstHeaderValue(req.headers.host) || 'localhost';
    const requestUrl = new URL(req.url || '/', `http://${host}`);
    const thid = requestUrl.searchParams.get('thid') || requestUrl.searchParams.get('jti');
    return (thid || '').trim() || undefined;
  } catch {
    return undefined;
  }
}

export function buildDidcommMessage<TBody>(
  req: IncomingMessage,
  body: TBody,
  options: {
    route?: RouteWithTenant;
    thid?: string;
    aud?: string;
    type?: string;
    thidFallback?: 'random' | 'empty';
    audFallback?: 'derived' | 'empty';
  } = {},
): DidcommPlaintextMessage<TBody> {
  const issuerDid = resolveDidcommIssuerDid(req);
  const thidCandidate = (options.thid || extractDidcommThreadId(req) || '').trim();
  const thid =
    thidCandidate ||
    (options.thidFallback === 'empty'
      ? ''
      : randomUUID());
  const aud =
    options.aud !== undefined
      ? options.aud
      : options.audFallback === 'empty'
        ? ''
        : resolveDidcommAudienceDid(req, options.route, issuerDid);
  return {
    jti: `urn:uuid:${randomUUID()}`,
    iss: issuerDid,
    aud,
    thid,
    type: options.type || DIDCOMM_BUNDLE_TYPE,
    body,
  };
}
