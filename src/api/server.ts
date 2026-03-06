import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { pathToFileURL } from 'node:url';
import { InMemoryVerificationJobStore } from './job-store.ts';
import { InMemoryActivationJobStore } from './activation-job-store.ts';
import { InMemoryEntityJobStore } from './entity-job-store.ts';
import {
  buildRotateResponseLocation,
  parseActivateRoute,
  parseAddEvidenceRoute,
  parseCredentialRevokeRoute,
  parseCredentialStatusRoute,
  parseIssueCredentialRoute,
  parseRotateRoute,
  parseVerifyRoute,
} from './path.ts';
import { ActivateRequestManager } from './managers/activate-request-manager.ts';
import { ActivateResponseManager } from './managers/activate-response-manager.ts';
import { AddEvidenceRequestManager } from './managers/add-evidence-request-manager.ts';
import { AddEvidenceResponseManager } from './managers/add-evidence-response-manager.ts';
import { CredentialRevokeRequestManager } from './managers/credential-revoke-request-manager.ts';
import { CredentialRevokeResponseManager } from './managers/credential-revoke-response-manager.ts';
import { CredentialStatusRequestManager } from './managers/credential-status-request-manager.ts';
import { CredentialStatusResponseManager } from './managers/credential-status-response-manager.ts';
import { IssueCredentialRequestManager } from './managers/issue-credential-request-manager.ts';
import { IssueCredentialResponseManager } from './managers/issue-credential-response-manager.ts';
import { VerifyRequestManager } from './managers/verify-request-manager.ts';
import { VerifyResponseManager } from './managers/verify-response-manager.ts';
import { buildIcaVerifyOpenApiSpec } from './openapi.ts';
import { createDefaultSignatureVerificationManagerFromEnv } from './signature-verification-manager.ts';
import { createAuditDocumentStorageServiceFromEnv } from './tools/audit-document-storage.ts';
import { createVerificationCollectionsServiceFromEnv } from './tools/verification-collections-storage.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from './tools/didcomm-message.ts';
import { buildIcaDidDocument } from './tools/ica-identity.ts';
import type {
  OperationOutcomeIssue,
  OperationOutcomeResource,
  PdfVerificationService,
  VerifyBundleResponse,
  ActivateRouteContext,
  AddEvidenceResult,
  AddEvidenceRouteContext,
  CredentialRevokeResult,
  CredentialRevokeRouteContext,
  CredentialStatusResult,
  CredentialStatusRouteContext,
  IssueCredentialResult,
  IssueCredentialRouteContext,
  RotateRouteContext,
  VerifyRouteContext,
} from './types.ts';
export { buildVerificationVcBundle } from './tools/vc-bundle.ts';

export type IcaApiServerOptions = {
  host?: string;
  port?: number;
  jobResultTtlSeconds?: number;
  verifier?: PdfVerificationService;
};

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  const body = JSON.stringify(payload, null, 2);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(body));
  res.end(body);
}

function sendHtml(res: ServerResponse, statusCode: number, html: string): void {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Length', Buffer.byteLength(html));
  res.end(html);
}

function sendDidcommJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  const body = JSON.stringify(payload, null, 2);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/didcomm-plain+json');
  res.setHeader('Content-Length', Buffer.byteLength(body));
  res.end(body);
}

function sendDidDocumentJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  const body = JSON.stringify(payload, null, 2);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/did+ld+json');
  res.setHeader('Content-Length', Buffer.byteLength(body));
  res.end(body);
}

function mapStatusIssue(statusCode: number): Pick<OperationOutcomeIssue, 'severity' | 'code'> {
  if (statusCode >= 500) return { severity: 'error', code: 'exception' };
  if (statusCode === 404) return { severity: 'error', code: 'not-found' };
  if (statusCode === 405) return { severity: 'error', code: 'not-supported' };
  if (statusCode === 401) return { severity: 'error', code: 'forbidden' };
  if (statusCode === 415) return { severity: 'error', code: 'not-supported' };
  return { severity: 'error', code: 'invalid' };
}

function buildOperationOutcome(issue: OperationOutcomeIssue[]): OperationOutcomeResource {
  return {
    resourceType: 'OperationOutcome',
    issue,
  };
}

function buildErrorBundle(statusCode: number, message: string): VerifyBundleResponse {
  const mapped = mapStatusIssue(statusCode);
  return {
    resourceType: 'Bundle',
    type: 'batch-response',
    total: 0,
    data: [],
    issues: buildOperationOutcome([
      {
        severity: mapped.severity,
        code: mapped.code,
        diagnostics: message,
      },
    ]),
  };
}

function sendError(
  req: IncomingMessage,
  res: ServerResponse,
  statusCode: number,
  message: string,
  route?:
    | VerifyRouteContext
    | ActivateRouteContext
    | RotateRouteContext
    | AddEvidenceRouteContext
    | IssueCredentialRouteContext
    | CredentialStatusRouteContext
    | CredentialRevokeRouteContext,
): void {
  const payload = buildDidcommMessage(req, buildErrorBundle(statusCode, message), {
    route,
    type: DIDCOMM_BUNDLE_TYPE,
    thidFallback: 'empty',
    audFallback: 'empty',
  });
  sendDidcommJson(res, statusCode, payload);
}

function sendMethodNotAllowed(res: ServerResponse, allow: string): void {
  res.statusCode = 405;
  res.setHeader('Allow', allow);
  res.end();
}

function buildApiDocsHtml(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DataSpace ICA Verification API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>
      body { margin: 0; background: #f7f8fa; }
      #swagger-ui { max-width: 1200px; margin: 0 auto; }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        docExpansion: 'list',
        presets: [SwaggerUIBundle.presets.apis]
      });
    </script>
  </body>
</html>`;
}

export function createIcaApiServer(options: IcaApiServerOptions = {}) {
  const verifier = options.verifier || createDefaultSignatureVerificationManagerFromEnv();
  const jobStore = new InMemoryVerificationJobStore(options.jobResultTtlSeconds || 3600);
  const activationJobStore = new InMemoryActivationJobStore(options.jobResultTtlSeconds || 3600);
  const addEvidenceJobStore = new InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>(
    options.jobResultTtlSeconds || 3600,
  );
  const issueCredentialJobStore = new InMemoryEntityJobStore<IssueCredentialRouteContext, IssueCredentialResult>(
    options.jobResultTtlSeconds || 3600,
  );
  const credentialStatusJobStore = new InMemoryEntityJobStore<CredentialStatusRouteContext, CredentialStatusResult>(
    options.jobResultTtlSeconds || 3600,
  );
  const credentialRevokeJobStore = new InMemoryEntityJobStore<CredentialRevokeRouteContext, CredentialRevokeResult>(
    options.jobResultTtlSeconds || 3600,
  );
  const auditStorageService = createAuditDocumentStorageServiceFromEnv();
  const verificationCollectionsService = createVerificationCollectionsServiceFromEnv();
  const verifyRequestManager = new VerifyRequestManager(jobStore, verifier, auditStorageService);
  const verifyResponseManager = new VerifyResponseManager(jobStore, verificationCollectionsService);
  const activateRequestManager = new ActivateRequestManager(activationJobStore);
  const activateResponseManager = new ActivateResponseManager(activationJobStore);
  const addEvidenceRequestManager = new AddEvidenceRequestManager(addEvidenceJobStore, verificationCollectionsService);
  const addEvidenceResponseManager = new AddEvidenceResponseManager(addEvidenceJobStore);
  const issueCredentialRequestManager = new IssueCredentialRequestManager(
    issueCredentialJobStore,
    verificationCollectionsService,
  );
  const issueCredentialResponseManager = new IssueCredentialResponseManager(issueCredentialJobStore);
  const credentialStatusRequestManager = new CredentialStatusRequestManager(
    credentialStatusJobStore,
    verificationCollectionsService,
  );
  const credentialStatusResponseManager = new CredentialStatusResponseManager(credentialStatusJobStore);
  const credentialRevokeRequestManager = new CredentialRevokeRequestManager(
    credentialRevokeJobStore,
    verificationCollectionsService,
  );
  const credentialRevokeResponseManager = new CredentialRevokeResponseManager(credentialRevokeJobStore);
  const openApiSpec = buildIcaVerifyOpenApiSpec();
  const apiDocsHtml = buildApiDocsHtml();

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const requestUrl = new URL(req.url || '/', 'http://localhost');
      const method = req.method?.toUpperCase() || 'GET';
      const pathname = requestUrl.pathname;

      if (pathname === '/') {
        if (method !== 'GET') {
          sendMethodNotAllowed(res, 'GET');
          return;
        }
        sendJson(res, 200, {
          name: 'dataspace-ica verification api',
          status: 'ok',
          docs: '/api-docs',
          openapi: '/openapi.json',
          did: '/.well-known/did.json',
          endpoints: {
            verify: 'POST /ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify',
            verifyResponse:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/terms/pdf/{resourceType}/_verify-response',
            activate:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate',
            activateResponse:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_activate-response',
            addEvidence:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add',
            addEvidenceResponse:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/network/evidence/{evidenceType}/_add-response',
            issueCredential:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue',
            issueCredentialResponse:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_issue-response',
            credentialStatus:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status',
            credentialStatusResponse:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_status-response',
            credentialRevoke:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke',
            credentialRevokeResponse:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/network/credentials/{credentialType}/_revoke-response',
            rotateCredentials:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate',
            rotateCredentialsResponse:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/credentials/_rotate-response',
            rotateCommunications:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate',
            rotateCommunicationsResponse:
              'POST /ica/cds-{jurisdiction}/v1/{sector}/entity/keys/communications/_rotate-response',
          },
        });
        return;
      }

      if (pathname === '/openapi.json') {
        if (method !== 'GET') {
          sendMethodNotAllowed(res, 'GET');
          return;
        }
        sendJson(res, 200, openApiSpec);
        return;
      }

      if (pathname === '/.well-known/did.json' || pathname === '/did.json') {
        if (method !== 'GET') {
          sendMethodNotAllowed(res, 'GET');
          return;
        }
        sendDidDocumentJson(res, 200, buildIcaDidDocument(req));
        return;
      }

      if (pathname === '/api-docs' || pathname === '/api-docs/') {
        if (method !== 'GET') {
          sendMethodNotAllowed(res, 'GET');
          return;
        }
        sendHtml(res, 200, apiDocsHtml);
        return;
      }

      const parsedVerifyRoute = parseVerifyRoute(requestUrl.pathname);
      if (parsedVerifyRoute) {
        if (!parsedVerifyRoute.ok) {
          sendError(req, res, parsedVerifyRoute.statusCode, parsedVerifyRoute.message);
          return;
        }
        if (method !== 'POST') {
          res.setHeader('Allow', 'POST');
          sendError(req, res, 405, 'Method not allowed. Use POST.', parsedVerifyRoute.context);
          return;
        }

        const route = parsedVerifyRoute.context;
        if (route.action === '_verify') {
          const outcome = await verifyRequestManager.submit(route, req);
          if (outcome.type === 'error') {
            sendError(req, res, outcome.statusCode, outcome.message, route);
            return;
          }
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }

        const outcome = await verifyResponseManager.poll(route, req, requestUrl);
        if (outcome.type === 'error') {
          sendError(req, res, outcome.statusCode, outcome.message, route);
          return;
        }
        if (outcome.type === 'pending') {
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }
        sendDidcommJson(res, 200, outcome.payload);
        return;
      }

      const parsedActivate = parseActivateRoute(requestUrl.pathname);
      if (parsedActivate) {
        if (!parsedActivate.ok) {
          sendError(req, res, parsedActivate.statusCode, parsedActivate.message);
          return;
        }
        if (method !== 'POST') {
          res.setHeader('Allow', 'POST');
          sendError(req, res, 405, 'Method not allowed. Use POST.', parsedActivate.context);
          return;
        }

        const route = parsedActivate.context;
        if (route.action === '_activate') {
          const outcome = await activateRequestManager.submit(route, req);
          if (outcome.type === 'error') {
            sendError(req, res, outcome.statusCode, outcome.message, route);
            return;
          }
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }

        const outcome = await activateResponseManager.poll(route, req, requestUrl);
        if (outcome.type === 'error') {
          sendError(req, res, outcome.statusCode, outcome.message, route);
          return;
        }
        if (outcome.type === 'pending') {
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }
        sendDidcommJson(res, 200, outcome.payload);
        return;
      }

      const parsedAddEvidence = parseAddEvidenceRoute(requestUrl.pathname);
      if (parsedAddEvidence) {
        if (!parsedAddEvidence.ok) {
          sendError(req, res, parsedAddEvidence.statusCode, parsedAddEvidence.message);
          return;
        }
        if (method !== 'POST') {
          res.setHeader('Allow', 'POST');
          sendError(req, res, 405, 'Method not allowed. Use POST.', parsedAddEvidence.context);
          return;
        }

        const route = parsedAddEvidence.context;
        if (route.action === '_add') {
          const outcome = await addEvidenceRequestManager.submit(route, req);
          if (outcome.type === 'error') {
            sendError(req, res, outcome.statusCode, outcome.message, route);
            return;
          }
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }

        const outcome = await addEvidenceResponseManager.poll(route, req, requestUrl);
        if (outcome.type === 'error') {
          sendError(req, res, outcome.statusCode, outcome.message, route);
          return;
        }
        if (outcome.type === 'pending') {
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }
        sendDidcommJson(res, 200, outcome.payload);
        return;
      }

      const parsedIssueCredential = parseIssueCredentialRoute(requestUrl.pathname);
      if (parsedIssueCredential) {
        if (!parsedIssueCredential.ok) {
          sendError(req, res, parsedIssueCredential.statusCode, parsedIssueCredential.message);
          return;
        }
        if (method !== 'POST') {
          res.setHeader('Allow', 'POST');
          sendError(req, res, 405, 'Method not allowed. Use POST.', parsedIssueCredential.context);
          return;
        }

        const route = parsedIssueCredential.context;
        if (route.action === '_issue') {
          const outcome = await issueCredentialRequestManager.submit(route, req);
          if (outcome.type === 'error') {
            sendError(req, res, outcome.statusCode, outcome.message, route);
            return;
          }
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }

        const outcome = await issueCredentialResponseManager.poll(route, req, requestUrl);
        if (outcome.type === 'error') {
          sendError(req, res, outcome.statusCode, outcome.message, route);
          return;
        }
        if (outcome.type === 'pending') {
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }
        sendDidcommJson(res, 200, outcome.payload);
        return;
      }

      const parsedCredentialStatus = parseCredentialStatusRoute(requestUrl.pathname);
      if (parsedCredentialStatus) {
        if (!parsedCredentialStatus.ok) {
          sendError(req, res, parsedCredentialStatus.statusCode, parsedCredentialStatus.message);
          return;
        }
        if (method !== 'POST') {
          res.setHeader('Allow', 'POST');
          sendError(req, res, 405, 'Method not allowed. Use POST.', parsedCredentialStatus.context);
          return;
        }

        const route = parsedCredentialStatus.context;
        if (route.action === '_status') {
          const outcome = await credentialStatusRequestManager.submit(route, req);
          if (outcome.type === 'error') {
            sendError(req, res, outcome.statusCode, outcome.message, route);
            return;
          }
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }

        const outcome = await credentialStatusResponseManager.poll(route, req, requestUrl);
        if (outcome.type === 'error') {
          sendError(req, res, outcome.statusCode, outcome.message, route);
          return;
        }
        if (outcome.type === 'pending') {
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }
        sendDidcommJson(res, 200, outcome.payload);
        return;
      }

      const parsedCredentialRevoke = parseCredentialRevokeRoute(requestUrl.pathname);
      if (parsedCredentialRevoke) {
        if (!parsedCredentialRevoke.ok) {
          sendError(req, res, parsedCredentialRevoke.statusCode, parsedCredentialRevoke.message);
          return;
        }
        if (method !== 'POST') {
          res.setHeader('Allow', 'POST');
          sendError(req, res, 405, 'Method not allowed. Use POST.', parsedCredentialRevoke.context);
          return;
        }

        const route = parsedCredentialRevoke.context;
        if (route.action === '_revoke') {
          const outcome = await credentialRevokeRequestManager.submit(route, req);
          if (outcome.type === 'error') {
            sendError(req, res, outcome.statusCode, outcome.message, route);
            return;
          }
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }

        const outcome = await credentialRevokeResponseManager.poll(route, req, requestUrl);
        if (outcome.type === 'error') {
          sendError(req, res, outcome.statusCode, outcome.message, route);
          return;
        }
        if (outcome.type === 'pending') {
          res.statusCode = 202;
          res.setHeader('Location', outcome.location);
          res.setHeader('Retry-After', String(outcome.retryAfter));
          res.end();
          return;
        }
        sendDidcommJson(res, 200, outcome.payload);
        return;
      }

      const parsedRotate = parseRotateRoute(requestUrl.pathname);
      if (parsedRotate) {
        if (!parsedRotate.ok) {
          sendError(req, res, parsedRotate.statusCode, parsedRotate.message);
          return;
        }
        if (method !== 'POST') {
          res.setHeader('Allow', 'POST');
          sendError(req, res, 405, 'Method not allowed. Use POST.', parsedRotate.context);
          return;
        }
        if (parsedRotate.context.action === '_rotate') {
          res.statusCode = 202;
          res.setHeader('Location', buildRotateResponseLocation(parsedRotate.context));
          res.setHeader('Retry-After', '5');
          res.end();
          return;
        }
        sendError(req, res, 501, `Endpoint ${requestUrl.pathname} is not implemented yet.`, parsedRotate.context);
        return;
      }

      sendError(req, res, 404, 'Endpoint not found.');
    } catch (error: unknown) {
      sendError(req, res, 500, (error as Error)?.message || 'Unexpected server error.');
    }
  });
}

export function startIcaApiServer(options: IcaApiServerOptions = {}) {
  const host = options.host || process.env.ICA_API_HOST || '0.0.0.0';
  const port = options.port || Number.parseInt(process.env.ICA_API_PORT || process.env.PORT || '3310', 10);
  const server = createIcaApiServer(options);
  server.listen(port, host, () => {
    console.log(`ICA verify API listening on http://${host}:${port}`);
  });
  return server;
}

const isDirectExecution = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isDirectExecution) {
  startIcaApiServer();
}
