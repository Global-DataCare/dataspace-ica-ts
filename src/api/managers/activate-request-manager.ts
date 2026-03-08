import type { IncomingMessage } from 'node:http';
import { InMemoryActivationJobStore } from '../activation-job-store.ts';
import { parseActivateSigningKeySubmission } from '../request-parsing.ts';
import { buildActivateResponseLocation } from '../path.ts';
import type { ActivateRouteContext } from '../types.ts';
import { validateActivateControllerCaCredential } from '../tools/controller-ca-credential.ts';
import { activateSigningKey } from '../tools/active-signing-keys.ts';
import { validateActivateControllerDidcommProof } from '../tools/controller-didcomm-proof.ts';
import { resolveIcaIssuerDid } from '../tools/ica-identity.ts';

export type ActivateSubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

export class ActivateRequestManager {
  private readonly jobStore: InMemoryActivationJobStore;

  constructor(jobStore: InMemoryActivationJobStore) {
    this.jobStore = jobStore;
  }

  async submit(route: ActivateRouteContext, req: IncomingMessage): Promise<ActivateSubmitOutcome> {
    try {
      const submission = await parseActivateSigningKeySubmission(req);
      validateActivateControllerDidcommProof(submission, req);
      validateActivateControllerCaCredential(submission);
      const issuerDid = resolveIcaIssuerDid(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const activated = submission.keys.map((keyInput) => {
            const record = activateSigningKey({
              kid: keyInput.kid,
              alg: keyInput.alg,
              privateKeyPem: keyInput.privateKeyPem,
              x5c: keyInput.x5c,
              certificateChainPem: keyInput.certificateChainPem,
            });
            return {
              kid: record.kid,
              alg: record.alg,
              activatedAt: record.activatedAt,
              assertionMethod: `${issuerDid}#${record.kid}`,
              chainLength: record.x5c?.length || 0,
            };
          });
          this.jobStore.markSucceeded(submission.thid, {
            issuerDid,
            activated,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Activation job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildActivateResponseLocation(route),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid activation payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
