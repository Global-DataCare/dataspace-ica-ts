import type { IncomingMessage } from 'node:http';
import { buildVerifyResponseLocation } from '../path.ts';
import { parseVerifySubmission } from '../request-parsing.ts';
import { InMemoryVerificationJobStore } from '../job-store.ts';
import type { PdfVerificationService, VerificationErrorDetails, VerifyRouteContext } from '../types.ts';
import { AuditDocumentStorageService } from '../tools/audit-document-storage.ts';

export type VerifySubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

function extractVerificationErrorDetails(error: unknown): VerificationErrorDetails | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const details = (error as { errorDetails?: VerificationErrorDetails }).errorDetails;
  if (!details || typeof details !== 'object') return undefined;
  return details;
}

export class VerifyRequestManager {
  private readonly jobStore: InMemoryVerificationJobStore;
  private readonly verifier: PdfVerificationService;
  private readonly auditStorage: AuditDocumentStorageService;

  constructor(
    jobStore: InMemoryVerificationJobStore,
    verifier: PdfVerificationService,
    auditStorage: AuditDocumentStorageService = new AuditDocumentStorageService(),
  ) {
    this.jobStore = jobStore;
    this.verifier = verifier;
    this.auditStorage = auditStorage;
  }

  async submit(route: VerifyRouteContext, req: IncomingMessage): Promise<VerifySubmitOutcome> {
    try {
      const submission = await parseVerifySubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const verificationResult = await this.verifier.verify(route, submission);
          const enrichedResult = await this.auditStorage.persistVerifiedPdf(route, submission, verificationResult);
          this.jobStore.markSucceeded(submission.thid, enrichedResult);
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          const errorDetails = extractVerificationErrorDetails(error);
          console.error(`Verification job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message, errorDetails);
        }
      });

      return {
        type: 'accepted',
        location: buildVerifyResponseLocation(route, { thid: submission.thid }),
        retryAfter: 5,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid upload payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
