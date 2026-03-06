import { FnmtPdfVerificationService } from '../fnmt-pdf-verifier.ts';
import type {
  PdfVerificationService,
  SignatureVerifierAdapter,
  VerifyResult,
  VerifyRouteContext,
  VerifySubmission,
} from '../types.ts';

function parseJurisdictions(values: string[] | undefined): Set<string> {
  const source = values?.length ? values : ['ES'];
  return new Set(
    source
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
}

export type FnmtSignatureVerifierAdapterOptions = {
  id?: string;
  allowedJurisdictions?: string[];
  verifier?: PdfVerificationService;
};

export class FnmtSignatureVerifierAdapter implements SignatureVerifierAdapter {
  public readonly id: string;
  private readonly verifier: PdfVerificationService;
  private readonly allowedJurisdictions: Set<string>;

  constructor(options: FnmtSignatureVerifierAdapterOptions = {}) {
    this.id = (options.id || 'fnmt-es').trim().toLowerCase();
    this.verifier = options.verifier || new FnmtPdfVerificationService();
    this.allowedJurisdictions = parseJurisdictions(options.allowedJurisdictions);
  }

  supports(route: VerifyRouteContext): boolean {
    return this.allowedJurisdictions.has(route.jurisdiction.trim().toLowerCase());
  }

  verify(route: VerifyRouteContext, submission: VerifySubmission): Promise<VerifyResult> {
    return this.verifier.verify(route, submission);
  }
}
