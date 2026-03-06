import { FnmtSignatureVerifierAdapter } from './adapters/fnmt-signature-verifier-adapter.ts';
import type {
  PdfVerificationService,
  SignatureVerifierAdapter,
  VerifyResult,
  VerifyRouteContext,
  VerifySubmission,
} from './types.ts';

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function parseCsv(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export type SignatureVerificationManagerOptions = {
  preferredAdapterId?: string;
  strictPreferredAdapter?: boolean;
};

export class SignatureVerificationManager implements PdfVerificationService {
  private readonly adapters: readonly SignatureVerifierAdapter[];
  private readonly preferredAdapterId?: string;
  private readonly strictPreferredAdapter: boolean;

  constructor(
    adapters: readonly SignatureVerifierAdapter[],
    options: SignatureVerificationManagerOptions = {},
  ) {
    this.adapters = adapters;
    this.preferredAdapterId = options.preferredAdapterId?.trim().toLowerCase() || undefined;
    this.strictPreferredAdapter = options.strictPreferredAdapter ?? false;
  }

  private findById(id: string): SignatureVerifierAdapter | undefined {
    return this.adapters.find((adapter) => adapter.id.trim().toLowerCase() === id.trim().toLowerCase());
  }

  async verify(route: VerifyRouteContext, submission: VerifySubmission): Promise<VerifyResult> {
    if (!this.adapters.length) {
      throw new Error('No signature verification adapters are registered.');
    }

    if (this.preferredAdapterId) {
      const preferred = this.findById(this.preferredAdapterId);
      if (!preferred) {
        throw new Error(`Preferred signature verifier adapter "${this.preferredAdapterId}" is not registered.`);
      }

      if (await preferred.supports(route)) {
        return preferred.verify(route, submission);
      }

      if (this.strictPreferredAdapter) {
        throw new Error(
          `Preferred signature verifier adapter "${this.preferredAdapterId}" does not support jurisdiction "${route.jurisdiction}".`,
        );
      }
    }

    for (const adapter of this.adapters) {
      if (await adapter.supports(route)) {
        return adapter.verify(route, submission);
      }
    }

    throw new Error(
      `No signature verifier adapter supports jurisdiction "${route.jurisdiction}" for sector "${route.sector}".`,
    );
  }
}

export function createDefaultSignatureVerificationManagerFromEnv(): SignatureVerificationManager {
  const preferredAdapterId = process.env.ICA_VERIFY_ADAPTER?.trim() || undefined;
  const strictPreferredAdapter = parseBoolean(process.env.ICA_VERIFY_ADAPTER_STRICT, false);
  const fnmtJurisdictions = parseCsv(process.env.ICA_FNMT_ADAPTER_JURISDICTIONS);

  const adapters: SignatureVerifierAdapter[] = [
    new FnmtSignatureVerifierAdapter({
      id: 'fnmt-es',
      allowedJurisdictions: fnmtJurisdictions.length ? fnmtJurisdictions : ['ES'],
    }),
  ];

  return new SignatureVerificationManager(adapters, {
    preferredAdapterId,
    strictPreferredAdapter,
  });
}
