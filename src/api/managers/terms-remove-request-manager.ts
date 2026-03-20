import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseTermsRemoveSubmission } from '../request-parsing.ts';
import { buildTermsRemoveResponseLocation } from '../path.ts';
import type { TermsRemoveResult, TermsRemoveRouteContext } from '../types.ts';
import type { DidBindingRecord, DidDocumentRecord } from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';
import { sameAsValuesEqual } from '../tools/multihash.ts';
import { stableStringifyJson, type JsonLike } from '../tools/canonical-json.ts';
import { normalizeControllerPublicKeyJwk } from '../tools/bootstrap-organization-key.ts';

export type TermsRemoveSubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

type JsonObject = Record<string, unknown>;

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function equalsIgnoreCase(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function controllerPublicKeysEqual(left: JsonObject, right: JsonObject): boolean {
  return stableStringifyJson(left as JsonLike) === stableStringifyJson(right as JsonLike);
}

function resolveLatestDidBindingRecord(
  records: DidBindingRecord[],
  route: TermsRemoveRouteContext,
  lookup: { did?: string; taxId?: string },
): DidBindingRecord | undefined {
  return [...records]
    .filter((record) =>
      equalsIgnoreCase(record.tenantId, route.tenantId)
      && equalsIgnoreCase(record.jurisdiction, route.jurisdiction)
      && equalsIgnoreCase(record.sector, route.sector)
      && (
        (lookup.did ? equalsIgnoreCase(asNonEmptyString(record.did), lookup.did) : false)
        || (lookup.taxId ? equalsIgnoreCase(record.taxId, lookup.taxId) : false)
      ))
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0];
}

function resolveLatestDidDocumentRecord(
  records: DidDocumentRecord[],
  route: TermsRemoveRouteContext,
  lookup: { did?: string; taxId?: string },
): DidDocumentRecord | undefined {
  return [...records]
    .filter((record) =>
      equalsIgnoreCase(record.tenantId, route.tenantId)
      && equalsIgnoreCase(record.jurisdiction, route.jurisdiction)
      && equalsIgnoreCase(record.sector, route.sector)
      && (
        (lookup.did ? equalsIgnoreCase(record.did, lookup.did) : false)
        || (lookup.taxId ? equalsIgnoreCase(asNonEmptyString(record.taxId), lookup.taxId) : false)
      ))
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0];
}

export class TermsRemoveRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<TermsRemoveRouteContext, TermsRemoveResult>;
  private readonly collectionsService: VerificationCollectionsService;

  constructor(
    jobStore: InMemoryEntityJobStore<TermsRemoveRouteContext, TermsRemoveResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
  }

  async submit(route: TermsRemoveRouteContext, req: IncomingMessage): Promise<TermsRemoveSubmitOutcome> {
    try {
      const submission = await parseTermsRemoveSubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const nowIso = new Date().toISOString();
          const didBindings = await this.collectionsService.listDidBindings();
          const didDocuments = await this.collectionsService.listDidDocuments();
          const removedBindingRecords: DidBindingRecord[] = [];
          const removedDidDocumentRecords: DidDocumentRecord[] = [];
          const resultItems = [];

          for (const item of submission.items) {
            const taxId = asNonEmptyString(item.organization.taxID).toUpperCase() || undefined;
            const requestedDid = asNonEmptyString(item.organization.identifier) || undefined;
            const latestDidBinding = resolveLatestDidBindingRecord(didBindings, route, {
              ...(requestedDid ? { did: requestedDid } : {}),
              ...(taxId ? { taxId } : {}),
            });
            const latestDidDocument = resolveLatestDidDocumentRecord(didDocuments, route, {
              ...(requestedDid ? { did: requestedDid } : {}),
              ...(taxId ? { taxId } : {}),
            });
            const lookupLabel = requestedDid
              ? `organization.identifier "${requestedDid}"`
              : `organization.taxID "${taxId}"`
            ;

            if (!latestDidBinding || latestDidBinding.status === 'removed') {
              throw new Error(`No active organization binding found for ${lookupLabel}.`);
            }
            if (!latestDidDocument || latestDidDocument.status === 'removed') {
              throw new Error(`No active organization DID document found for ${lookupLabel}.`);
            }

            const did = asNonEmptyString(latestDidDocument.did);
            if (!did) {
              throw new Error(`Active DID document is missing did for ${lookupLabel}.`);
            }
            if (item.organization.identifier && !equalsIgnoreCase(item.organization.identifier, did)) {
              throw new Error(
                `organization.identifier "${item.organization.identifier}" must match active DID "${did}".`,
              );
            }
            const resolvedTaxId = asNonEmptyString(latestDidBinding.taxId || latestDidDocument.taxId).toUpperCase() || undefined;
            if (taxId && resolvedTaxId && !equalsIgnoreCase(taxId, resolvedTaxId)) {
              throw new Error(
                `organization.taxID "${taxId}" must match active organization taxID "${resolvedTaxId}" for DID "${did}".`,
              );
            }

            const storedControllerPublicKeyJwk = asObject(latestDidBinding.controllerPublicKeyJwk);
            const requestedControllerPublicKeyJwk = item.controller.publicKeyJwk
              ? normalizeControllerPublicKeyJwk(item.controller.publicKeyJwk)
              : undefined;
            if (!requestedControllerPublicKeyJwk) {
              throw new Error(
                `Controller binding public key is required for _remove on DID "${did}".`,
              );
            }
            if (!storedControllerPublicKeyJwk || !controllerPublicKeysEqual(requestedControllerPublicKeyJwk, storedControllerPublicKeyJwk)) {
              throw new Error(
                `controller public key must match the stored controller binding for DID "${did}".`,
              );
            }
            const storedControllerSameAs = asNonEmptyString(latestDidBinding.controllerSameAs);
            if (item.controller.sameAs && storedControllerSameAs && !sameAsValuesEqual(item.controller.sameAs, storedControllerSameAs)) {
              throw new Error(
                `controller.sameAs "${item.controller.sameAs}" must match stored controller.sameAs "${storedControllerSameAs}" for DID "${did}".`,
              );
            }

            removedBindingRecords.push({
              ...latestDidBinding,
              status: 'removed',
              updatedAt: nowIso,
              removedAt: nowIso,
              ...(item.reason ? { removeReason: item.reason } : {}),
            });
            removedDidDocumentRecords.push({
              ...latestDidDocument,
              status: 'removed',
              updatedAt: nowIso,
              removedAt: nowIso,
              ...(item.reason ? { removeReason: item.reason } : {}),
            });
            resultItems.push({
              ...(resolvedTaxId ? { organizationTaxId: resolvedTaxId } : {}),
              did,
              removedAt: nowIso,
              ...(item.reason ? { reason: item.reason } : {}),
              effects: {
                didBindings: 'removed' as const,
                didDocument: 'removed' as const,
                catalogMembership: 'removed' as const,
                organizationKeys: 'revoked' as const,
              },
            });
          }

          await this.collectionsService.storeDidBindings(removedBindingRecords);
          await this.collectionsService.storeDidDocuments(removedDidDocumentRecords);

          this.jobStore.markSucceeded(submission.thid, {
            removedCount: resultItems.length,
            items: resultItems,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Terms _remove job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildTermsRemoveResponseLocation(route, { thid: submission.thid }),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid terms remove payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
