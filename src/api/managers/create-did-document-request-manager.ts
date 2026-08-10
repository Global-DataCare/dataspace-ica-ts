import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseCreateDidDocumentSubmission } from '../request-parsing.ts';
import { buildCreateDidDocumentResponseLocation } from '../path.ts';
import type { CreateDidDocumentResult, CreateDidDocumentRouteContext } from '../types.ts';
import {
  buildOrganizationDidFromTaxId,
  buildOrganizationDidDocument,
  extractOrganizationDidTaxId,
  validateOrganizationDidInput,
} from '../tools/organization-did.ts';
import type {
  DidBindingRecord,
  DidDocumentRecord,
  IssuedCredentialRecord,
} from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';
import { sameAsValuesEqual } from '../tools/multihash.ts';
import { stableStringifyJson, type JsonLike } from '../tools/canonical-json.ts';
import { normalizeControllerPublicKeyJwk } from '../tools/bootstrap-organization-key.ts';

export type CreateDidDocumentSubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

type JsonObject = Record<string, unknown>;

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function controllerPublicKeysEqual(left: JsonObject, right: JsonObject): boolean {
  return stableStringifyJson(left as JsonLike) === stableStringifyJson(right as JsonLike);
}

function controllerJwkSetsEqual(
  left: { keys: JsonObject[] },
  right: { keys: JsonObject[] },
): boolean {
  return stableStringifyJson(left as unknown as JsonLike) === stableStringifyJson(right as unknown as JsonLike);
}

function equalsIgnoreCase(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function resolveCredentialSubject(credential: JsonObject): JsonObject | undefined {
  const credentialSubject = credential.credentialSubject;
  if (Array.isArray(credentialSubject)) {
    for (const candidate of credentialSubject) {
      const subject = asObject(candidate);
      if (subject) return subject;
    }
    return undefined;
  }
  return asObject(credentialSubject);
}

function resolveOrganizationTaxId(subject: JsonObject): string {
  return asNonEmptyString(subject.taxID || subject.taxId);
}

function isOrganizationSubject(subject: JsonObject): boolean {
  const type = subject['@type'];
  if (typeof type === 'string') return equalsIgnoreCase(type, 'Organization');
  if (Array.isArray(type)) return type.some((value) => equalsIgnoreCase(asNonEmptyString(value), 'Organization'));
  return false;
}

function isPersonSubject(subject: JsonObject): boolean {
  const type = subject['@type'];
  if (typeof type === 'string') return equalsIgnoreCase(type, 'Person');
  if (Array.isArray(type)) return type.some((value) => equalsIgnoreCase(asNonEmptyString(value), 'Person'));
  return false;
}

function resolvePersonOrganizationTaxId(subject: JsonObject): string {
  const memberOf = asObject(subject.memberOf);
  if (!memberOf) return '';
  return asNonEmptyString(memberOf.taxID || memberOf.taxId);
}

function resolveStoredOrganizationDid(
  records: IssuedCredentialRecord[],
  route: CreateDidDocumentRouteContext,
  lookup: { taxId?: string; did?: string },
): string | undefined {
  const normalizedTaxId = asNonEmptyString(lookup.taxId);
  const normalizedDid = asNonEmptyString(lookup.did);
  if (!normalizedTaxId && !normalizedDid) return undefined;

  for (const record of [...records].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))) {
    if (!equalsIgnoreCase(record.tenantId, route.tenantId)) continue;
    if (!equalsIgnoreCase(record.jurisdiction, route.jurisdiction)) continue;
    if (!equalsIgnoreCase(record.sector, route.sector)) continue;
    const subject = resolveCredentialSubject(asObject(record.credential) || {});
    if (!subject || !isOrganizationSubject(subject)) continue;
    const did = asNonEmptyString(subject.id) || asNonEmptyString(record.subjectId);
    if (normalizedDid) {
      if (!equalsIgnoreCase(did, normalizedDid)) continue;
    } else if (!equalsIgnoreCase(resolveOrganizationTaxId(subject), normalizedTaxId)) {
      continue;
    }
    if (did) return did;
  }

  return undefined;
}

function resolveRequestedOrganizationDid(
  route: CreateDidDocumentRouteContext,
  item: {
    id?: string;
    organization: { identifier?: string; url?: string; taxID?: string };
  },
): string {
  const explicitDid = asNonEmptyString(item.id || item.organization.identifier);
  if (explicitDid) return explicitDid;
  return buildOrganizationDidFromTaxId(route.sector, item.organization.taxID || '', item.organization.url || '');
}

function resolveStoredControllerSameAs(
  records: IssuedCredentialRecord[],
  route: CreateDidDocumentRouteContext,
  taxId: string,
): string | undefined {
  const normalizedTaxId = asNonEmptyString(taxId);
  if (!normalizedTaxId) return undefined;

  for (const record of [...records].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))) {
    if (!equalsIgnoreCase(record.tenantId, route.tenantId)) continue;
    if (!equalsIgnoreCase(record.jurisdiction, route.jurisdiction)) continue;
    if (!equalsIgnoreCase(record.sector, route.sector)) continue;
    const subject = resolveCredentialSubject(asObject(record.credential) || {});
    if (!subject || !isPersonSubject(subject)) continue;
    if (!equalsIgnoreCase(resolvePersonOrganizationTaxId(subject), normalizedTaxId)) continue;
    const sameAs = asNonEmptyString(subject.sameAs);
    if (sameAs) return sameAs;
  }

  return undefined;
}

function resolveStoredOrganizationPublicKeyJwk(
  records: DidBindingRecord[],
  route: CreateDidDocumentRouteContext,
  taxId: string,
): { publicKeyJwk: JsonObject; keySource?: 'attachment' | 'generated' } | undefined {
  const normalizedTaxId = asNonEmptyString(taxId);
  if (!normalizedTaxId) return undefined;

  for (const record of [...records].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))) {
    if (!equalsIgnoreCase(record.tenantId, route.tenantId)) continue;
    if (!equalsIgnoreCase(record.jurisdiction, route.jurisdiction)) continue;
    if (!equalsIgnoreCase(record.sector, route.sector)) continue;
    if (!equalsIgnoreCase(record.taxId, normalizedTaxId)) continue;
    if (record.status === 'removed') return undefined;
    const publicKeyJwk = asObject(record.organizationPublicKeyJwk);
    if (publicKeyJwk) {
      return {
        publicKeyJwk,
        ...(record.organizationKeySource ? { keySource: record.organizationKeySource } : {}),
      };
    }
  }

  return undefined;
}

function resolveStoredControllerPublicKeyJwk(
  records: DidBindingRecord[],
  route: CreateDidDocumentRouteContext,
  taxId: string,
): JsonObject | undefined {
  const normalizedTaxId = asNonEmptyString(taxId);
  if (!normalizedTaxId) return undefined;

  for (const record of [...records].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))) {
    if (!equalsIgnoreCase(record.tenantId, route.tenantId)) continue;
    if (!equalsIgnoreCase(record.jurisdiction, route.jurisdiction)) continue;
    if (!equalsIgnoreCase(record.sector, route.sector)) continue;
    if (!equalsIgnoreCase(record.taxId, normalizedTaxId)) continue;
    if (record.status === 'removed') return undefined;
    const publicKeyJwk = asObject(record.controllerPublicKeyJwk);
    if (publicKeyJwk) return publicKeyJwk;
  }

  return undefined;
}

function resolveLatestDidBindingRecord(
  records: DidBindingRecord[],
  route: CreateDidDocumentRouteContext,
  taxId: string,
): DidBindingRecord | undefined {
  const normalizedTaxId = asNonEmptyString(taxId);
  if (!normalizedTaxId) return undefined;

  return [...records]
    .filter((record) =>
      equalsIgnoreCase(record.tenantId, route.tenantId)
      && equalsIgnoreCase(record.jurisdiction, route.jurisdiction)
      && equalsIgnoreCase(record.sector, route.sector)
      && equalsIgnoreCase(record.taxId, normalizedTaxId))
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0];
}

export class CreateDidDocumentRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>;
  private readonly collectionsService: VerificationCollectionsService;
  private readonly requireControllerSameAsMatch: boolean;

  constructor(
    jobStore: InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
    this.requireControllerSameAsMatch = parseBooleanEnv(
      process.env.ICA_CREATE_DID_REQUIRE_CONTROLLER_SAMEAS_MATCH,
      false,
    );
  }

  async submit(route: CreateDidDocumentRouteContext, req: IncomingMessage): Promise<CreateDidDocumentSubmitOutcome> {
    try {
      const submission = await parseCreateDidDocumentSubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const issuedRecords = await this.collectionsService.listIssuedCredentials();
          const didBindingRecords = await this.collectionsService.listDidBindings();
          const createdAt = new Date().toISOString();
          const confirmedDidBindings: DidBindingRecord[] = [];
          const confirmedDidDocuments: DidDocumentRecord[] = [];
          const items = submission.items.map((item) => {
            const taxId = asNonEmptyString(item.organization.taxID);
            const did = resolveRequestedOrganizationDid(route, {
              id: item.id,
              organization: item.organization,
            });
            const lookupTaxId = extractOrganizationDidTaxId(did) || taxId || '';
            const latestDidBinding = resolveLatestDidBindingRecord(didBindingRecords, route, lookupTaxId);
            if (latestDidBinding?.status === 'removed') {
              throw new Error(
                `Organization terms were removed for organization.taxID "${lookupTaxId}". Complete _verify again before calling _create.`,
              );
            }
            const expectedDid = resolveStoredOrganizationDid(issuedRecords, route, {
              ...(lookupTaxId ? { taxId: lookupTaxId } : {}),
            });
            if (!expectedDid) {
              throw new Error(
                lookupTaxId
                  ? `No organization credential found for organization.taxID "${lookupTaxId}" with credentialSubject.id.`
                  : `No organization credential found for organization.identifier "${did}".`,
              );
            }
            validateOrganizationDidInput({
              did,
              sector: route.sector,
              jurisdiction: route.jurisdiction,
              ...(lookupTaxId ? { taxId: lookupTaxId } : {}),
            });
            if (!equalsIgnoreCase(did, expectedDid)) {
              throw new Error(
                lookupTaxId
                  ? `Resolved DID "${did}" must match stored organization credentialSubject.id "${expectedDid}" for organization.taxID "${lookupTaxId}".`
                  : `organization.identifier "${did}" must match stored organization credentialSubject.id "${expectedDid}".`,
              );
            }
            if (this.requireControllerSameAsMatch) {
              const controllerSameAs = asNonEmptyString(item.controller.sameAs);
              if (!controllerSameAs) {
                throw new Error(
                  'controller.sameAs is required when ICA_CREATE_DID_REQUIRE_CONTROLLER_SAMEAS_MATCH=true.',
                );
              }
              const expectedControllerSameAs = resolveStoredControllerSameAs(issuedRecords, route, lookupTaxId);
              if (!expectedControllerSameAs) {
                throw new Error(
                  `No person credential found for organization.taxID "${lookupTaxId}" with credentialSubject.sameAs.`,
                );
              }
              if (!sameAsValuesEqual(controllerSameAs, expectedControllerSameAs)) {
                throw new Error(
                  `controller.sameAs "${controllerSameAs}" must match stored person credentialSubject.sameAs "${expectedControllerSameAs}" for organization.taxID "${lookupTaxId}".`,
                );
              }
            }
            const storedControllerPublicKeyJwk = resolveStoredControllerPublicKeyJwk(didBindingRecords, route, lookupTaxId);
            const requestedControllerPublicKeyJwk = item.controller.publicKeyJwk
              ? normalizeControllerPublicKeyJwk(item.controller.publicKeyJwk, item.controller.alg)
              : undefined;
            if (
              requestedControllerPublicKeyJwk
              && storedControllerPublicKeyJwk
              && !controllerPublicKeysEqual(requestedControllerPublicKeyJwk, storedControllerPublicKeyJwk)
            ) {
              throw new Error(
                `controller.publicKeyJwk must match the controller binding stored during _verify for organization.taxID "${lookupTaxId}". `
                + `Use the exact key returned by _verify-response body.data[1].publicKeyJwk.`,
              );
            }
            const controllerPublicKeyJwk = requestedControllerPublicKeyJwk || storedControllerPublicKeyJwk;
            if (!controllerPublicKeyJwk) {
              throw new Error(
                `No controller publicKeyJwk found for organization.taxID "${lookupTaxId}". Send controller.publicKeyJwk or complete _verify v2 with controller binding first.`,
              );
            }
            const requestedControllerDid = asNonEmptyString(item.controller.did);
            const storedControllerDid = asNonEmptyString(latestDidBinding?.controllerDid);
            if (requestedControllerDid && storedControllerDid && requestedControllerDid !== storedControllerDid) {
              throw new Error(
                `controller.did must match the controller DID stored during _verify for organization.taxID "${lookupTaxId}".`,
              );
            }
            const controllerDid = requestedControllerDid || storedControllerDid || undefined;
            const requestedControllerJwks = item.controller.jwks as { keys: JsonObject[] } | undefined;
            const storedControllerJwks = latestDidBinding?.controllerJwks;
            if (
              requestedControllerJwks
              && storedControllerJwks
              && !controllerJwkSetsEqual(requestedControllerJwks, storedControllerJwks)
            ) {
              throw new Error(
                `controller.jwks must match the controller key set stored during _verify for organization.taxID "${lookupTaxId}".`,
              );
            }
            const controllerJwks = requestedControllerJwks || storedControllerJwks;
            const storedOrganizationKey = resolveStoredOrganizationPublicKeyJwk(didBindingRecords, route, lookupTaxId);
            const requestedOrganizationPublicKeyJwk = item.organization.publicKeyJwk;
            const organizationPublicKeyJwk = requestedOrganizationPublicKeyJwk
              || storedOrganizationKey?.publicKeyJwk;
            if (!organizationPublicKeyJwk) {
              throw new Error(
                `No organization publicKeyJwk found for organization.taxID "${lookupTaxId}". Send organization.publicKeyJwk or complete _verify v2 with organization key bootstrap first.`,
              );
            }
            const selectedOrganizationKeySource = requestedOrganizationPublicKeyJwk
              ? 'attachment'
              : storedOrganizationKey?.keySource;
            const built = buildOrganizationDidDocument({
              did,
              controller: {
                ...item.controller,
                ...(controllerDid ? { did: controllerDid } : {}),
                publicKeyJwk: controllerPublicKeyJwk,
                ...(controllerJwks ? { jwks: controllerJwks } : {}),
              },
              organization: {
                ...item.organization,
                publicKeyJwk: organizationPublicKeyJwk,
              },
            });
            confirmedDidBindings.push({
              id: [
                route.tenantId.trim().toLowerCase(),
                route.jurisdiction.trim().toLowerCase(),
                route.sector.trim().toLowerCase(),
                lookupTaxId.trim().toUpperCase(),
              ].join('::'),
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              resourceType: route.action === '_create' ? 'document' : route.resourceType,
              thid: submission.thid,
              taxId: lookupTaxId,
              did,
              ...(controllerDid ? { controllerDid } : {}),
              ...(item.controller.sameAs ? { controllerSameAs: item.controller.sameAs } : {}),
              controllerPublicKeyJwk,
              ...(controllerJwks ? { controllerJwks } : {}),
              organizationPublicKeyJwk,
              ...(selectedOrganizationKeySource ? { organizationKeySource: selectedOrganizationKeySource } : {}),
              status: 'confirmed',
              createdAt,
              updatedAt: createdAt,
              confirmedAt: createdAt,
            });
            confirmedDidDocuments.push({
              id: did,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              resourceType: 'document',
              thid: submission.thid,
              did,
              ...(lookupTaxId ? { taxId: lookupTaxId } : {}),
              ...(controllerDid ? { controllerDid } : {}),
              ...(item.controller.sameAs ? { controllerSameAs: item.controller.sameAs } : {}),
              controllerPublicKeyJwk,
              ...(controllerJwks ? { controllerJwks } : {}),
              organizationPublicKeyJwk,
              didDocument: built.didDocument,
              status: 'confirmed',
              createdAt,
              updatedAt: createdAt,
            });
            return {
              did,
              verificationMethod: built.verificationMethodId,
              nodeOperator: built.nodeOperator,
              createdAt,
              ...(item.controller.sameAs ? { controllerSameAs: item.controller.sameAs } : {}),
              ...(item.organization.taxID ? { organizationTaxId: item.organization.taxID } : {}),
              ...(item.organization.legalName ? { organizationLegalName: item.organization.legalName } : {}),
              didDocument: built.didDocument,
            };
          });
          await this.collectionsService.storeDidBindings(confirmedDidBindings);
          await this.collectionsService.storeDidDocuments(confirmedDidDocuments);
          this.jobStore.markSucceeded(submission.thid, {
            createdCount: items.length,
            items,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`DID document _create job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildCreateDidDocumentResponseLocation(route, { thid: submission.thid }),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid DID document create payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
