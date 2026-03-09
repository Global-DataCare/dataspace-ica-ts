import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseCredentialSearchSubmission } from '../request-parsing.ts';
import { buildCredentialSearchResponseLocation } from '../path.ts';
import type { CredentialSearchResult, CredentialSearchRouteContext } from '../types.ts';
import type { IssuedCredentialRecord } from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';
import { multibase58MultihashSha3_256 } from '../tools/multihash.ts';

export type CredentialSearchSubmitOutcome =
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

function equalsIgnoreCase(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function includesIgnoreCase(left: string, right: string): boolean {
  return left.trim().toLowerCase().includes(right.trim().toLowerCase());
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

function resolveOrganizationNode(subject: JsonObject): JsonObject {
  const memberOf = asObject(subject.memberOf);
  if (memberOf) return memberOf;
  const organization = asObject(subject.organization);
  if (organization) return organization;
  return subject;
}

function resolveTaxId(entity: JsonObject): string {
  return (
    asNonEmptyString(entity.taxId)
    || asNonEmptyString(entity.taxID)
    || asNonEmptyString(entity.vatID)
    || asNonEmptyString(entity.vatId)
    || asNonEmptyString(entity.identifier)
  );
}

function resolveLegalName(entity: JsonObject): string {
  return (
    asNonEmptyString(entity.legalName)
    || asNonEmptyString(entity.name)
    || asNonEmptyString(entity.alternateName)
  );
}

function resolveOrganizationDid(subject: JsonObject, record: IssuedCredentialRecord): string {
  const organizationNode = resolveOrganizationNode(subject);
  return (
    asNonEmptyString(organizationNode.id)
    || asNonEmptyString(subject.id)
    || asNonEmptyString(record.subjectId)
  );
}

function resolveEmail(entity: JsonObject): string {
  return asNonEmptyString(entity.email);
}

function resolveAddressText(entity: JsonObject): string {
  const address = asObject(entity.address);
  if (!address) return '';
  return [
    asNonEmptyString(address.streetAddress),
    asNonEmptyString(address.addressLocality),
    asNonEmptyString(address.addressRegion),
    asNonEmptyString(address.postalCode),
    asNonEmptyString(address.addressCountry),
  ].filter(Boolean).join(' ');
}

function matchesQuery(record: IssuedCredentialRecord, query: {
  id?: string;
  text?: string;
  email?: string;
  taxId?: string;
  taxIdHash?: string;
  legalName?: string;
  subjectId?: string;
  issuerId?: string;
  credentialId?: string;
}): {
  matched: boolean;
  subject: JsonObject;
  organizationNode: JsonObject;
  taxId: string;
  legalName: string;
  organizationDid: string;
  taxIdHash?: string;
} {
  const credential = asObject(record.credential) || {};
  const subject = resolveCredentialSubject(credential) || {};
  const organizationNode = resolveOrganizationNode(subject);
  const taxId = resolveTaxId(organizationNode) || resolveTaxId(subject);
  const legalName = resolveLegalName(organizationNode) || resolveLegalName(subject);
  const organizationDid = resolveOrganizationDid(subject, record);
  const taxIdHash = taxId ? multibase58MultihashSha3_256(taxId) : undefined;
  const email = resolveEmail(organizationNode) || resolveEmail(subject);
  const addressText = resolveAddressText(organizationNode) || resolveAddressText(subject);

  if (query.id) {
    const idMatched =
      equalsIgnoreCase(query.id, record.credentialId)
      || equalsIgnoreCase(query.id, record.subjectId)
      || equalsIgnoreCase(query.id, taxId)
      || equalsIgnoreCase(query.id, taxIdHash || '');
    if (!idMatched) {
      return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
    }
  }
  if (query.email && !equalsIgnoreCase(query.email, email)) {
    return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.text && !includesIgnoreCase(`${legalName} ${addressText}`.trim(), query.text)) {
    return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
  }

  if (query.taxId && !equalsIgnoreCase(query.taxId, taxId)) {
    return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.taxIdHash && !equalsIgnoreCase(query.taxIdHash, taxIdHash || '')) {
    return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.legalName && !includesIgnoreCase(legalName, query.legalName)) {
    return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.subjectId && !equalsIgnoreCase(query.subjectId, record.subjectId)) {
    return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.issuerId && !equalsIgnoreCase(query.issuerId, record.issuerId)) {
    return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.credentialId && !equalsIgnoreCase(query.credentialId, record.credentialId)) {
    return { matched: false, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
  }

  return { matched: true, subject, organizationNode, taxId, legalName, organizationDid, taxIdHash };
}

export class CredentialSearchRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<CredentialSearchRouteContext, CredentialSearchResult>;
  private readonly collectionsService: VerificationCollectionsService;

  constructor(
    jobStore: InMemoryEntityJobStore<CredentialSearchRouteContext, CredentialSearchResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
  }

  async submit(route: CredentialSearchRouteContext, req: IncomingMessage): Promise<CredentialSearchSubmitOutcome> {
    try {
      const submission = await parseCredentialSearchSubmission(req, route.credentialType);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const records = await this.collectionsService.listIssuedCredentials();
          const scoped = records.filter((record) =>
            equalsIgnoreCase(record.tenantId, route.tenantId) &&
            equalsIgnoreCase(record.jurisdiction, route.jurisdiction) &&
            equalsIgnoreCase(record.sector, route.sector) &&
            equalsIgnoreCase(record.credentialType, route.credentialType)
          );

          const dedup = new Map<string, {
            issuedCredentialRecordId: string;
            credentialId: string;
            credentialType: string;
            subjectId: string;
            issuerId: string;
            legalName?: string;
            taxId?: string;
            taxIdHash?: string;
            organizationDid?: string;
            credential: JsonObject;
          }>();

          submission.queries.forEach((query) => {
            scoped.forEach((record) => {
              const match = matchesQuery(record, query);
              if (!match.matched) return;
              if (dedup.has(record.id)) return;
              dedup.set(record.id, {
                issuedCredentialRecordId: record.id,
                credentialId: record.credentialId,
                credentialType: record.credentialType,
                subjectId: record.subjectId,
                issuerId: record.issuerId,
                ...(match.legalName ? { legalName: match.legalName } : {}),
                ...(match.taxId ? { taxId: match.taxId } : {}),
                ...(match.taxIdHash ? { taxIdHash: match.taxIdHash } : {}),
                ...(match.organizationDid ? { organizationDid: match.organizationDid } : {}),
                credential: record.credential,
              });
            });
          });

          this.jobStore.markSucceeded(submission.thid, {
            matchedCount: dedup.size,
            items: Array.from(dedup.values()),
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Credential _search job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildCredentialSearchResponseLocation(route),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid credential search payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
