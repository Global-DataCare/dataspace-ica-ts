import { randomUUID } from 'node:crypto';
import type { VerifiableCredentialV2 } from 'gdc-common-utils-ts/models/verifiable-credential';
import type { DidcommAttachment, VerifyBundleResponse, VerifyRouteContext } from '../types.ts';
import { convertCredentialToVcJwt } from './ica-identity.ts';

function isVerifiableCredential(value: unknown): value is VerifiableCredentialV2 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  const types = Array.isArray(candidate.type) ? candidate.type : [];
  return types.includes('VerifiableCredential');
}

export function buildVcJwtAttachments(
  route: VerifyRouteContext,
  body: VerifyBundleResponse,
  issuerDidInput?: string,
): DidcommAttachment[] {
  const attachments: DidcommAttachment[] = [];

  body.data.forEach((entry, index) => {
    if (!isVerifiableCredential(entry.resource)) return;
    const vcJwt = convertCredentialToVcJwt(entry.resource, route, issuerDidInput);
    attachments.push({
      id: randomUUID(),
      format: 'vc+jwt',
      media_type: 'application/vc+jwt',
      filename: `${entry.type || 'credential'}-${index + 1}.jwt`,
      data: {
        json: {
          format: 'vc+jwt',
          credentialId: String(entry.resource.id || ''),
          jwt: vcJwt,
        },
      },
    });
  });

  return attachments;
}
