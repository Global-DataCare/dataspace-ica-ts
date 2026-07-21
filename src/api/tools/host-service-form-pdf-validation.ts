import { UrnPrefixes } from 'gdc-common-utils-ts/constants/urn';
import {
  HOST_SERVICE_FORM_VERSION,
  HostServiceFormPdfFieldName,
  HostServiceFormPdfRequiredFieldNames,
} from '../models/host-service-form-pdf-fields.ts';
import type { HostServiceFormPdfFieldMap } from '../models/host-service-form-pdf-fields.ts';

export interface HostServiceFormPdfValidationResult {
  valid: boolean;
  missingFields: string[];
  errors: string[];
}

const SHA_256_BASE64URL = /^[A-Za-z0-9_-]{43}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const COUNTRY = /^[A-Z]{2}$/;

function fieldValue(fields: HostServiceFormPdfFieldMap, name: string): string {
  const value = fields[name];
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * Validates the security-relevant raw fields extracted from a signed host PDF.
 *
 * This validates document completeness and syntax. Issuance derives the hashed
 * `owner.sameAs` from email. Later signed operations prove possession of the
 * private key identified by `owner.hasCredential.material`.
 */
export function validateHostServiceFormPdfFields(
  fields: HostServiceFormPdfFieldMap,
): HostServiceFormPdfValidationResult {
  const missingFields: string[] = HostServiceFormPdfRequiredFieldNames
    .filter((name) => !fieldValue(fields, name));
  const errors: string[] = [];

  const identifierValue = fieldValue(fields, HostServiceFormPdfFieldName.providerIdentifierValue);
  const taxID = fieldValue(fields, HostServiceFormPdfFieldName.providerTaxID);
  if (!identifierValue && !taxID) {
    missingFields.push(
      `${HostServiceFormPdfFieldName.providerIdentifierValue}|${HostServiceFormPdfFieldName.providerTaxID}`,
    );
  }
  if (identifierValue && !fieldValue(fields, HostServiceFormPdfFieldName.providerIdentifierAdditionalType)) {
    missingFields.push(HostServiceFormPdfFieldName.providerIdentifierAdditionalType);
  }

  const formVersion = fieldValue(fields, HostServiceFormPdfFieldName.formVersion);
  if (formVersion && formVersion !== HOST_SERVICE_FORM_VERSION) {
    errors.push(`Unsupported formVersion: ${formVersion}.`);
  }

  const url = fieldValue(fields, HostServiceFormPdfFieldName.url);
  if (url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/') {
        errors.push('url must be an HTTPS host origin without credentials or path.');
      }
    } catch {
      errors.push('url must be a valid HTTPS host origin.');
    }
  }

  const country = fieldValue(fields, HostServiceFormPdfFieldName.providerAddressCountry).toUpperCase();
  if (country && !COUNTRY.test(country)) {
    errors.push('provider.address.addressCountry must be an ISO 3166-1 alpha-2 code.');
  }

  const email = fieldValue(fields, HostServiceFormPdfFieldName.ownerEmail);
  if (email && !EMAIL.test(email)) {
    errors.push('owner.email must be a valid email address.');
  }

  const material = fieldValue(fields, HostServiceFormPdfFieldName.ownerHasCredentialMaterial);
  const thumbprint = material.startsWith(UrnPrefixes.JwkThumbprintSha256KeyId)
    ? material.slice(UrnPrefixes.JwkThumbprintSha256KeyId.length)
    : '';
  if (material && !SHA_256_BASE64URL.test(thumbprint)) {
    errors.push('owner.hasCredential.material must be an RFC 9278 SHA-256 JWK-thumbprint URN.');
  }

  return {
    valid: missingFields.length === 0 && errors.length === 0,
    missingFields,
    errors,
  };
}
