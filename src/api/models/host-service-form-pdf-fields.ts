/**
 * Canonical AcroForm field names for the signed host-service authorization PDF.
 *
 * TypeScript properties use camelCase. The values are dotted semantic paths so
 * the signed PDF remains self-describing and can be projected into a Service
 * VC without relying on visible labels.
 */
export const HostServiceFormPdfFieldName = {
  formVersion: 'formVersion',
  serviceType: 'serviceType',
  category: 'category',
  url: 'url',
  providerLegalName: 'provider.legalName',
  providerAddressCountry: 'provider.address.addressCountry',
  providerIdentifierAdditionalType: 'provider.identifier.additionalType',
  providerIdentifierValue: 'provider.identifier.value',
  providerTaxID: 'provider.taxID',
  ownerEmail: 'owner.email',
  ownerHasCredentialMaterial: 'owner.hasCredential.material',
} as const;

export type HostServiceFormPdfFieldKey = keyof typeof HostServiceFormPdfFieldName;
export type HostServiceFormPdfFieldNameValue =
  typeof HostServiceFormPdfFieldName[HostServiceFormPdfFieldKey];

/**
 * Raw values extracted from a host-service PDF form.
 *
 * `ownerEmail` is the signed input from which the public VC projection derives
 * `owner.sameAs`. `ownerHasCredentialMaterial` fixes the RFC 9278 identifier of
 * the controller key; later controller actions prove possession of its private
 * key.
 */
export interface HostServiceFormPdfFields {
  formVersion?: string;
  serviceType?: string;
  category?: string;
  url?: string;
  providerLegalName?: string;
  providerAddressCountry?: string;
  providerIdentifierAdditionalType?: string;
  providerIdentifierValue?: string;
  providerTaxID?: string;
  ownerEmail?: string;
  ownerHasCredentialMaterial?: string;
}

export type HostServiceFormPdfFieldValue = string | undefined | null;
export type HostServiceFormPdfFieldMap = Readonly<
  Partial<Record<HostServiceFormPdfFieldNameValue, HostServiceFormPdfFieldValue>>
  & Record<string, HostServiceFormPdfFieldValue>
>;

/** Stable version of the first host-service authorization form contract. */
export const HOST_SERVICE_FORM_VERSION = '1.0' as const;

/** Fields required independently of the provider identifier alternative. */
export const HostServiceFormPdfRequiredFieldNames = Object.freeze([
  HostServiceFormPdfFieldName.formVersion,
  HostServiceFormPdfFieldName.serviceType,
  HostServiceFormPdfFieldName.category,
  HostServiceFormPdfFieldName.url,
  HostServiceFormPdfFieldName.providerLegalName,
  HostServiceFormPdfFieldName.providerAddressCountry,
  HostServiceFormPdfFieldName.ownerEmail,
  HostServiceFormPdfFieldName.ownerHasCredentialMaterial,
] as const);
