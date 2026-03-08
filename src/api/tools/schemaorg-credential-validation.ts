type JsonObject = Record<string, unknown>;

const SUPPORTED_SUBJECT_TYPES = new Set([
  'Organization',
  'Person',
  'https://schema.org/Organization',
  'https://schema.org/Person',
  'schema:Organization',
  'schema:Person',
]);

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeTypeToken(value: unknown): string {
  return asNonEmptyString(value);
}

function includesSupportedType(rawType: unknown): boolean {
  if (typeof rawType === 'string') {
    return SUPPORTED_SUBJECT_TYPES.has(normalizeTypeToken(rawType));
  }
  if (!Array.isArray(rawType)) return false;
  return rawType.some((entry) => SUPPORTED_SUBJECT_TYPES.has(normalizeTypeToken(entry)));
}

function validateOrganizationRef(value: unknown, path: string, errors: string[]): void {
  const obj = asObject(value);
  if (!obj) {
    errors.push(`${path} must be an object when provided.`);
    return;
  }
  if ('@type' in obj && !includesSupportedType(obj['@type'])) {
    errors.push(`${path}.@type must be Organization when provided.`);
  }
}

function validateSubjectObject(subject: JsonObject, path: string, errors: string[]): void {
  if (!includesSupportedType(subject['@type'])) {
    errors.push(`${path}.@type must include Person or Organization (schema.org).`);
  }
  if ('memberOf' in subject) {
    validateOrganizationRef(subject.memberOf, `${path}.memberOf`, errors);
  }
  if ('affiliation' in subject) {
    validateOrganizationRef(subject.affiliation, `${path}.affiliation`, errors);
  }
}

function validateCredentialSubject(subjectRaw: unknown, path: string, errors: string[]): void {
  if (Array.isArray(subjectRaw)) {
    if (!subjectRaw.length) {
      errors.push(`${path} must not be an empty array.`);
      return;
    }
    subjectRaw.forEach((entry, index) => {
      const itemPath = `${path}[${index}]`;
      const subject = asObject(entry);
      if (!subject) {
        errors.push(`${itemPath} must be an object.`);
        return;
      }
      validateSubjectObject(subject, itemPath, errors);
    });
    return;
  }

  const subject = asObject(subjectRaw);
  if (!subject) {
    errors.push(`${path} must be an object or an array of objects.`);
    return;
  }
  validateSubjectObject(subject, path, errors);
}

export function validateSchemaOrgCredential(credential: JsonObject, path = 'body.credential'): string[] {
  const errors: string[] = [];
  validateCredentialSubject(credential.credentialSubject, `${path}.credentialSubject`, errors);
  return errors;
}

export function assertSchemaOrgCredential(credential: JsonObject, path = 'body.credential'): void {
  const errors = validateSchemaOrgCredential(credential, path);
  if (!errors.length) return;
  throw new Error(`Invalid credentialSubject schema.org payload: ${errors.join(' ')}`);
}
