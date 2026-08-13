type JsonObject = Record<string, unknown>;

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function asObjectList(value: unknown): JsonObject[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => asObject(entry))
    .filter(Boolean) as JsonObject[];
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => asNonEmptyString(entry))
    .filter(Boolean);
}

function pushError(errors: string[], message: string): void {
  if (message) errors.push(message);
}

function readEntityDid(value: unknown): string {
  const direct = asNonEmptyString(value);
  if (direct) return direct;
  const objectValue = asObject(value);
  if (!objectValue) return '';
  return asNonEmptyString(objectValue['@id'])
    || asNonEmptyString(objectValue.id)
    || asNonEmptyString(objectValue.reference);
}

function readConstraintLeftOperand(constraint: JsonObject): string {
  return asNonEmptyString(constraint.leftOperand)
    || asNonEmptyString(constraint['odrl:leftOperand'])
    || asNonEmptyString(constraint['ovc:leftOperand']);
}

function readConstraintRightOperand(constraint: JsonObject): string {
  return asNonEmptyString(constraint.rightOperand)
    || asNonEmptyString(constraint['odrl:rightOperand'])
    || asNonEmptyString(constraint['ovc:rightOperand']);
}

function collectPermissions(resource: JsonObject): JsonObject[] {
  return asObjectList(resource.permission);
}

function collectConstraints(permission: JsonObject): JsonObject[] {
  return [
    ...asObjectList(permission.constraint),
    ...asObjectList(permission['odrl:constraint']),
    ...asObjectList(permission['ovc:constraint']),
  ];
}

function findTopLevelAssignee(resource: JsonObject): string {
  return readEntityDid(resource.assignee);
}

function findPermissionAssignee(permission: JsonObject): string {
  return readEntityDid(permission.assignee);
}

function normalizeLeftOperand(value: string): string {
  return value.replace(/\s+/g, '');
}

function isDidWeb(value: string): boolean {
  return value.toLowerCase().startsWith('did:web:');
}

const OCCUPATION_LEFT_OPERAND = '$.credentialSubject.hasOccupation.occupationalCategory';
const LEGACY_OCCUPATION_LEFT_OPERAND = '$.credentialSubject.hasOccupation.identifier';

function isOccupationLeftOperand(value: string): boolean {
  return value === OCCUPATION_LEFT_OPERAND || value === LEGACY_OCCUPATION_LEFT_OPERAND;
}

export function summarizeDelegationPolicyResource(resource: JsonObject): {
  policyId: string;
  assigneeDid: string;
  roleIdentifier: string;
} {
  const permissions = collectPermissions(resource);
  const policyId = asNonEmptyString(resource.uid)
    || asNonEmptyString(resource.id)
    || '';
  const topLevelAssignee = findTopLevelAssignee(resource);

  let assigneeDid = topLevelAssignee;
  let roleIdentifier = '';
  for (const permission of permissions) {
    if (!assigneeDid) {
      assigneeDid = findPermissionAssignee(permission);
    }
    const constraints = collectConstraints(permission);
    for (const constraint of constraints) {
      const leftOperand = normalizeLeftOperand(readConstraintLeftOperand(constraint));
      if (!roleIdentifier && isOccupationLeftOperand(leftOperand)) {
        roleIdentifier = readConstraintRightOperand(constraint);
      }
    }
  }

  return {
    policyId,
    assigneeDid,
    roleIdentifier,
  };
}

export function validateDelegationPolicyResource(
  resource: JsonObject,
  path = 'body.data[].resource',
): string[] {
  const errors: string[] = [];

  if (!Array.isArray(resource['@context'])) {
    pushError(errors, `${path}.@context should include ODRL context(s).`);
  }

  const permissions = collectPermissions(resource);
  if (!permissions.length) {
    pushError(errors, `${path}.permission must be a non-empty array.`);
    return errors;
  }

  let assigneeDid = findTopLevelAssignee(resource);
  const normalizedLeftOperands = new Set<string>();
  let hasRoleRightOperand = false;

  for (const [index, permission] of permissions.entries()) {
    if (!assigneeDid) {
      assigneeDid = findPermissionAssignee(permission);
    }

    const actions = [
      asNonEmptyString(permission.action),
      ...asStringList(permission['odrl:action']),
    ].filter(Boolean);
    if (!actions.length && !asObject(permission.action)) {
      pushError(errors, `${path}.permission[${index}].action is required.`);
    }

    const constraints = collectConstraints(permission);
    for (const constraint of constraints) {
      const normalized = normalizeLeftOperand(readConstraintLeftOperand(constraint));
      if (!normalized) continue;
      normalizedLeftOperands.add(normalized);
      if (isOccupationLeftOperand(normalized)) {
        const rightOperand = readConstraintRightOperand(constraint);
        hasRoleRightOperand = Boolean(rightOperand);
      }
    }
  }

  if (!assigneeDid) {
    pushError(errors, `${path}.assignee (or permission[].assignee) with DID is required.`);
  } else {
    if (!isDidWeb(assigneeDid)) {
      pushError(errors, `${path}.assignee must be did:web.`);
    }
    if (!assigneeDid.includes(':delegate:')) {
      pushError(errors, `${path}.assignee DID should include ":delegate:" segment.`);
    }
  }

  if (!normalizedLeftOperands.has('$.credentialSubject.id')) {
    pushError(
      errors,
      `${path} must constrain $.credentialSubject.id (leftOperand / ovc:leftOperand).`,
    );
  }

  if (!normalizedLeftOperands.has(OCCUPATION_LEFT_OPERAND)
    && !normalizedLeftOperands.has(LEGACY_OCCUPATION_LEFT_OPERAND)) {
    pushError(
      errors,
      `${path} must constrain ${OCCUPATION_LEFT_OPERAND} (ISCO-08 occupation).`,
    );
  } else if (!hasRoleRightOperand) {
    pushError(
      errors,
      `${path} must provide an ISCO-08 rightOperand for ${OCCUPATION_LEFT_OPERAND} (e.g. ISCO-08|1120).`,
    );
  }

  return errors;
}

export function assertValidDelegationPolicyResource(
  resource: JsonObject,
  path = 'body.data[].resource',
): void {
  const errors = validateDelegationPolicyResource(resource, path);
  if (!errors.length) return;
  throw new Error(`Invalid ODRL delegation policy payload: ${errors.join(' ')}`);
}
