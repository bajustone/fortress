import type { Permission, PermissionCondition, PermissionContext } from '../types';

const VARIABLE_PATTERN = /^\$\{(.+)\}$/;

export type EvaluationMode = 'allow-only' | 'deny-overrides';

/**
 * Evaluate a set of permissions against a resource+action request.
 *
 * - 'allow-only': if any ALLOW matches → allow, otherwise deny
 * - 'deny-overrides' (AWS-style):
 *   1. Collect all matching permissions
 *   2. If any DENY matches → deny (overrides everything)
 *   3. If any ALLOW matches → allow
 *   4. Otherwise → deny (implicit)
 */
export function evaluatePermissions(
  permissions: Permission[],
  resource: string,
  action: string,
  mode: EvaluationMode,
  context?: PermissionContext,
): boolean {
  const matching = permissions.filter(p =>
    matchesResourceAction(p, resource, action),
  );

  if (matching.length === 0)
    return false;

  // Evaluate conditions on each matching permission
  const evaluated = matching.map(p => ({
    effect: p.effect,
    conditionsMet: !p.conditions?.length || evaluateConditions(p.conditions, context),
  }));

  // Only consider permissions where conditions are met
  const effective = evaluated.filter(e => e.conditionsMet);

  if (effective.length === 0)
    return false;

  if (mode === 'deny-overrides') {
    // Any DENY → deny (overrides everything)
    if (effective.some(e => e.effect === 'DENY'))
      return false;
    // Any ALLOW → allow
    return effective.some(e => e.effect === 'ALLOW');
  }

  // allow-only: any ALLOW → allow
  return effective.some(e => e.effect === 'ALLOW');
}

function matchesResourceAction(permission: Permission, resource: string, action: string): boolean {
  return permission.resource === resource && permission.action === action;
}

/**
 * Evaluate all conditions. All conditions must be true (AND logic).
 */
export function evaluateConditions(
  conditions: PermissionCondition[],
  context?: PermissionContext,
): boolean {
  if (!context)
    return false;

  return conditions.every(condition => evaluateCondition(condition, context));
}

function evaluateCondition(condition: PermissionCondition, context: PermissionContext): boolean {
  const actualValue = resolveFieldValue(condition.field, context);
  const expectedValue = resolveExpectedValue(condition.value, context);

  switch (condition.operator) {
    case 'eq':
      return String(actualValue) === String(expectedValue);
    case 'neq':
      return String(actualValue) !== String(expectedValue);
    case 'in': {
      const list = Array.isArray(expectedValue) ? expectedValue : [expectedValue];
      return list.map(String).includes(String(actualValue));
    }
    case 'startsWith':
      return String(actualValue).startsWith(String(expectedValue));
    default:
      return false;
  }
}

/**
 * Resolve a dotted field path from the permission context.
 * e.g., "resource.ownerId" → context.resource.ownerId
 */
function resolveFieldValue(field: string, context: PermissionContext): unknown {
  const [section, ...rest] = field.split('.');
  const key = rest.join('.');

  let source: Record<string, unknown> | undefined;
  if (section === 'resource')
    source = context.resource;
  else if (section === 'request')
    source = context.request;
  else if (section === 'user')
    source = context.user;

  if (!source || !key)
    return undefined;

  return getNestedValue(source, key);
}

/**
 * Resolve expected value — supports ${variable} template syntax.
 * e.g., "${user.id}" resolves to context.user.id
 */
function resolveExpectedValue(
  value: string | string[],
  context: PermissionContext,
): unknown {
  if (Array.isArray(value)) {
    return value.map(v => resolveSingleValue(v, context));
  }
  return resolveSingleValue(value, context);
}

function resolveSingleValue(value: string, context: PermissionContext): unknown {
  const match = VARIABLE_PATTERN.exec(value);
  if (!match)
    return value;

  // It's a variable reference like ${user.id}
  return resolveFieldValue(match[1], context);
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object')
      return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}
