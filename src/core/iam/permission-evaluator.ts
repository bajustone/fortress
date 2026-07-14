import type { Permission, PermissionCondition, PermissionContext } from '../types';

const VARIABLE_PATTERN = /^\$\{(.+)\}$/;

export type EvaluationMode = 'allow-only' | 'deny-overrides';

/**
 * Check whether a credential-level scope set allows the requested
 * resource/action. `null`/`undefined` means the credential is unscoped and
 * inherits the subject's full IAM permissions; an empty array allows nothing.
 */
export function withinCredentialScope(
  scopes: string[] | null | undefined,
  resource: string,
  action: string,
): boolean {
  if (scopes == null)
    return true;
  return scopes.some(scope =>
    scope === '*'
    || scope === `${resource}:*`
    || scope === `${resource}:${action}`,
  );
}

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
  return matchesWildcard(permission.resource, resource)
    && matchesWildcard(permission.action, action);
}

function matchesWildcard(pattern: string, value: string): boolean {
  if (pattern === '*')
    return true;
  return pattern === value;
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
  // Missing fields/references are never comparable. In particular, `neq`
  // must not turn an unresolved value into an accidental grant.
  if (
    actualValue === undefined
    || expectedValue === undefined
    || (Array.isArray(expectedValue) && expectedValue.includes(undefined))
  ) {
    return false;
  }

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
 * Resolve expected value — supports both ${variable} template syntax
 * and structured ConditionRef objects ({ ref: "user.id" }).
 */
function resolveExpectedValue(
  value: string | string[] | { ref: string } | { ref: string }[],
  context: PermissionContext,
): unknown {
  if (Array.isArray(value)) {
    return value.map((v) => {
      if (typeof v === 'object' && 'ref' in v)
        return resolveFieldValue(v.ref, context);
      return resolveSingleValue(v, context);
    });
  }
  if (typeof value === 'object' && 'ref' in value)
    return resolveFieldValue(value.ref, context);
  return resolveSingleValue(value, context);
}

function resolveSingleValue(value: string, context: PermissionContext): unknown {
  const match = VARIABLE_PATTERN.exec(value);
  if (!match)
    return value;

  // It's a variable reference like ${user.id}
  return resolveFieldValue(match[1], context);
}

// L-tier: prototype-pollution-safe key set. Reading `__proto__` /
// `constructor` / `prototype` off an attacker-controlled object would
// either return the prototype chain or let a condition spoof an
// inherited value as a real field. We skip these keys defensively even
// though all currently-known callers feed plain object literals.
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object')
      return undefined;
    if (FORBIDDEN_PROTO_KEYS.has(part))
      return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}
