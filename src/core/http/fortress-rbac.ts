/**
 * Default-deny RBAC for fortress-managed routes.
 *
 * Run by `fortress.handleRequest` *after* an endpoint has been matched. Uses
 * the endpoint's `meta.security` and `meta.permission` declarations to
 * decide whether the caller is allowed through:
 *
 * - `security: 'none'` or `security: 'basic'` → public, allow.
 * - `meta.permission` set → require auth + IAM `checkPermission`.
 * - `security: 'bearer'` (no permission) → require auth, no IAM check.
 * - Anything else → deny (security-first default).
 *
 * Adapter-side route maps (Hono/Express user-route protection) live in
 * each adapter — this module only handles fortress's own routes.
 */

import type { EndpointDefinition } from '../endpoint';
import type { RuntimeFortressPlugin } from '../plugin';
import type { Subject } from '../types';
import { Errors } from '../errors';

const FORTRESS_CORE_PREFIXES = ['/iam/'];
const FORTRESS_AUTH_PROTECTED = ['/auth/impersonate', '/auth/users'];
const PLUGIN_PREFIX_REGEX = /^(\/[^/]+\/)/;

/**
 * Compute the unique top-level path prefixes (e.g. `/oauth/`) used by all
 * registered plugin routes. Adapters call this once at startup to feed
 * {@link isFortressPath}.
 */
export function getPluginPathPrefixes(plugins: readonly RuntimeFortressPlugin[]): string[] {
  const prefixes = new Set<string>();
  for (const plugin of plugins) {
    if (!plugin.routes)
      continue;
    for (const route of Object.values(plugin.routes) as EndpointDefinition[]) {
      const match = PLUGIN_PREFIX_REGEX.exec(route.path);
      if (match) {
        const prefix = match[1];
        if (prefix === undefined)
          throw Errors.badRequest(`Plugin route '${route.path}' has no path prefix`);
        prefixes.add(prefix);
      }
    }
  }
  return [...prefixes];
}

/**
 * Check whether a path is owned by fortress (core IAM, sensitive auth, or
 * any plugin-registered prefix). Fortress-owned paths are subject to
 * default-deny when no permission mapping resolves.
 */
export function isFortressPath(
  path: string,
  pluginPathPrefixes: readonly string[],
): boolean {
  if (FORTRESS_CORE_PREFIXES.some(p => path.startsWith(p)))
    return true;
  if (FORTRESS_AUTH_PROTECTED.some(p => path === p || path.startsWith(`${p}/`)))
    return true;
  if (pluginPathPrefixes.some(p => path.startsWith(p)))
    return true;
  return false;
}

/**
 * Per-call dependencies for {@link enforceFortressPermission}.
 */
export interface PermissionEnforcement {
  /** IAM check, typically `fortress.iam.checkPermission`. */
  checkPermission: (
    subject: Subject,
    resource: string,
    action: string,
    scopes?: string[] | null,
  ) => Promise<boolean>;
}

/**
 * Enforce fortress's default-deny policy for an already-matched endpoint.
 *
 * - Public endpoints (`security: 'none'` / `'basic'`) pass through.
 * - Endpoints with `meta.permission` require an authenticated subject and a
 *   passing `checkPermission` call — otherwise throws `UNAUTHORIZED` /
 *   `FORBIDDEN`.
 * - Bearer-only endpoints require an authenticated subject but skip IAM.
 * - Endpoints with no security metadata are denied.
 *
 * The caller (typically `fortress.handleRequest`) is responsible for first
 * resolving the request principal (either via a plugin's `resolvePrincipal`
 * or the JWT fallback) and supplying the resulting `subject`.
 */
export async function enforceFortressPermission(
  endpoint: EndpointDefinition,
  subject: Subject | undefined,
  enforcement: PermissionEnforcement,
  scopes?: string[] | null,
): Promise<void> {
  const security = endpoint.meta?.security;

  // Explicit IAM permission requirements always win over transport metadata.
  // A route cannot become public merely because it also accepts Basic auth.
  if (endpoint.meta?.permission) {
    if (!subject)
      throw Errors.unauthorized('Not authenticated');
    const allowed = await enforcement.checkPermission(
      subject,
      endpoint.meta.permission.resource,
      endpoint.meta.permission.action,
      scopes,
    );
    if (!allowed) {
      throw Errors.forbidden('Insufficient permissions', {
        // Report only the route's declared requirement. Do not include the
        // caller's roles, grants, conditions, or other policy internals.
        details: {
          requiredPermission: `${endpoint.meta.permission.resource}:${endpoint.meta.permission.action}`,
        },
      });
    }
    return;
  }

  // Public/self-authenticated routes without an IAM requirement.
  if (security?.includes('none') || security?.includes('basic'))
    return;

  // Bearer-only routes — auth required, no IAM check
  if (security?.includes('bearer')) {
    if (!subject)
      throw Errors.unauthorized('Not authenticated');
    return;
  }

  // No security metadata at all → default deny
  throw Errors.forbidden('No permission mapping for this route');
}
