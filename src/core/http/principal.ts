/**
 * Shared principal resolution for `fortress.handleRequest` and user-route
 * adapters (Hono / Express / SvelteKit).
 *
 * Plugins that register a `resolvePrincipal` capability (e.g. `api-key`) are
 * tried in registration order; the first non-null result wins. If no plugin
 * resolves the request, a JWT bearer token is attempted as a fallback.
 *
 * Two variants are exported:
 *
 * - {@link tryPluginPrincipal} — only walks the plugin chain. Used by
 *   `handle-request.ts`, which needs to decide whether to enforce the JWT
 *   fallback based on the endpoint's `security` metadata.
 * - {@link resolveRequestPrincipal} — plugin chain + non-throwing JWT
 *   fallback. Used by adapter user-route middleware so that API keys and
 *   cookies/bearer tokens authenticate uniformly on *any* route, not just
 *   Fortress-owned routes.
 */

import type { Fortress } from '../fortress';
import type { Subject, TokenClaims } from '../types';

/** Result of a successful principal resolution. */
export interface ResolvedPrincipal {
  subject: Subject;
  claims?: TokenClaims;
  /** Credential-level narrowing scopes (e.g. API-key scopes). null/undefined = unscoped. */
  scopes?: string[] | null;
}

/**
 * Walk the `resolvePrincipal` plugin chain. Returns the first non-null
 * result, or null if every plugin deferred.
 */
export async function tryPluginPrincipal(
  fortress: Fortress,
  request: Request,
): Promise<ResolvedPrincipal | null> {
  const plugins = fortress.config.plugins ?? [];
  for (const plugin of plugins) {
    if (!plugin.resolvePrincipal)
      continue;
    const resolved = await plugin.resolvePrincipal(request, {
      db: fortress.config.database,
      config: fortress.config,
      auth: fortress.auth,
      iam: fortress.iam,
    });
    if (resolved)
      return { subject: resolved.subject, claims: resolved.claims, scopes: resolved.scopes };
  }
  return null;
}

/**
 * Resolve a request principal by trying the plugin chain first, then falling
 * back to the configured JWT bearer token (cookie-first, `Authorization:
 * Bearer` second).
 *
 * Non-throwing: returns `null` if no credential is present **or** the JWT
 * fails verification. Adapter user-route middleware calls this so RBAC can
 * decide how to handle the missing principal (401 for protected routes,
 * anonymous pass for public ones).
 */
export async function resolveRequestPrincipal(
  fortress: Fortress,
  request: Request,
): Promise<ResolvedPrincipal | null> {
  const plugin = await tryPluginPrincipal(fortress, request);
  if (plugin)
    return plugin;

  const token = fortress.extractAccessToken(request);
  if (!token)
    return null;
  try {
    const claims = await fortress.auth.verifyToken(token);
    return {
      subject: { type: claims.subjectType, id: claims.sub },
      claims,
    };
  }
  catch {
    return null;
  }
}
