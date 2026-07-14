/**
 * SvelteKit adapter types. Public handle/action signatures are anchored to
 * the real optional `@sveltejs/kit` peer so strict-mode consumers can assign
 * them without casts. Small request/cookie subsets remain for framework-free
 * helpers and tests; every real RequestEvent structurally satisfies them.
 */

import type { Handle, RequestEvent } from '@sveltejs/kit';
import type { DatabaseAdapter } from '../adapters/database';
import type { Subject, TokenClaims } from '../core/types';

// ── Minimal SvelteKit type subset ───────────────────────────────────

/** Cookie options accepted by SvelteKit's `event.cookies.set` / `delete`. */
export interface SvelteKitCookieOptions {
  path?: string;
  domain?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none' | boolean;
  maxAge?: number;
  expires?: Date;
}

/** SvelteKit `Cookies` API surface used by the fortress adapter. */
export interface SvelteKitCookies {
  get: (name: string) => string | undefined;
  set: (name: string, value: string, opts: SvelteKitCookieOptions & { path: string }) => void;
  delete: (name: string, opts: SvelteKitCookieOptions & { path: string }) => void;
  getAll?: () => { name: string; value: string }[];
}

/**
 * Minimal `RequestEvent` shape consumed by the adapter. Compatible by
 * structural typing with `@sveltejs/kit`'s real `RequestEvent`. The
 * `locals.fortress` field comes from the consumer augmenting `App.Locals`
 * with {@link FortressLocals}.
 *
 * `TLocals` is constrained to `object` (not `Record<string, unknown>`) so
 * the {@link FortressLocals} interface — which only declares the
 * `fortress` key without an index signature — satisfies it.
 */
export interface SvelteKitRequestEvent<TLocals extends object = object> {
  request: Request;
  url: URL;
  cookies: SvelteKitCookies;
  locals: TLocals;
  params: Record<string, string>;
  setHeaders?: (headers: Record<string, string>) => void;
}

/** Exact SvelteKit `Handle` hook signature, including the resolve options overload. */
export type SvelteKitHandle = Handle;

/** SvelteKit-compatible form action signature with a narrowed result type. */
export type SvelteKitAction<TResult = unknown> = (
  event: RequestEvent,
) => Promise<TResult> | TResult;

// ── Fortress-specific types ─────────────────────────────────────────

/**
 * Shape of `event.locals.fortress` after the fortress handle hook runs.
 *
 * Consumers augment SvelteKit's `App.Locals` with this interface so server
 * load functions and `+server.ts` handlers can read the auth context with
 * full type safety.
 *
 * @example
 * ```ts
 * // src/app.d.ts
 * import type { FortressLocals } from '@bajustone/fortress/sveltekit';
 *
 * declare global {
 *   namespace App {
 *     interface Locals extends FortressLocals {}
 *   }
 * }
 * ```
 */
export interface FortressLocals {
  fortress: {
    /**
     * Resolved principal for the current request. Set for every
     * authenticated request regardless of credential type (JWT, api-key,
     * future OAuth client_credentials, mTLS). Check `subject.type` to
     * distinguish `USER` / `SERVICE_ACCOUNT` / `GROUP`.
     */
    subject?: Subject;
    /**
     * Convenience alias for `subject.id` — set **only** when
     * `subject.type === 'USER'`. Non-USER principals (e.g. a service
     * account via api-key) leave this undefined; fall back to `subject`.
     */
    userId?: string;
    /**
     * Verified JWT claims, if the request was authenticated via a JWT.
     * Plugin-resolved principals (api-key, etc.) do not populate this.
     */
    claims?: TokenClaims;
    /** Credential-level narrowing scopes (for example API-key scopes). */
    scopes?: string[] | null;
    /** Per-request DB adapter with plugin `wrapAdapter` chain applied. */
    db?: DatabaseAdapter;
    /** Lazily compute a model-scoped DB adapter (data-isolation aware). */
    getScopedDb?: (model: string) => Promise<DatabaseAdapter>;
  };
}

/** Options accepted by {@link createSvelteKitHandle}. */
export interface SvelteKitAdapterOptions {
  /**
   * Path prefix the fortress routes live under (defaults to `/api`).
   *
   * Example: with `basePath: '/api'`, the request `/api/auth/login` is
   * internally rewritten to `/auth/login` before being passed to
   * `fortress.handleRequest`. Plugin and IAM routes follow the same prefix.
   */
  basePath?: string;
  /**
   * Optional declarative route → `(resource, action)` map for user-owned
   * routes. Used by the user-route RBAC pass to call
   * `fortress.iam.checkPermission` for non-fortress paths. Format:
   * `'GET /api/users': { resource: 'user', action: 'list' }`.
   */
  routeMap?: Record<string, { resource: string; action: string }>;
  /** Behavior for user-owned routes absent from routeMap (default: allow). */
  unmappedRoutes?: 'allow' | 'deny';
  /**
   * Paths the user-route RBAC pass should skip entirely (supports `*`).
   * Example: `['/api/health', '/api/public/*']`.
   */
  skipPaths?: string[];
}
