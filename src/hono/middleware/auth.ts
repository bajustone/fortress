import type { Context, Env, MiddlewareHandler } from 'hono';
import type { DatabaseAdapter } from '../../adapters/database';
import type { Fortress } from '../../core/fortress';
import type { PluginContext } from '../../core/plugin';
import type { Subject, TokenClaims } from '../../core/types';
import { FortressError } from '../../core/errors';
import {
  chainAdapterWrappers,
  collectScopeRules,
  wrapAdapterWithScopeRules,
} from '../../core/plugin-runner';

/**
 * Hono `Variables` slot populated by the fortress auth middleware.
 *
 * `fortressSubject` is the authoritative principal — set for every
 * authenticated request regardless of credential type (JWT, api-key, future
 * OAuth client_credentials, mTLS, ...). `fortressUserId` is a convenience
 * alias populated **only** when the subject is a `USER`; non-USER subjects
 * (e.g. `SERVICE_ACCOUNT` via api-key) leave it `undefined`.
 *
 * Use {@link FortressEnv} to compose this with your own Hono env types
 * without casts.
 */
export interface FortressVariables {
  fortressSubject: Subject;
  fortressUserId?: number;
  fortressClaims?: TokenClaims;
  fortressScopes?: string[] | null;
  fortressDb: DatabaseAdapter;
  fortressGetScopedDb: (model: string) => Promise<DatabaseAdapter>;
}

type ExtractVariables<E> = E extends { Variables: infer V } ? V : Record<string, never>;
type ExtractBindings<E> = E extends { Bindings: infer B } ? B : Record<string, never>;

/**
 * Generic Hono env that composes {@link FortressVariables} with the host
 * app's own env types. Use it directly (`Hono<FortressEnv>`) for a
 * Fortress-only app, or parameterize with your existing env
 * (`Hono<FortressEnv<MyEnv>>`) to add Fortress's variables on top of
 * yours — no `Context<AppEnv>` ↔ `Context<FortressEnv>` casts.
 *
 * @example
 * ```ts
 * interface MyEnv {
 *   Variables: { requestId: string };
 *   Bindings: { DB: D1Database };
 * }
 *
 * const app = new Hono<FortressEnv<MyEnv>>();
 * app.use(createAuthMiddleware(fortress));
 * app.get('/me', (c) => {
 *   const requestId = c.get('requestId');     // host-defined, typed
 *   const subject = getSubject(c);            // fortress-defined, typed
 *   return c.json({ requestId, subject });
 * });
 * ```
 */
export interface FortressEnv<TAppEnv extends Env = Env> {
  Variables: FortressVariables & ExtractVariables<TAppEnv>;
  Bindings: ExtractBindings<TAppEnv>;
}

/** Minimum-viable context shape the typed helpers need — works with any `Context<E>` whose `Variables` include {@link FortressVariables}. */
export type FortressContext<E extends Env = FortressEnv> = Context<E>;

/**
 * Hono middleware that resolves the request principal and populates the
 * Hono context with `fortressSubject`, `fortressUserId` (USER alias),
 * `fortressClaims`, `fortressDb`, and `fortressGetScopedDb`.
 *
 * Principal resolution goes through `fortress.resolvePrincipal`, which
 * tries plugin `resolvePrincipal` hooks (api-key, future OAuth
 * client_credentials, mTLS) first and then falls back to the JWT bearer
 * token (cookie-first, `Authorization: Bearer` second). This means the
 * same Hono app can authenticate browsers (cookies), SPA clients (Bearer),
 * and service accounts (`Authorization: ApiKey ...` or `X-API-Key`)
 * without extra wiring on any route.
 *
 * `fortressDb` has plugin `wrapAdapter` applied (e.g. tenancy schema
 * switching). `fortressGetScopedDb(model)` additionally applies
 * `scopeRules` for the requested model.
 */
export function createAuthMiddleware(
  fortress: Fortress,
): MiddlewareHandler<FortressEnv> {
  // Internally typed as the base FortressEnv. The middleware is variance-safe
  // when mounted on a `Hono<FortressEnv<MyApp>>()` because the augmented env's
  // Variables are a superset of FortressVariables — Hono accepts the wider
  // shape during use().
  return async (c, next) => {
    const resolved = await fortress.resolvePrincipal(c.req.raw);
    if (!resolved) {
      throw new FortressError(
        'UNAUTHORIZED',
        'Missing or invalid credentials',
        401,
      );
    }

    const { subject, claims, scopes } = resolved;
    c.set('fortressSubject', subject);
    if (subject.type === 'USER')
      c.set('fortressUserId', subject.id);
    if (claims)
      c.set('fortressClaims', claims);
    if (scopes !== undefined)
      c.set('fortressScopes', scopes);

    // Build request context for plugin adapter wrappers. The tenant is taken
    // from the verified JWT claim (set by tenancy's enrichTokenClaims), never
    // a client header — so a caller can only reach a tenant they belong to.
    const plugins = fortress.config.plugins ?? [];
    const requestContext: Record<string, unknown> = {
      tenantId: claims?.customClaims?.tenantId,
      ipAddress:
        c.req.header('X-Forwarded-For') ?? c.req.header('X-Real-IP'),
      userAgent: c.req.header('User-Agent'),
    };

    // Chain adapter wrappers (e.g., tenancy schema switching)
    const wrappedAdapter = chainAdapterWrappers(
      plugins,
      fortress.config.database,
      requestContext,
    );
    c.set('fortressDb', wrappedAdapter);

    // Lazy scope rule applicator — routes pick the model they need. Scope
    // rules key off the subject id; for non-USER subjects the plugins that
    // care (data-isolation) typically noop, but the call still works.
    const pluginCtx: PluginContext = {
      db: wrappedAdapter,
      config: fortress.config,
    };
    c.set(
      'fortressGetScopedDb',
      async (model: string): Promise<DatabaseAdapter> => {
        const scopeRule = await collectScopeRules(
          plugins,
          subject.id,
          model,
          pluginCtx,
        );
        if (!scopeRule)
          return wrappedAdapter;
        return wrapAdapterWithScopeRules(wrappedAdapter, scopeRule);
      },
    );

    await next();
  };
}

/**
 * Get the authenticated principal from the Hono context. Works for every
 * subject kind (`USER`, `SERVICE_ACCOUNT`, ...). Generic in the env type
 * so host apps can pass their own `Context<FortressEnv<MyEnv>>` without
 * casts.
 */
export function getSubject<E extends Env = FortressEnv>(c: Context<E>): Subject {
  const subject = c.get('fortressSubject' as never) as Subject | undefined;
  if (!subject) {
    throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
  }
  return subject;
}

/**
 * Get the authenticated user ID from Hono context. Throws 401 if the
 * request was authenticated by a non-USER subject (e.g. a service account
 * via api-key) — use {@link getSubject} for handlers that need to accept
 * any principal.
 */
export function getUserId<E extends Env = FortressEnv>(c: Context<E>): number {
  const subject = c.get('fortressSubject' as never) as Subject | undefined;
  if (!subject || subject.type !== 'USER') {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return subject.id;
}

/**
 * Get the authenticated user's JWT claims from Hono context. Claims are
 * only populated when the request was authenticated via a JWT — api-key
 * principals have no JWT claims. Throws 401 if unavailable.
 *
 * Pass a `TCustomClaims` type parameter to narrow `customClaims` to your
 * deployment's plugin-augmented claim shape (e.g. tenancy adds
 * `tenantId` / `tenantCode`).
 *
 * @example
 * ```ts
 * interface MyClaims { tenantId: number; tenantCode: string }
 * const claims = getClaims<MyClaims>(c);
 * claims.customClaims?.tenantCode; // string | undefined
 * ```
 */
export function getClaims<
  TCustomClaims extends object = Record<string, unknown>,
  E extends Env = FortressEnv,
>(c: Context<E>): TokenClaims & { customClaims?: TCustomClaims } {
  const claims = c.get('fortressClaims' as never) as TokenClaims | undefined;
  if (!claims) {
    throw new FortressError('UNAUTHORIZED', 'No JWT claims on this request', 401);
  }
  return claims as TokenClaims & { customClaims?: TCustomClaims };
}

/**
 * Get the request-scoped database adapter with plugin wrapAdapter applied.
 */
export function getDb<E extends Env = FortressEnv>(c: Context<E>): DatabaseAdapter {
  const db = c.get('fortressDb' as never) as DatabaseAdapter | undefined;
  if (!db) {
    throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
  }
  return db;
}

/**
 * Get a model-scoped database adapter with both wrapAdapter and scopeRules applied.
 */
export function getScopedDb<E extends Env = FortressEnv>(
  c: Context<E>,
  model: string,
): Promise<DatabaseAdapter> {
  const fn = c.get('fortressGetScopedDb' as never) as
    | ((model: string) => Promise<DatabaseAdapter>)
    | undefined;
  if (!fn) {
    throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
  }
  return fn(model);
}
