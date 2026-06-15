import type { DatabaseAdapter } from '../adapters/database';
import type { JwtKeyMaterial } from './auth/jwt';
import type { PasswordPolicyConfig } from './auth/password-policy';
import type { EndpointDefinition } from './endpoint';
import type { CsrfConfig } from './http/csrf';
import type { FortressLogger } from './observability/logger';
import type { TelemetryProvider } from './observability/types';
import type { FortressPlugin } from './plugin';

/** Pluggable password hashing contract — implement to swap fortress's default Argon2id WASM hasher. */
export interface PasswordHasher {
  hash: (password: string) => Promise<string>;
  verify: (hash: string, password: string) => Promise<boolean>;
}

/**
 * Cookie configuration consumed by `fortress.handleRequest` and any framework
 * adapter that wants to serialize auth tokens to `Set-Cookie` headers.
 *
 * Defaults are production-safe: `__Host-` prefixed names, `httpOnly`,
 * `secure`, `sameSite: 'lax'`, `path: '/'`. In non-production environments
 * the `__Host-` prefix is dropped and `secure` is disabled so localhost
 * over HTTP works during development.
 */
export interface CookieConfig {
  /** Override the access-token cookie name. Defaults: `__Host-fortress_access` (prod) / `fortress_access` (dev). */
  accessName?: string;
  /** Override the refresh-token cookie name. Defaults: `__Host-fortress_refresh` (prod) / `fortress_refresh` (dev). */
  refreshName?: string;
  /** SameSite attribute. Default: `'lax'`. */
  sameSite?: 'lax' | 'strict' | 'none';
  /** Force the `Secure` attribute on or off. Default: `true` in production, `false` otherwise. */
  secure?: boolean;
  /** Optional `Domain` attribute. Defaults to host-only when omitted. */
  domain?: string;
  /** `Path` attribute. Default: `'/'`. */
  path?: string;
}

/** Top-level fortress configuration accepted by {@link createFortress}. */
export interface FortressConfig {
  jwt: {
    /**
     * Signing/verification key material. Today: an HS256 shared secret
     * (string) or a rotation array of shared secrets (first signs, all
     * verify). See {@link JwtKeyMaterial} for the planned expansion to
     * asymmetric keys / JWKS.
     */
    key: JwtKeyMaterial;
    issuer?: string;
    accessTokenExpirySeconds?: number;
    refreshTokenExpirySeconds?: number;
    validateRefreshFingerprint?: boolean | 'warn';
  };
  rbac?: {
    evaluationMode?: 'allow-only' | 'deny-overrides';
    resourceFile?: string;
    cache?: {
      ttlSeconds?: number;
      maxEntries?: number;
    };
  };
  database: DatabaseAdapter;
  passwordHasher?: PasswordHasher;
  passwordPolicy?: PasswordPolicyConfig;
  /**
   * Impersonation hardening (RFC 8693 `act` tokens). All fields optional;
   * defaults to a 1-hour ceiling on caller-supplied `expirySeconds`.
   */
  impersonation?: {
    /**
     * Hard ceiling on the impersonation access-token lifetime in seconds.
     * `auth.impersonate({ expirySeconds })` is clamped to this. Default: 3600.
     */
    maxTtlSeconds?: number;
  };
  plugins?: readonly FortressPlugin[];
  /**
   * Host-application endpoint definitions to register with the manifest,
   * OpenAPI generation, and `protect()` / adapter `protectedRoute()` helpers
   * without authoring a one-field plugin. Equivalent to passing a
   * `FortressPlugin` whose only field is `routes` — fortress synthesizes
   * exactly that plugin under the reserved name `__host`.
   *
   * Top-level `routes` are metadata-only: they do not add `fortress.call.*`
   * entries because no handler methods are registered. If you need typed
   * in-process callables for custom routes, declare a real plugin with both
   * `routes` and matching `methods`.
   *
   * Keyed by handler name, matching {@link FortressPlugin.routes}:
   *
   * ```ts
   * createFortress({
   *   database, jwt, cookies,
   *   routes: appEndpoints,
   * });
   * ```
   *
   * The name `__host` is reserved — declaring a plugin called `__host`
   * alongside `routes` is a configuration error.
   */
  routes?: Record<string, EndpointDefinition>;
  /** Auth-cookie naming and attributes used by `fortress.handleRequest` and framework adapters. */
  cookies?: CookieConfig;
  /**
   * Pipeline CSRF protection (H5). Defaults to `{ enabled: true }`.
   * Bearer/API-key requests are exempt automatically — only cookie-auth
   * traffic is checked. See {@link CsrfConfig}.
   */
  csrf?: CsrfConfig;
  /**
   * Optional pluggable logger. Accepts any object that conforms structurally
   * to {@link FortressLogger} — a `pino()` instance, Fastify's `app.log`,
   * or a hand-rolled `console` wrapper. Defaults to a silent no-op so
   * Fortress never writes to stderr unless the caller opts in.
   */
  logger?: FortressLogger;
  /**
   * Optional telemetry provider (tracer + meter). Wire this to the
   * OpenTelemetry adapter with `createOtelTelemetry` from the
   * `@bajustone/fortress/otel` sub-path, or provide any custom
   * implementation. Defaults to a zero-alloc no-op provider.
   */
  observability?: TelemetryProvider;
}

/** Cookie attributes resolved against the runtime environment (NODE_ENV-aware). */
export interface ResolvedCookieConfig {
  accessName: string;
  refreshName: string;
  sameSite: 'lax' | 'strict' | 'none';
  secure: boolean;
  domain?: string;
  path: string;
}

/**
 * Resolve a {@link CookieConfig} against `NODE_ENV`. In production, defaults
 * to `__Host-` prefixed names, `secure: true`, and `sameSite: 'lax'`. In dev,
 * drops the `__Host-` prefix (which requires `Secure` per spec) and disables
 * `secure` so localhost over HTTP works.
 */
export function resolveCookieConfig(config?: CookieConfig): ResolvedCookieConfig {
  // P3.7: default to `Secure` unless the caller explicitly opts out. Many
  // production runtimes do not set NODE_ENV to 'production' (containers,
  // serverless, Kubernetes Jobs), so falling back to NODE_ENV would leave
  // cookies unprotected. Local HTTP development must now opt out
  // explicitly via `cookies: { secure: false }`.
  const secure = config?.secure ?? true;
  // __Host- prefix requires Secure + Path=/ + no Domain (RFC 6265bis).
  const canHostPrefix = secure && !config?.domain && (config?.path ?? '/') === '/';
  const defaultAccess = canHostPrefix ? '__Host-fortress_access' : 'fortress_access';
  const defaultRefresh = canHostPrefix ? '__Host-fortress_refresh' : 'fortress_refresh';

  return {
    accessName: config?.accessName ?? defaultAccess,
    refreshName: config?.refreshName ?? defaultRefresh,
    sameSite: config?.sameSite ?? 'lax',
    secure,
    domain: config?.domain,
    path: config?.path ?? '/',
  };
}

/** Default JWT and RBAC settings applied when {@link FortressConfig} omits them. */
export const DEFAULT_CONFIG = {
  jwt: {
    issuer: 'fortress',
    accessTokenExpirySeconds: 900,
    refreshTokenExpirySeconds: 604800,
  },
  rbac: {
    evaluationMode: 'allow-only' as const,
    resourceFile: './fortress.resources.json',
  },
} as const;
