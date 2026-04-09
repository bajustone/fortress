import type { DatabaseAdapter } from '../adapters/database';
import type { PasswordPolicyConfig } from './auth/password-policy';
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
    secret: string | string[];
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
  plugins?: readonly FortressPlugin[];
  /** Auth-cookie naming and attributes used by `fortress.handleRequest` and framework adapters. */
  cookies?: CookieConfig;
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
  const isProd = typeof process !== 'undefined' && process.env?.NODE_ENV === 'production';
  const secure = config?.secure ?? isProd;
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
