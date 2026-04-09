import type { DatabaseAdapter } from '../adapters/database';
import type { PasswordPolicyConfig } from './auth/password-policy';
import type { FortressPlugin } from './plugin';

/** Pluggable password hashing contract — implement to swap fortress's default Argon2id WASM hasher. */
export interface PasswordHasher {
  hash: (password: string) => Promise<string>;
  verify: (hash: string, password: string) => Promise<boolean>;
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
