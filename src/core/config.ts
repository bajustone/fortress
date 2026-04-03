import type { DatabaseAdapter } from '../adapters/database';
import type { FortressPlugin } from './plugin';

export interface PasswordHasher {
  hash: (password: string) => Promise<string>;
  verify: (hash: string, password: string) => Promise<boolean>;
}

export interface FortressConfig {
  jwt: {
    secret: string | string[];
    issuer?: string;
    accessTokenExpirySeconds?: number;
    refreshTokenExpirySeconds?: number;
  };
  rbac?: {
    evaluationMode?: 'allow-only' | 'deny-overrides';
    resourceFile?: string;
  };
  database: DatabaseAdapter;
  passwordHasher?: PasswordHasher;
  plugins?: FortressPlugin[];
}

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
