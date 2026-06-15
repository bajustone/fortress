/**
 * Password hashing primitives for fortress.
 *
 * Exports {@link createDefaultHasher}, a WASM-based Argon2id `PasswordHasher`
 * that works across every runtime fortress targets (Bun, Deno, Node, Cloudflare
 * Workers, Vercel Edge). Consumers can drop in a faster native hasher
 * (`@node-rs/argon2`, `Bun.password`) by implementing the `PasswordHasher`
 * contract and passing it to `createFortress({ passwordHasher })`.
 *
 * @module
 */

import { argon2id, argon2Verify } from 'hash-wasm';

export type { PasswordHasher } from '../config';

/**
 * Canonicalize password input before policy checks, breach checks, hashing,
 * and verification. NFKC collapses visually/confusably equivalent Unicode
 * forms (for example full-width ASCII) so users are not locked out by input
 * method differences.
 */
export function normalizePasswordInput(password: string): string {
  return password.normalize('NFKC');
}

/**
 * Default PasswordHasher using WASM-based Argon2id.
 * Works across all runtimes (Bun, Deno, Node, edge).
 * Consumers can swap for @node-rs/argon2 or Bun.password for native speed.
 */
export function createDefaultHasher(): {
  hash: (password: string) => Promise<string>;
  verify: (hash: string, password: string) => Promise<boolean>;
} {
  return {
    async hash(password: string): Promise<string> {
      const normalizedPassword = normalizePasswordInput(password);
      const salt = new Uint8Array(16);
      crypto.getRandomValues(salt);

      return argon2id({
        password: normalizedPassword,
        salt,
        parallelism: 1,
        iterations: 3,
        memorySize: 65536, // 64 MB
        hashLength: 32,
        outputType: 'encoded',
      });
    },

    async verify(hash: string, password: string): Promise<boolean> {
      try {
        return await argon2Verify({ hash, password: normalizePasswordInput(password) });
      }
      catch {
        return false;
      }
    },
  };
}
