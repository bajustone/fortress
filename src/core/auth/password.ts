import { argon2id, argon2Verify } from 'hash-wasm';

export type { PasswordHasher } from '../config';

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
      const salt = new Uint8Array(16);
      crypto.getRandomValues(salt);

      return argon2id({
        password,
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
        return await argon2Verify({ hash, password });
      }
      catch {
        return false;
      }
    },
  };
}
