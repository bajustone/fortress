import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    hono: 'src/hono/index.ts',
    drizzle: 'src/drizzle/index.ts',
    testing: 'src/testing/index.ts',
    crypto: 'src/core/auth/password.ts',
    jwt: 'src/core/auth/jwt.ts',
    otel: 'src/otel/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  clean: true,
  outDir: 'dist',
  external: ['drizzle-orm', 'hono', 'better-sqlite3', 'bun:sqlite', '@opentelemetry/api'],
});
