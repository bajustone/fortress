import { createFortress } from '@bajustone/fortress';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
import { mountFortress } from '@bajustone/fortress/hono';
import { drizzle } from 'drizzle-orm/bun-sqlite';
import { Hono } from 'hono';

/**
 * Compiles README.md's "Start with Hono and SQLite" quickstart unchanged
 * against both source entrypoints and freshly generated package declarations.
 */
const fortress = createFortress({
  database: createDrizzleAdapter(drizzle('app.db')),
  jwt: {
    key: process.env.FORTRESS_JWT_SECRET!, // at least 32 UTF-8 bytes
    issuer: 'my-app',
  },
  // Required only for plain-HTTP local development.
  cookies: { secure: false },
});

await fortress.migrate();

const app = new Hono();
mountFortress(app, fortress);

export default app;
