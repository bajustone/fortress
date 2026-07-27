# CI checks

Fortress ships a bundle of reusable CI checks under
`@bajustone/fortress/testing` plus a `fortress check:*` CLI namespace.
The same drift detectors Fortress uses internally to keep its own
routes/migrations/RBAC mappings honest are exposed to consumer apps so
you can gate deploys on them.

## What's covered

| Check | API | CLI | Catches |
|---|---|---|---|
| Route-manifest drift | `checkRouteManifestDrift(fortress)` | `fortress manifest:check --module <path>` / `fortress check:routes --module <path>` | Mounted routes not in the manifest, manifest routes not mounted, RBAC permission/OpenAPI mismatches |
| Public-route allow-list | `checkPublicRoutes(fortress, { allow })` | `fortress check:public-routes --module <path>` | A new route marked `.security('none')` or `bearerKind:'oauth'` that wasn't reviewed |
| Live migration drift | `checkMigrationDrift(adapter)` | _(run from a test or deploy script)_ | Missing version table, pending migrations, missing Fortress tables, DB ahead of bundled catalog |
| Bundled catalog consistency | _(internal catalog)_ | `fortress migrate:check` / `fortress check:migrations` | Duplicate versions, invalid dialect metadata, or missing up/down SQL in the selected installed catalog |
| Generated artifact parity | _(repository maintenance)_ | `bun run generate:migrations --check` | Missing, extra, or byte-modified committed SQL projections |
| Auth smoke test | `smokeTestAuth(fortress)` | _(run from a test file)_ | User creation/login/access-token verification/refresh/logout regression |
| Aggregator | `runFortressChecks({ fortress })` | _(run from a test file)_ | All of the above with a single ok/messages roll-up |

`runFortressChecks` is the convenience entry point — wire it into a
single vitest test or a deploy preflight script. Under Node, install
`better-sqlite3` as a development dependency for `createTestAdapter()`;
Bun uses `bun:sqlite` without an extra driver.

## In a vitest test

```ts
import { describe, expect, it } from 'vitest';
import { createFortress } from '@bajustone/fortress';
import { createTestAdapter, runFortressChecks } from '@bajustone/fortress/testing';
import { config } from '../src/lib/fortress-config';

describe('fortress CI checks', () => {
  it('passes every Fortress drift checker', async () => {
    // Build the fortress instance with your real plugin set against an
    // in-memory adapter so smokeTestAuth has somewhere to write.
    const fortress = createFortress({ ...config, database: createTestAdapter() });
    const result = await runFortressChecks({ fortress });
    if (!result.ok)
      console.error(result.messages.join('\n'));
    expect(result.ok).toBe(true);
  });
});
```

This single test catches:

- A new plugin route that's accidentally `.security('none')`.
- A migration that was added without bumping `fortress_schema_version`.
- A manifest entry that no longer corresponds to a mounted route.
- A regression in the auth pipeline (create user/login/token verification/refresh/logout).

## As a CLI

Point the route commands at a module that exports your `config` so they cover
your plugin and host-owned routes:

```sh
fortress manifest:check --module ./fortress.config.ts       # route-security drift (also: check:routes)
fortress check:public-routes --module ./fortress.config.ts  # public-route allow-list
fortress migrate:check          # installed migration catalog (also: check:migrations)
bun run generate:migrations --check  # Fortress-repository SQL artifact parity
```

The module should export your configuration as `export const config`. The CLI
derives the route surface from it directly and **never calls
`createFortress()`**, so no plugin is constructed and no plugin worker starts.
That matters: constructing an instance runs every plugin's `methods()` factory,
and plugins do real work there — the webhook plugin's queue, for example, runs
a startup recovery sweep that queries pending deliveries and can dispatch them.
`fortress init` scaffolds a `fortress.config.ts` in exactly this shape.

A module exporting a configured instance as `export const fortress` is also
accepted, and is what `fortress migrate:up` requires. Prefer `config` for the
route checks: an instance export means importing the module constructs your
application, with whatever that entails. A `dispose()` export is awaited when
the command finishes, on both the pass and the fail path.

The CLI never constructs your app when it is given `config`, but importing any
module runs that module's top-level code. Keep a CLI-facing config module free
of side effects — no `createFortress()` at module scope, no opening a database
connection — and put the constructed instance in a separate module for
`migrate:up`.

Optionally export `componentSchemas` to contribute your own reusable schemas;
they are merged with Fortress's for `openapi` and `schemas` output, so an
endpoint that `$ref`s an application schema still resolves.

**Without `--module`, the route commands cover Fortress's own auth + IAM
surface only.** They catch drift in Fortress itself but cannot see your
plugins or host-owned routes, and they say so in their output:

```
Scope: core-only (Fortress auth + IAM routes). Pass --module <path> to include plugin and host-owned routes.
```

The migration CLI check validates the selected bundled catalog; it does not
connect to a live database. For live migration checks, use the APIs from a
vitest or deploy script as shown above.

## GitHub Actions snippet

A drop-in workflow is committed at
[`docs/ci/github-actions.yml`](./ci/github-actions.yml). Save it as
`.github/workflows/fortress-ci.yml` in your repo. It runs:

1. `bun run lint`
2. `bun run typecheck`
3. `bun run typecheck:examples`
4. `bunx fortress manifest:check --module ./fortress.config.ts`
5. `bunx fortress check:public-routes --module ./fortress.config.ts`
6. `bunx fortress migrate:check`
7. `bun run test` (which should include `runFortressChecks(...)` from
   the snippet above)
8. `bun run test:integration` for PostgreSQL-backed projects
9. `bun run build` (verifies distributable output)

Fortress's own repository workflow additionally runs
`bun run generate:migrations --check`. Consumer projects do not own the
package's generated SQL projection and should not add that maintainer-only step.

Adjust `oven-sh/setup-bun` to your preferred Node/PNPM/NPM setup; every
step is plain shell.

## Customising the public-route allow-list

The default allow-list covers Fortress's intentional public surface
(auth open routes + OAuth protocol endpoints). Add your own public
routes via the `allow` option:

```ts
checkPublicRoutes(fortress, {
  allow: [
    'GET /health',
    'GET /robots.txt',
    'POST /webhooks/incoming',
  ],
});
```

CLI usage repeats `--allow`:

```sh
fortress check:public-routes --module ./fortress.config.ts \
  --allow 'GET /health' --allow 'GET /robots.txt'
```

If you want a stricter posture (e.g. fail on `oauth-protocol` routes
that appeared without review), restrict `classifications` to just
`['public']`.
