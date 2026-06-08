# Fortress CI checks (P1-10)

Fortress ships a bundle of reusable CI checks under
`@bajustone/fortress/testing` plus a `fortress check:*` CLI namespace.
The same drift detectors Fortress uses internally to keep its own
routes/migrations/RBAC mappings honest are exposed to consumer apps so
you can gate deploys on them.

## What's covered

| Check | API | CLI | Catches |
|---|---|---|---|
| Route-manifest drift | `checkRouteManifestDrift(fortress)` | `fortress manifest:check` / `fortress check:routes` | Mounted routes not in the manifest, manifest routes not mounted, RBAC permission/OpenAPI mismatches |
| Public-route allow-list | `checkPublicRoutes(fortress, { allow })` | `fortress check:public-routes` | A new route marked `.security('none')` or `bearerKind:'oauth'` that wasn't reviewed |
| Migration drift | `checkMigrationDrift(adapter)` | `fortress migrate:check` / `fortress check:migrations` | Missing version table, pending migrations, missing Fortress tables, DB ahead of bundled catalog |
| Auth smoke test | `smokeTestAuth(fortress)` | _(run from a test file)_ | Register/login/refresh/logout regression |
| Aggregator | `runFortressChecks({ fortress })` | _(run from a test file)_ | All of the above with a single ok/messages roll-up |

`runFortressChecks` is the convenience entry point — wire it into a
single vitest test or a deploy preflight script.

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
- A regression in the auth pipeline (register/login/refresh/logout).

## As a CLI

```sh
fortress manifest:check         # route-security drift (also: check:routes)
fortress check:public-routes    # public-route allow-list (core surface)
fortress migrate:check          # migration catalog (also: check:migrations)
```

The CLI runs against Fortress's **core auth + IAM** route surface, so it
catches drift in Fortress itself but doesn't see your plugins. For
app-level checks (plugin routes + your real config), use the API from a
vitest test as shown above.

## GitHub Actions snippet

A drop-in workflow is committed at
[`docs/ci/github-actions.yml`](./ci/github-actions.yml). Save it as
`.github/workflows/fortress-ci.yml` in your repo. It runs:

1. `bun run lint`
2. `bun run typecheck`
3. `bunx fortress manifest:check`
4. `bunx fortress check:public-routes`
5. `bunx fortress migrate:check`
6. `bun run test` (which should include `runFortressChecks(...)` from
   the snippet above)
7. `bunx tsup` (optional — verifies the package builds cleanly)

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
fortress check:public-routes --allow 'GET /health' --allow 'GET /robots.txt'
```

If you want a stricter posture (e.g. fail on `oauth-protocol` routes
that appeared without review), restrict `classifications` to just
`['public']`.
