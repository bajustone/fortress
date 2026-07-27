# Route security manifest

Fortress builds a canonical route-security manifest from endpoint metadata. The manifest is derived from the same `EndpointDefinition` records used by `fortress.handleRequest()`, adapter mounting, and OpenAPI generation.

## Runtime API

```ts
const manifest = fortress.manifest;
```

Each entry contains:

- `method`, `path`, `handler` — the HTTP route and dispatcher handler.
- `plugin` — `auth`, `iam`, a registered plugin name, or `null` when the origin cannot be inferred.
- `classification` — one of:
  - `public` — `meta.security` includes `none`.
  - `authenticated` — bearer/basic/API-key route without an IAM permission.
  - `rbac` — route has `meta.permission` and requires IAM authorization.
  - `oauth-protocol` — route has `meta.bearerKind: 'oauth'` and self-authenticates as an OAuth protocol endpoint.
  - `default-deny` — no usable security metadata; the request pipeline denies it.
- `permission`, `security`, `bearerKind` — direct endpoint security metadata.
- `csrfApplicable` — unsafe method and not skipped by `config.csrf`.
- `rateLimited` — route matches plugin rate-limit middleware, or a rate-limit hook protects the auth gate.
- `mounted` — `true` for routes present in the active `fortress.endpoints` union.

## CLI

```sh
fortress manifest --module ./src/lib/fortress.ts --out route-manifest.json
fortress manifest:check --module ./src/lib/fortress.ts
```

`--module` points at a module exporting your configured instance as
`export const fortress` (a default export also works); an optional `dispose()`
export is called when the command finishes. Constructing the instance needs no
database connection, so this stays offline.

Without `--module` both commands emit/check the core auth + IAM manifest only —
they cannot see your plugins or host-owned routes, and they label their output
`Scope: core-only`. You can also call the programmatic API against your
configured `fortress` instance, which is the better fit inside a test:

```ts
import { detectRouteManifestDrift, hasRouteManifestDrift } from '@bajustone/fortress';

const drift = detectRouteManifestDrift(fortress, { openapi: yourGeneratedOpenApiSpec });
if (hasRouteManifestDrift(drift)) {
  throw new Error(JSON.stringify(drift, null, 2));
}
```

## Adapter behavior

Hono, Express, and SvelteKit adapters use `fortress.manifest` to decide which paths are Fortress-managed before delegating to `fortress.handleRequest()`. This keeps route interception, OpenAPI, and security drift checks aligned with the same endpoint metadata.
