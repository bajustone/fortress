# Security Review Packet — 2026-06-08

Status: prepared for independent review

## Scope

Review Fortress core and first-party plugin security controls:

1. OAuth/OIDC flows.
2. Refresh-token rotation/replay handling.
3. CSRF and cookie posture.
4. IAM/RBAC authorization and permission-cache invalidation.
5. API-key and service-account flows.
6. Tenancy/data isolation.
7. Route manifest, OpenAPI, and migration drift tooling.

## Review materials

- Threat model: [docs/threat-model.md](./threat-model.md)
- Security policy: [SECURITY.md](../SECURITY.md)
- Security guide: [docs/security.md](./security.md)
- Architecture: [docs/architecture.md](./architecture.md)
- Route manifest guide: [docs/route-manifest.md](./route-manifest.md)
- Host-owned route boundary: [docs/host-owned-routes.md](./host-owned-routes.md)
- Migration guide: [docs/migrations/0001-schema-version.md](./migrations/0001-schema-version.md)
- Tenancy guide: [docs/plugins/tenancy.md](./plugins/tenancy.md)

## Repro / verification commands

```sh
bun run lint
bun run typecheck
bun run test
fortress manifest:check
fortress migrate:check --dialect sqlite
fortress migrate:check --dialect pg
```

For app-specific review, generate from the configured app instance:

```ts
const manifest = fortress.manifest;
const routeDrift = detectRouteManifestDrift(fortress, { openapi });
const migrationDrift = await detectMigrationDrift(fortress.config.database);
```

## Findings tracker

| ID | Area | Severity | Status | Summary | Remediation |
|---|---|---:|---|---|---|
| _TBD_ | _TBD_ | _TBD_ | Open | _Reviewer to fill_ | _Link PR/doc_ |

Use the existing remediation-plan format for any confirmed findings.
