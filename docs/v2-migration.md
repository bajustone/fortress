# Migrating to Fortress v2 — the definition-derived API

Fortress v2 derives every typed surface from one source — the `const` plugin
tuple you pass to `createFortress()` — and replaces erased instance boundaries
with minimal runtime capability interfaces. The full design rationale is in
[ADR 0001](./adr/0001-definition-derived-api.md). Runtime behavior is
unchanged; every break below is source-level only.

## At a glance

| v1 | v2 |
|---|---|
| `Fortress<TPlugins, TCall>` | `Fortress<TPlugins extends readonly RuntimeFortressPlugin[]>` — one generic, both surfaces derived |
| `AnyFortress` | bare `Fortress` (erased supertype), or — better — a capability interface |
| `TypedCall<T>` | `CallTree<T>` |
| `fortress.call.login(...)` | `fortress.call.auth.login(...)` |
| `fortress.call.createRole(...)` | `fortress.call.iam.createRole(...)` |
| `fortress.call.createKey(...)` | `fortress.call.plugins['api-key'].createKey(...)` |
| `getPluginMethods<T>(fortress, name)` | `fortress.plugins.<name>` (static) / `fortress.resolvePlugin(name, validator?)` (dynamic) |
| `CallableForEndpoints<E>` | `CallClient<E>` |
| `InferPluginCallMap<T>` | `PluginCallTree<T>` (namespaced; no intersection) |
| `PluginMethodsMap` augmentation | `definePlugin()` inference (bridge kept, deprecated) |
| bare endpoint record literals | `defineEndpoints({...})` (validated + branded at the definition site) |

## 1. The call client is namespaced

Ownership is explicit at every call site: core auth under `call.auth`, core
IAM under `call.iam`, and each plugin's routes under `call.plugins.<name>`.
Cross-plugin call-name collisions are impossible by construction — plugin
names are unique (still enforced at startup as defense in depth).

```ts
// v1                                        // v2
await fortress.call.login({ ... });          await fortress.call.auth.login({ ... });
await fortress.call.createRole({ ... });     await fortress.call.iam.createRole({ ... });
await fortress.call.sendMagicLink({ ... });  await fortress.call.plugins['magic-link'].sendMagicLink({ ... });
```

The rewrite is mechanical. No flattened compatibility client ships in core;
if you need a flat map during migration, the runtime builder is still
exported:

```ts
import { buildCall } from '@bajustone/fortress';
const flat = buildCall(fortress, { ...authEndpoints, ...iamEndpoints });
```

## 2. `AnyFortress` is gone — accept a capability instead

Framework adapters and utilities now accept the capability they actually use
(`src/core/capabilities.ts`). Every `Fortress<TPlugins>` instance satisfies
every capability, so call sites that pass a real instance need no change.
Code that *declared* `AnyFortress` parameters should narrow:

```ts
// v1
function mount(app: Hono, fortress: AnyFortress) { ... }

// v2 — say what you use
function mount(app: Hono, fortress: FortressHttpRuntime) { ... }
```

Available capabilities: `FortressHttpRuntime` (endpoints, manifest, config,
handleRequest), `FortressAuthRuntime` (auth, iam, cookies, config, token
extraction, principal resolution, cookie serialization),
`FortressPluginRuntime` (config, erased plugins, plugin middleware,
`resolvePlugin`), `FortressManifestRuntime` (endpoints, manifest, config,
toOpenAPI), `FortressMigrationRuntime` (migrate, syncPermissionsFromManifest),
`FortressObservabilityRuntime` (logger, telemetry), plus the compositions
`FortressProtectRuntime` and `FortressRuntime`. If you genuinely need the
whole erased instance, the bare `Fortress` type is the supertype of every
concrete instantiation.

`MigrateOptions`, `MigrateResult`, `FortressToOpenAPIOptions`, and
`PluginMethodsValidator` now live with the capabilities but remain exported
from the package root — imports keep working.

## 3. `getPluginMethods()` is removed

- **Known plugin, configured tuple** — use the inferred surface:
  `fortress.plugins.oauth.createAuthorizationUrl(...)`. Unknown names are
  compile errors.
- **Dynamic name** — `fortress.resolvePlugin(name)` returns `unknown`. Pass a
  type guard to prove the surface at runtime:
  `fortress.resolvePlugin(name, isOAuthMethods)`. There is deliberately no
  `resolvePlugin<T>(name)` caller-selected assertion — the v1
  `getPluginMethods<T>()` form was an unchecked cast.

## 4. Endpoint collections use `defineEndpoints()`

Wrap keyed endpoint records at their definition site. Non-endpoint members
fail to compile *on that property* (and throw at runtime as defense in
depth); exact keys and per-endpoint generics are preserved and branded.

```ts
const authEndpoints = defineEndpoints({
  login: endpoint('POST', '/auth/login')...build(),
  register: endpoint('POST', '/auth/register')...build(),
});
```

A defined collection feeds `CallClient<E>` directly — the v1 conditional
filtering (`CallableForEndpoints`) and its destructive fallback branches are
gone.

## 5. `definePlugin()` checks route→method wiring

`definePlugin()` (canonical since #11) now statically verifies that every
route's `.handler('x')` names an existing plugin method whose signature is
compatible: the method must accept the endpoint's inferred
body+query+params input, and its resolved return must serialize (`Date` →
ISO string) to the declared success response.

Migrating a v1 plugin:

- Ensure each route's handler exists on the object returned by `methods()`.
- Ensure route response schemas describe what the method actually returns —
  in v1 several built-ins had drifted (api-key's `id` was documented as an
  integer but returned as a string; webauthn's `verifyAuthentication`
  documented a bespoke envelope but returns the standard auth result). v2
  makes such drift a compile error.
- Hand-authored route literals must keep their handler literal:
  `handler: 'getSpec' as const`. Routes built with `endpoint().handler(...)`
  capture the literal automatically.
- Routes with no declared schemas ("contractless") and self-authenticating
  OAuth protocol routes (`meta.bearerKind: 'oauth'`) keep only the
  handler-existence check.
- Dynamically aggregated route records (string-indexed, e.g. built with
  `Object.fromEntries`) are validated at runtime only and contribute no
  typed call namespace — same as v1.
- Metadata-only route collections that a host app serves itself belong in
  top-level `config.routes`, not in a plugin — plugin routes without backing
  methods are now compile errors by design.

`PluginMethodsMap` remains only as a deprecated bridge so existing
`declare module` augmentations keep resolving; new plugins need no central
registry edit and no augmentation.

## 6. Rarely needed

- `EndpointDefinition` gained a fifth phantom generic (`THandler extends
  string = string`). Code that spelled out all four generics is unaffected;
  code that pattern-matched `EndpointDefinition<infer A, infer B, infer C,
  infer D>` in conditional types should add a trailing `any`.
- `buildCall()` now accepts `Pick<FortressHttpRuntime, 'handleRequest'>`
  instead of `AnyFortress` — strictly wider.
- `record()` in the schema builder accepts an optional generic
  (`record<RegistrationResponseJSON>(...)`) to type a permissive object
  schema's wire shape precisely.
