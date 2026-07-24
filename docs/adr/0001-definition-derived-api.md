# ADR 0001 — Definition-derived Fortress API with capability-based runtime boundaries

- **Status:** accepted
- **Date:** 2026-07-24
- **Issue:** #32
- **Applies to:** next major (v2). Source-breaking; must not be folded into 1.x patch work.
- **Informed by:** #9/PR #30 (typed consumer boundaries), #10/PR #31 (precise call types), #11 (generic plugin contract), the 2026-07-24 TypeScript ergonomics audit (P3-2, P3-3, P3-4, structural findings).

## Context

The 1.x type architecture recovers types after the fact instead of deriving them
from declarations:

- `Fortress<TPlugins, TCall>` carries two independently supplied generics even
  though both are derived from the same configured plugin tuple. Nothing prevents
  them from drifting apart, and every erased boundary needs `AnyFortress`.
- Adapters accept `AnyFortress = Fortress<unknown, unknown>` — safe since #9,
  but each adapter still receives (and appears to depend on) the *entire*
  instance rather than the two or three members it actually uses.
- `CallableForEndpoints` must key-filter endpoint maps (`as E[K] extends
  EndpointDefinition ? K : never`) because nothing validates an endpoint
  collection where it is written. A stray non-endpoint property silently
  disappears from the call surface instead of failing at the definition site.
- The flat `fortress.call.*` map intersects every plugin's handler names into
  one namespace. Two plugins using the same route key is a startup error at
  runtime and an unintelligible intersection at the type level.
- `getPluginMethods<T>(fortress, name)` accepts a caller-invented `T` — a cast
  wearing a helper's clothes (audit P3-2). Static and dynamic plugin access are
  the same code path.

## Decision

### 1. One plugin tuple is the source of every derived instance type

```ts
interface Fortress<TPlugins extends readonly RuntimeFortressPlugin[] = readonly RuntimeFortressPlugin[]>
  extends FortressHttpRuntime, FortressAuthRuntime, FortressPluginRuntime,
          FortressManifestRuntime, FortressMigrationRuntime, FortressObservabilityRuntime {
  readonly plugins: InferPlugins<TPlugins>;   // typed projection of the tuple
  readonly call: CallTree<TPlugins>;          // namespaced typed call tree (§5)
  // resolvePlugin(name[, validator]) is inherited from FortressPluginRuntime (§6)
}
```

`TCall` is gone. `createFortress()` keeps the `const` plugin tuple and derives
`plugins` and `call` from it. There is no second generic to drift and no
`AnyFortress`: the unparameterized `Fortress` (default tuple) is the erased
form, and boundaries that don't need plugin inference accept a capability
interface instead (§4). The erased form remains a true supertype by making no
plugin-call promises: `InferPlugins` degrades a non-literal plugin name
(`string`) to `object`, while the broad default `CallTree` resolves to an
empty erased tree. A concrete tuple resolves to its precise core and plugin
callables.

### 2. Endpoint collections are validated and branded at their definition site

```ts
const authEndpoints = defineEndpoints({
  login: endpoint('POST', '/auth/login')...build(),
  register: endpoint('POST', '/auth/register')...build(),
});
```

`defineEndpoints()` is an inference-preserving identity function whose
parameter type maps every non-endpoint property to a per-property compile
error, so invalid members fail *where they are written*, with exact literal
keys and full `EndpointDefinition<TBody, TQuery, TParams, TResponses,
THandler, TMethod, TPath>` generics preserved and no string index signature introduced. The
returned type carries a phantom `DefinedEndpoints` brand recording that
validation happened.

Because collections are exact by construction, the call client is the plain
mapped type the 1.x filtering machinery was trying to approximate:

```ts
type CallClient<E> = { readonly [K in keyof E]: EndpointCall<E[K]> };
```

No conditional filtering, no `Record<string, never>`-style destructive
fallback branches.

### 3. `definePlugin()` correlates name, methods, routes, and handlers

`EndpointDefinition` gains trailing phantom generics for the literal handler,
method, and path. `EndpointBuilder` captures all three so call ownership can
remove a core callable when a plugin intentionally overrides the same
method/path. `definePlugin()` (canonical
authoring API, introduced by #11, extended here) statically verifies:

- the plugin name is preserved as a literal type;
- method keys and signatures are exact (no widening to `Record<string, Function>`);
- route keys and endpoint generics are exact;
- **every route's `handler` names an existing plugin method** — a route whose
  handler doesn't exist on the methods surface is a compile error on that route
  property (`RouteHandlerMissing`);
- **the handler accepts the full dispatched function call and its resolved
  return value serializes to the body declared for the lowest numeric exact
  2xx response key** (`RouteHandlerIncompatible`). Dispatch calls
  `methods[handler]({...body, ...query, ...params}, ctx)` with validated,
  schema-transformed values; zero/one-argument handlers and a compatible
  optional context remain valid, while incompatible optional/rest parameters
  and required trailing arguments fail. The return check compares through a
  `JsonOf` wire projection
  (`Date` → ISO string) — schemas describe the wire, methods describe the
  runtime;
- third-party plugins get all of this from inference alone — no central
  registry edit, no module augmentation.

Three route classes keep only the handler-existence check, each for a
principled reason: self-authenticating OAuth protocol routes
(`meta.bearerKind: 'oauth'`) use bespoke dispatch conventions whose typing is
tracked by #27; *contractless* routes (no inferred input keys, `unknown`
success) declare nothing to correlate against; and dynamically aggregated
route records (string index signature, e.g. admin's `Object.fromEntries`
composition) have no statically known properties — they are validated at
runtime and contribute no typed call namespace.

Duplicate plugin names and cross-plugin call ownership conflicts cannot be
checked inside a single `definePlugin()` call; they are prevented by
construction in the call topology (§5) and still rejected at startup as
defense in depth.

Applying the check to the built-in plugins immediately surfaced real,
shipped contract drift — api-key's `createKey`/`rotateKey` documented an
integer `id` but return strings, `listKeys` documented a `{keys: [...]}`
envelope but returns a bare array, tenancy's response schema omitted
nullability and timestamps, and webauthn's `verifyAuthentication` documented
a bespoke envelope while returning the standard auth result — validating the
design before it left the branch.

`PluginMethodsMap` remains only as a deprecated compatibility bridge for
legacy widened plugins; it is not consulted for anything authored with
`definePlugin()`.

### 4. Runtime boundaries accept minimal capability interfaces

An audit of all 94 `AnyFortress` sites (28 files) shows adapters use a small,
stable subset of the instance, clustering into a handful of shapes — and the
manifest code already models the target pattern with
`Pick<AnyFortress, 'endpoints' | 'config'>` slices. v2 defines focused
capability interfaces in `src/core/capabilities.ts`; the full `Fortress`
composes them (§1):

| Capability | Members | Consumers (measured) |
|---|---|---|
| `FortressHttpRuntime` | `endpoints`, `manifest`, `config`, `handleRequest` | HTTP consumers use exact `Pick` slices: Hono/Express `mountFortress` need `manifest` + `handleRequest`; `buildCall` needs only `handleRequest`; other helpers select their measured members |
| `FortressAuthRuntime` | `auth`, `iam`, `cookies`, `config`, `extractAccessToken`, `resolvePrincipal`, `serializeAuthCookies` | auth + RBAC middleware (Hono/Express/SvelteKit), SvelteKit actions/cookies, `smokeTestAuth` |
| `FortressPluginRuntime` | `config`, `plugins` (erased `object`), `runPluginMiddleware`, `resolvePlugin` | plugin-middleware slots, rate-limit framework adapters, principal chain |
| `FortressManifestRuntime` | `endpoints`, `manifest`, `config`, `toOpenAPI` | manifest drift/route checks, OpenAPI emission (already `Pick`-shaped today) |
| `FortressMigrationRuntime` | `migrate`, `syncPermissionsFromManifest` | bootstrap and CLI paths |
| `FortressObservabilityRuntime` | `logger`, `telemetry` | error handlers, `protect()` logging |

`protect()` — the widest measured consumer — takes the composition
`FortressProtectRuntime = FortressManifestRuntime & FortressAuthRuntime &
FortressPluginRuntime & FortressObservabilityRuntime`; internal core
machinery (request dispatch, instance assembly) consumes `FortressRuntime`,
the composition of all six. Narrow internal helpers use `Pick` slices of a
capability (e.g. `Pick<FortressHttpRuntime, 'handleRequest'>` for
`buildCall`).

Adapter signatures use exact slices, e.g. `mountFortress(app: Hono, fortress:
Pick<FortressHttpRuntime, 'manifest' | 'handleRequest'>)`. Every concrete `Fortress<TPlugins>` satisfies every
capability automatically, so consumers never cast; and a test can hand-roll a
capability object without building a full instance. Member sets are fixed by
the usage audit, not by guesswork — a capability never carries a member no
consumer uses.

### 5. Call ownership is namespaced

Two topologies were compared, as the issue requires:

**(a) Flat map with compile-time duplicate rejection.** Keep
`fortress.call.login`, make `createFortress` reject tuples whose route keys
collide. *For:* no migration cost; terse call sites. *Against:* the collision
diagnostic surfaces as an assignability failure on the whole config object
(poor locality — the error names neither route key nor plugins); the
intersection machinery (`UnionToIntersection` over per-plugin
`CallableForEndpoints`) that #10 had to repair remains load-bearing; core and
plugin keys still share one namespace, so a third-party plugin can still
shadow `login` for readers even when the compiler accepts it; ownership stays
invisible in code review and generated docs.

**(b) Namespaced tree.** `call.auth.*` and `call.iam.*` for core;
`call.plugins.<pluginName>.<routeKey>` for plugin routes that the generic JSON
caller can serialize. *For:* collisions are impossible by construction —
plugin names are already unique (enforced at startup and keyed by
`InferPlugins`); ownership is explicit at every call site and in generated
documentation; symmetric with `fortress.plugins.<name>` (direct method
access) — same second segment, HTTP pipeline vs in-process. OAuth protocol
routes that require form, Basic, or OAuth-bearer semantics are excluded.
Intentional plugin overrides remain available in the plugin namespace and
remove the conflicting core callable rather than retaining a false core
contract. An override must list the core call key in `coreOverrides` and reuse
that key as its route key and handler name; this explicit declaration lets the
type projection identify removed callables even when route records or paths
are configurable. *Against:* every 1.x call site changes.

**Decision: (b), namespaced.** The migration is mechanical
(`call.login` → `call.auth.login`; `call.createKey` →
`call.plugins['api-key'].createKey`) and a one-time cost at a major boundary,
whereas (a)'s diagnostic quality and residual shadowing are permanent. No
flattened compatibility client ships in core: the rewrite is mechanical, and
`buildCall` (the runtime flat-map builder) remains exported for hosts that
need a bespoke flat client during migration. Runtime duplicate validation
in `createFortress` stays as defense in depth (non-goal: never remove runtime
validation merely because a compile-time contract exists).

Host routes declared via top-level `config.routes` remain excluded from the
call tree (they have no backing methods; calling them would be a guaranteed
`NOT_FOUND`). Host/core method-path collisions are rejected at startup;
intentional core overrides must be declared as explicit plugins so their
backing method and accurate plugin call contract are available.

### 6. Static and dynamic plugin access are separate APIs

- **Static (inferred):** `fortress.plugins.oauth.createAuthorizationUrl(...)` —
  exact surface derived from the tuple. Unknown keys are compile errors.
- **Dynamic:** `fortress.resolvePlugin(name)` returns `unknown`;
  `fortress.resolvePlugin(name, validator)` returns the validator-proven type.
  A caller-selected generic assertion (`resolvePlugin<T>(name)` with no
  validator) is not expressible — the bare overload returns `unknown`,
  and the typed overload's `T` is inferred solely from the validator argument.
- `getPluginMethods()` is removed in v2 (its validated overload moved onto the
  instance as `resolvePlugin`; its unconstrained-generic form is the exact
  anti-pattern this ADR eliminates).

## Consequences

- Plugin methods and calls cannot drift: both are projections of one tuple.
- An endpoint-collection typo is a compile error at the definition site, not a
  silently missing callable.
- Renaming a plugin method without updating its route (audit P3-3) is a
  compile error inside `definePlugin`.
- Adapters compile against capability interfaces, so a change to `Fortress`'s
  plugin surface can no longer ripple into adapter signatures; conversely,
  hand-rolled capability fakes make adapter tests cheap.
- All 1.x consumers of `AnyFortress`, flat `fortress.call.*`, bare
  `FortressPlugin` factories, `getPluginMethods`, and `PluginMethodsMap`
  augmentation must migrate — see `docs/v2-migration.md`.
- Request execution remains framework-neutral (web-standard
  `Request`/`Response` only); Bun, Node, Deno, and workerd remain supported.
  The public `fortress.call` object changes shape at runtime as part of the
  namespaced major-version API.

## Verification

- Source and generated-package type contract tests cover: core auth + IAM call
  trees, every built-in plugin's methods and call namespace, third-party
  `definePlugin` inference, cross-plugin collision impossibility, invalid
  endpoint-collection rejection (`@ts-expect-error` at the definition site),
  handler-correlation rejection, and dynamic lookup returning `unknown`
  without a validator.
- Runtime duplicate-route and duplicate-plugin-name validation keeps its
  existing tests.
