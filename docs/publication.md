# Publication policy

Fortress publishes one TypeScript library through two registry channels with one
intentional capability difference.

## npm registry

The npm package is the complete filesystem/Bun distribution. It includes:

- ESM/CJS builds and declarations under `dist/`;
- the Bun `fortress` executable under `bin/`;
- production TypeScript source required by the executable;
- public documentation, examples, and all generated migration SQL artifacts.

It excludes source tests, integration tests, snapshots, contributor scripts,
CI configuration, and project-only planning material.

Install this channel when using the CLI:

```sh
bun add @bajustone/fortress
# or: npm install @bajustone/fortress
```

## JSR

JSR is the source-first programmatic library. It includes exported production
source, public documentation/examples, and generated migration SQL artifacts.
It intentionally excludes `bin/` and `dist/`; JSR installations do not provide
the `fortress` executable.

```sh
bunx jsr add @bajustone/fortress
# or: deno add jsr:@bajustone/fortress
```

## Enforced manifest contracts

Registry dry runs are treated as the authority rather than trusting manifest
patterns alone:

```sh
bun run check:npm-publication   # clean build + ESM/CJS contracts + npm pack/CLI smoke
bun run check:jsr-publication   # pinned Deno/JSR selected-file manifest
bun run check:publication-files # repository policy + migration parity + both registries
```

The checks require every declared entrypoint, reject test/repository debris,
assert npm includes the CLI, and assert JSR does not. Built-package validation
compiles both the `import.types` (`.d.ts`) and `require.types` (`.d.cts`)
consumer contracts after one clean tsup build; strict export parity binds all
four conditional leaves to the same tsup entry. The release floor then runs
exact TypeScript 5.0.4 over both generated declaration branches without
rebuilding. A separate current-compiler package contract verifies a real
Express 4 application against isolated Express 4/core-v4 types; the existing
Express 5 contract remains in the ESM/source matrix. Migration expectations
come from the migration definitions rather than the `migrations/` tree, so a
dropped migration cannot regenerate into a self-consistent short set. CI,
release validation, and publication workflows run the same checks.

## Tagged publication and recovery

Pushing a `v*` tag publishes both registries from that commit after the shared
verification and quality gates pass. The tag must equal `v<package version>`
and its commit must be contained in `main`.

The two registries are published by independent jobs, so a release can land on
one registry and fail on the other. Because published versions are immutable on
both, the recovery for that state is to complete the missing half from the same
tag — never to move the tag or cut a replacement version.

`npm pack --json` returns a manifest array on npm 11 and an object keyed by
package name on npm 12; the packed-manifest check accepts either and requires
exactly one manifest. `bun run check:npm-pack-shapes` proves that against both
pinned CLIs using a synthetic fixture package. It is deliberately excluded from
`check:package-cli` and `check:release` so the everyday checks stay offline, and
runs explicitly in CI and in the publish workflow's quality job.

npm recovery runs through the `Publish` workflow's manual `workflow_dispatch`
input, because npm trusted publishing is bound to that workflow's filename. It
refuses to run unless the requested version is a well-formed release whose tag,
remote tag, and checked-out commit agree and are contained in `main`, JSR
already serves that exact version, and npm demonstrably does not while the
registry is reachable. It then runs the tagged commit's own `check:release` and
`check:npm-publication` under the npm CLI that release was validated against, so
the publish lifecycle executes rather than being bypassed, and finally asserts
the published version, `latest` tag, and `gitHead` match the tagged commit.

## TypeScript branch boundary

The Rust rewrite is a separate branch and is not part of the Fortress
TypeScript distribution. TypeScript/main must not track or publish Rust source,
Cargo metadata, or generated Rust Markdown/HTML. Public documentation on this
branch uses source Markdown/YAML; generated HTML is not a tracked or published
format. The repository policy check and `.gitignore` enforce that boundary. The
separate rewrite branch owns its source layout and documentation decisions.

Root audit, context, plan, planning, and progress documents are project inputs,
not registry assets. Actual npm and JSR file-set checks reject them if a
manifest change would otherwise publish them.
