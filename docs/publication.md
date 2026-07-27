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
bun run check:npm-publication   # build + npm pack manifest + installed CLI smoke
bun run check:jsr-publication   # pinned Deno/JSR selected-file manifest
bun run check:publication-files # repository policy + migration parity + both registries
```

The checks require every declared entrypoint, reject test/repository debris,
assert npm includes the CLI, and assert JSR does not. Migration expectations
come from the migration definitions rather than the `migrations/` tree, so a
dropped migration cannot regenerate into a self-consistent short set. CI,
release validation, and publication workflows run the same checks.

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
