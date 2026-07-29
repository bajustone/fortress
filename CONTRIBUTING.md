# Contributing to Fortress

## Prerequisites

- [Bun](https://bun.sh/) at the version pinned by `packageManager` in `package.json`.
- Node.js 20.19.0 or newer. Run `nvm use` to select the minimum supported release from `.nvmrc`.
- Docker or another Testcontainers-compatible container runtime only when running the PostgreSQL integration suite.

## Setup

```sh
bun install --frozen-lockfile
cp .env.example .env
```

The values in `.env.example` are for local examples only. Do not reuse them in deployed applications.

Start the Hono example with:

```sh
bun run dev
```

If its required environment is missing, the command exits with a pointer to `.env.example` rather than starting with an unsafe secret.

## Daily checks

```sh
bun run lint
bun run typecheck
bun run typecheck:examples
bun run test
```

Unit tests use in-memory SQLite and do not require Docker.

## Built-package contract

Run the source and built-package consumer contract before changing exports, declarations, adapters, plugins, or documented TypeScript examples:

```sh
bun run check:consumer-contract
```

For built output only, use the self-contained clean-checkout command:

```sh
bun run check:built-package
```

It builds `dist/`, checks declarations with the supported TypeScript branches,
and imports the testing entrypoint under Node ESM and CommonJS. Standalone
post-build checks fail immediately with a `bun run build` pointer when artifacts
are absent.

Code coverage is not currently a repository gate. The project gates behavior,
type contracts, framework examples, and PostgreSQL integration explicitly;
coverage thresholds should only be introduced with an agreed baseline.

## PostgreSQL integration tests

Start Docker (or a compatible runtime), then run:

```sh
bun run test:integration
```

The integration suite starts disposable PostgreSQL containers. It is release-critical and must not be silently skipped in CI.

## Before opening a pull request

At minimum, run the daily checks and any suite relevant to your change. For release-sensitive changes, run:

```sh
bun run check:release
```

`check:release` includes PostgreSQL integration tests and therefore requires a container runtime.
