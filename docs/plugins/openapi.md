# OpenAPI Plugin

## Overview

The `openapi` plugin generates an OpenAPI 3.1 specification from all Fortress endpoints (auth, IAM, and plugins) and serves a Scalar interactive API reference UI. It automatically discovers routes from every registered plugin, so the spec stays in sync with your Fortress configuration without manual upkeep.

Use the `additionalEndpoints` option with the `convertRoutes` utility to merge your application's own routes into a single unified spec.

## Installation

Import the `openapi` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { openapi } from '@bajustone/fortress/plugins/openapi';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    openapi({
      title: 'My API',
      version: '1.0.0',
      description: 'Auth and IAM powered by Fortress',
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['openapi']` with full type safety.

This gives you two routes out of the box:

- `GET /openapi.json` -- the OpenAPI 3.1 JSON spec
- `GET /openapi` -- Scalar interactive UI

Both routes are public (no authentication required).

## Configuration

All fields on `OpenAPIConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `title` | `string` | `'Fortress Auth API'` | API title displayed in the spec and UI. |
| `version` | `string` | `'1.0.0'` | API version. |
| `description` | `string` | -- | API description included in the spec's `info` block. |
| `servers` | `Array<{ url: string; description?: string }>` | -- | Server URL(s) for the spec. |
| `specPath` | `string` | `'/openapi.json'` | Path to serve the JSON spec. |
| `uiPath` | `string` | `'/openapi'` | Path to serve the Scalar UI. |
| `disableUI` | `boolean` | `false` | When `true`, only the JSON spec route is registered. |
| `includeCoreAuth` | `boolean` | `true` | Include core auth endpoints (login, register, refresh, etc.) in the spec. |
| `includeCoreIam` | `boolean` | `true` | Include core IAM endpoints (roles, groups, permissions, etc.) in the spec. |
| `additionalSchemas` | `ComponentSchemas` | -- | Extra component schemas to merge into `components.schemas`. |
| `additionalEndpoints` | `EndpointDefinition[]` | -- | Extra endpoint definitions to include in the spec, typically produced by `convertRoutes`. |

## Usage

### Basic setup

With no options, the plugin includes all core auth endpoints, all core IAM endpoints, and every registered plugin's routes:

```ts
openapi()
```

### Customizing the spec paths

```ts
openapi({
  specPath: '/api/docs/spec.json',
  uiPath: '/api/docs',
})
```

### Disabling the Scalar UI

If you only need the JSON spec (for example, to feed into a code generator), disable the UI:

```ts
openapi({
  disableUI: true,
})
```

### Excluding core endpoints

To generate a spec that only contains plugin and application routes:

```ts
openapi({
  includeCoreAuth: false,
  includeCoreIam: false,
})
```

### Adding server URLs

```ts
openapi({
  servers: [
    { url: 'https://api.example.com', description: 'Production' },
    { url: 'http://localhost:3000', description: 'Local development' },
  ],
})
```

## Merging Application Routes

The most powerful feature of the OpenAPI plugin is the ability to merge your application's own routes into the same spec as Fortress endpoints. This produces a single unified API reference.

### Using `convertRoutes`

The `convertRoutes` utility (exported from `@bajustone/fortress/hono` or `@bajustone/fortress/express`) converts `createRoute`-style route objects into Fortress `EndpointDefinition[]`. It is schema-library agnostic -- you provide a converter function that turns your schema objects into JSON Schema.

```ts
import { openapi } from '@bajustone/fortress/plugins/openapi';
import { convertRoutes } from '@bajustone/fortress/hono'; // or /express
import { z } from 'zod';

// Your application routes defined with createRoute
import { loginRoute, listUsersRoute } from './modules/auth/routes';
import { listSchoolsRoute } from './modules/sdms/routes';

openapi({
  title: 'My API',
  version: '1.0.0',
  description: 'Unified spec: fortress + app endpoints',
  additionalEndpoints: convertRoutes(
    [loginRoute, listUsersRoute, listSchoolsRoute],
    { prefix: '/api/v1', schemaConverter: z.toJSONSchema },
  ),
})
```

### `convertRoutes` options

| Option | Type | Required | Description |
|---|---|---|---|
| `schemaConverter` | `(schema: unknown) => JSONSchema` | Yes | Converts your schema objects to JSON Schema. For Zod v4 use `z.toJSONSchema`. Works with any schema library. |
| `prefix` | `string` | No | Path prefix to prepend to every route (e.g., `'/api/v1'`). |

### Supported route shape

`convertRoutes` accepts any object matching the `ExternalRoute` interface, which is compatible with the shape returned by `@hono/zod-openapi`'s `createRoute`:

```ts
interface ExternalRoute {
  method: string;
  path: string;
  tags?: string[];
  summary?: string;
  description?: string;
  deprecated?: boolean;
  security?: Array<Record<string, string[]>>;
  request?: {
    body?: { content: { 'application/json': { schema: unknown } } };
    params?: unknown;
    query?: unknown;
  };
  responses: Record<number | string, {
    description: string;
    content?: { 'application/json': { schema: unknown } };
  }>;
}
```

### Adding raw `EndpointDefinition` objects

If you prefer to skip `convertRoutes`, you can pass `EndpointDefinition[]` directly:

```ts
import type { EndpointDefinition } from '@bajustone/fortress';

const myEndpoint: EndpointDefinition = {
  method: 'GET',
  path: '/api/v1/health',
  handler: 'healthCheck',
  meta: { summary: 'Health check', tags: ['System'], security: ['none'] },
  responses: { 200: { description: 'OK' } },
};

openapi({
  additionalEndpoints: [myEndpoint],
})
```

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `generateSpec` | `()` | `OpenAPISpec` -- full OpenAPI 3.1 spec object (cached after first call) |
| `getSpec` | `()` | `Record<string, unknown>` -- the spec as a plain object (used by the JSON route) |
| `getUI` | `()` | `string` -- Scalar HTML page (used by the UI route) |

## How It Works

1. **Endpoint discovery** -- On the first call to `generateSpec`, the plugin collects endpoints from three sources: core auth endpoints, core IAM endpoints, and all registered plugins (excluding itself). Consumer-provided `additionalEndpoints` are appended last.
2. **Schema merging** -- Component schemas from core auth, core IAM, and `additionalSchemas` are merged into the spec's `components.schemas`.
3. **Spec building** -- The collected endpoints and schemas are passed to the internal `buildOpenAPISpec` function, which produces a valid OpenAPI 3.1.0 document. Path parameters using `:param` syntax are converted to `{param}` format. Operation IDs are auto-generated from the HTTP method and path.
4. **Security scheme detection** -- Security schemes (Bearer JWT, Basic, API Key) are only included in the spec when at least one endpoint references them, keeping the output clean.
5. **Caching** -- The generated spec is cached after the first call. The spec is regenerated only when a new Fortress instance is created.
6. **Scalar UI** -- The UI route serves a lightweight HTML page that loads the Scalar API reference library from a CDN and points it at the JSON spec path.
