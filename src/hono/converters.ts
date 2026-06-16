/**
 * Default schema converters for the Hono OpenAPI integration — so you can mount
 * fortress endpoints (or import external routes) **without pulling in Zod**.
 *
 * fortress's builder schemas (and `@bajustone/fetcher`'s builder schemas) ARE
 * JSON Schema, so the converters are trivial: identity for the JSON-Schema
 * direction, and `fromJSONSchema` when the target wants a validating Standard
 * Schema V1. Existing Zod callers are unaffected — these are opt-in defaults.
 *
 * @module
 */

import type { JSONSchema } from '../core/json-schema';
import type { StandardSchemaV1 } from '../core/standard-schema';
import type { ToJSONSchemaConverter } from './convert-routes';
import type { SchemaConverter } from './openapi';
import { fromJSONSchema } from '@bajustone/fetcher/openapi';
import { extractJsonSchema } from '../core/schema-builder';

/**
 * A {@link SchemaConverter} that passes JSON Schema through unchanged. Use with
 * OpenAPI tooling that consumes JSON Schema directly, or for raw spec
 * generation. Requires no schema library.
 */
export const identitySchemaConverter: SchemaConverter<JSONSchema> = jsonSchema => jsonSchema;

/**
 * A {@link SchemaConverter} that compiles JSON Schema into a validating
 * `@bajustone/fetcher` Standard Schema V1. Use with Hono OpenAPI tooling that
 * accepts Standard Schema (e.g. `hono-openapi` / `@hono/standard-validator`) —
 * no Zod required.
 */
export const fetcherSchemaConverter: SchemaConverter<StandardSchemaV1> = jsonSchema =>
  fromJSONSchema(jsonSchema) as unknown as StandardSchemaV1;

/**
 * A {@link ToJSONSchemaConverter} for importing external routes authored with
 * fortress's or fetcher's builder (both ARE JSON Schema). Extracts clean JSON
 * Schema (runtime-only `~`-prefixed props are dropped at OpenAPI emission).
 * Pass to {@link convertRoutes} so such routes import without Zod.
 */
export const toJSONSchemaConverter: ToJSONSchemaConverter = schema =>
  extractJsonSchema(schema as Parameters<typeof extractJsonSchema>[0]);
