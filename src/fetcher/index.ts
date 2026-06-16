/**
 * Re-export of `@bajustone/fetcher` — the schema-validated fetch client and
 * schema builder that power fortress's own request validation (and, in later
 * phases, its outbound HTTP).
 *
 * Surfaced here so consumers can use the exact same toolkit fortress uses
 * internally — authoring endpoint schemas with the same builder, building
 * their own validated outbound clients — without installing
 * `@bajustone/fetcher` as a separate dependency.
 *
 * - Flat root re-export: `createFetch`, middleware (`retry`, `timeout`,
 *   `authBearer`, …), error classes, and types.
 * - `schema` namespace: the schema builder (`object`, `string`, `integer`,
 *   `optional`, `email`, `uuid`, `discriminatedUnion`, `ref`, `compile`, …).
 * - `openapi` namespace: `fromOpenAPI`, `fromJSONSchema`, `extractRouteSchemas`, …
 * - `specTools` namespace: `coverage`, `lintSpec`.
 *
 * @example
 * ```ts
 * import { createFetch, schema } from '@bajustone/fortress/fetcher';
 *
 * const Login = schema.object({ email: schema.email(), password: schema.string() });
 * const api = createFetch({ baseUrl: 'https://api.example.com' });
 * ```
 *
 * @module
 */

export * from '@bajustone/fetcher';
export * as openapi from '@bajustone/fetcher/openapi';
export * as schema from '@bajustone/fetcher/schema';
export * as specTools from '@bajustone/fetcher/spec-tools';
