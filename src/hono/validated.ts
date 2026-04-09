/**
 * Typed extraction helpers for Hono handlers.
 *
 * These helpers extract request data (body, params, query) with full
 * TypeScript type inference using Standard Schema V1's type system. Useful
 * for **custom user routes** outside the Fortress dispatch pipeline —
 * Fortress-managed endpoints are validated automatically inside
 * `fortress.handleRequest`.
 *
 * **No runtime validation** — the schema parameter is used purely for
 * TypeScript type inference. If you need runtime validation on a custom
 * route, validate the result yourself with `schema['~standard'].validate()`.
 *
 * Works with any Standard Schema V1 library: Zod, Valibot, ArkType,
 * or fortress's built-in schema builders.
 *
 * @example
 * ```ts
 * import { vBody, vParam, vQuery } from '@bajustone/fortress/hono';
 *
 * app.post('/users/:id', async (c) => {
 *   const body   = await vBody(c, CreateUserBody);
 *   const { id } = vParam(c, IdParam);
 *   const { page } = vQuery(c, PaginationQuery);
 * });
 * ```
 */

import type { Context } from 'hono';
import type { StandardSchemaV1 } from '../core/standard-schema';

/** Infer the output type of a Standard Schema V1 schema. */
export type InferOutput<T extends StandardSchemaV1> = StandardSchemaV1.InferOutput<T>;

/**
 * Extract the request body with full type inference. The `_schema`
 * parameter is used only for TypeScript type inference — no runtime
 * validation occurs.
 */
export async function vBody<T extends StandardSchemaV1>(c: Context, _schema: T): Promise<InferOutput<T>> {
  return c.req.json();
}

/**
 * Extract route parameters with full type inference. The `_schema` parameter
 * is used only for TypeScript type inference — no runtime validation occurs.
 */
export function vParam<T extends StandardSchemaV1>(c: Context, _schema: T): InferOutput<T> {
  return c.req.param() as InferOutput<T>;
}

/**
 * Extract query parameters with full type inference. The `_schema`
 * parameter is used only for TypeScript type inference — no runtime
 * validation occurs.
 */
export function vQuery<T extends StandardSchemaV1>(c: Context, _schema: T): InferOutput<T> {
  return c.req.query() as InferOutput<T>;
}
