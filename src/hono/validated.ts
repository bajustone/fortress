/**
 * Typed validation helpers for Hono handlers.
 *
 * These helpers extract request data (body, params, query) with full
 * TypeScript type inference using Standard Schema V1's type system.
 *
 * **Zero runtime validation cost** — fortress's `createValidationMiddleware`
 * must be registered upstream and validates requests before handlers run.
 * The schema parameter is used only for TypeScript type inference.
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
 * Extract the validated request body with full type inference.
 *
 * **Requires `createValidationMiddleware(endpoints)` registered upstream.**
 * The `_schema` parameter is used only for TypeScript type inference —
 * no validation occurs here. If the middleware is missing, the data
 * will be unvalidated despite appearing typed.
 */
export async function vBody<T extends StandardSchemaV1>(c: Context, _schema: T): Promise<InferOutput<T>> {
  return c.req.json();
}

/**
 * Extract validated route parameters with full type inference.
 *
 * **Requires `createValidationMiddleware(endpoints)` registered upstream.**
 * The `_schema` parameter is used only for TypeScript type inference —
 * no validation occurs here. If the middleware is missing, the data
 * will be unvalidated despite appearing typed.
 */
export function vParam<T extends StandardSchemaV1>(c: Context, _schema: T): InferOutput<T> {
  return c.req.param() as InferOutput<T>;
}

/**
 * Extract validated query parameters with full type inference.
 *
 * **Requires `createValidationMiddleware(endpoints)` registered upstream.**
 * The `_schema` parameter is used only for TypeScript type inference —
 * no validation occurs here. If the middleware is missing, the data
 * will be unvalidated despite appearing typed.
 */
export function vQuery<T extends StandardSchemaV1>(c: Context, _schema: T): InferOutput<T> {
  return c.req.query() as InferOutput<T>;
}
