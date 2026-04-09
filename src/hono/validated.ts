/**
 * Typed extraction-and-validation helpers for Hono handlers.
 *
 * These helpers extract request data (body, params, query) **and validate
 * it at runtime** against the supplied Standard Schema. On success they
 * return the parsed value with full TypeScript inference; on failure they
 * throw `FortressError('VALIDATION_ERROR', 422)` — the same shape every
 * fortress-managed endpoint produces — so the existing Hono error handler
 * formats it identically.
 *
 * Works with any Standard Schema V1 library: Zod, Valibot, ArkType, or
 * fortress's built-in schema builders.
 *
 * @example
 * ```ts
 * import { vBody, vParam, vQuery } from '@bajustone/fortress/hono';
 *
 * app.post('/users/:id', async (c) => {
 *   const body     = await vBody(c, CreateUserBody);
 *   const { id }   = await vParam(c, IdParam);
 *   const { page } = await vQuery(c, PaginationQuery);
 *   // ...
 * });
 * ```
 *
 * Validation runs per call, so the first failing helper throws and any
 * downstream helpers in the same handler do not run. If you need to
 * aggregate body+query+params issues into a single response, use the
 * framework-agnostic `validateRequest` from `@bajustone/fortress` instead.
 */

import type { Context } from 'hono';
import type { StandardSchemaV1 } from '../core/standard-schema';
import { validateValue } from '../core/validation';

/** Infer the output type of a Standard Schema V1 schema. */
export type InferOutput<T extends StandardSchemaV1> = StandardSchemaV1.InferOutput<T>;

/**
 * Extract and validate the request body. Returns the parsed value typed as
 * `InferOutput<T>`, or throws `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vBody<T extends StandardSchemaV1>(c: Context, schema: T): Promise<InferOutput<T>> {
  const body = await c.req.json().catch(() => undefined);
  return validateValue(schema, body, 'body');
}

/**
 * Extract and validate route parameters. Returns the parsed value typed as
 * `InferOutput<T>`, or throws `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vParam<T extends StandardSchemaV1>(c: Context, schema: T): Promise<InferOutput<T>> {
  return validateValue(schema, c.req.param(), 'params');
}

/**
 * Extract and validate query parameters. Returns the parsed value typed as
 * `InferOutput<T>`, or throws `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vQuery<T extends StandardSchemaV1>(c: Context, schema: T): Promise<InferOutput<T>> {
  return validateValue(schema, c.req.query(), 'query');
}
