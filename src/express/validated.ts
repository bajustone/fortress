/**
 * Typed extraction-and-validation helpers for Express handlers.
 *
 * These helpers extract request data (body, params, query) **and validate
 * it at runtime** against the supplied Standard Schema. On success they
 * return the parsed value with full TypeScript inference; on failure they
 * throw `FortressError('VALIDATION_ERROR', 422)` — the same shape every
 * fortress-managed endpoint produces — so the existing Express error
 * handler (`createErrorHandler`) formats it identically.
 *
 * Works with any Standard Schema V1 library: Zod, Valibot, ArkType, or
 * fortress's built-in schema builders.
 *
 * Assumes body-parsing middleware (e.g. `app.use(express.json())`) has
 * already populated `req.body` for `vBody` to read.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { vBody, vParam, vQuery, createErrorHandler } from '@bajustone/fortress/express';
 * import { obj, str } from '@bajustone/fortress';
 *
 * const app = express();
 * app.use(express.json());
 *
 * const Body  = obj({ name: str() }, 'name');
 * const Param = obj({ id: str() }, 'id');
 *
 * app.patch('/users/:id', async (req, res, next) => {
 *   try {
 *     const { id }   = await vParam(req, Param);
 *     const { name } = await vBody(req, Body);
 *     res.json({ id, name });
 *   }
 *   catch (err) { next(err); }
 * });
 *
 * app.use(createErrorHandler());
 * ```
 *
 * Validation runs per call, so the first failing helper throws and any
 * downstream helpers in the same handler do not run. If you need to
 * aggregate body+query+params issues into a single response, use the
 * framework-agnostic `validateRequest` from `@bajustone/fortress` instead.
 */

import type { StandardSchemaV1 } from '../core/standard-schema';
import { validateValue } from '../core/validation';

/** Infer the output type of a Standard Schema V1 schema. */
export type InferOutput<T extends StandardSchemaV1> = StandardSchemaV1.InferOutput<T>;

/**
 * Structural shape of an Express `Request` accepted by these helpers.
 * Defined locally instead of importing from `express` so fortress can ship
 * without a hard `express` dependency. Compatible by structural typing with
 * the real `express.Request` — consumers pass their `req` directly.
 */
export interface ExpressRequestLike {
  body?: unknown;
  params?: unknown;
  query?: unknown;
}

/**
 * Extract and validate the request body. Assumes body-parsing middleware
 * (e.g. `express.json()`) populated `req.body`. Returns the parsed value
 * typed as `InferOutput<T>`, or throws `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vBody<T extends StandardSchemaV1>(
  req: ExpressRequestLike,
  schema: T,
): Promise<InferOutput<T>> {
  return validateValue(schema, req.body, 'body');
}

/**
 * Extract and validate route parameters from `req.params`. Returns the
 * parsed value typed as `InferOutput<T>`, or throws
 * `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vParam<T extends StandardSchemaV1>(
  req: ExpressRequestLike,
  schema: T,
): Promise<InferOutput<T>> {
  return validateValue(schema, req.params, 'params');
}

/**
 * Extract and validate query parameters from `req.query`. Returns the
 * parsed value typed as `InferOutput<T>`, or throws
 * `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vQuery<T extends StandardSchemaV1>(
  req: ExpressRequestLike,
  schema: T,
): Promise<InferOutput<T>> {
  return validateValue(schema, req.query, 'query');
}
