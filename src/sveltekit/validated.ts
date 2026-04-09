/**
 * Typed extraction-and-validation helpers for SvelteKit `+server.ts` handlers
 * and form actions.
 *
 * These helpers extract request data (body, params, query) **and validate
 * it at runtime** against the supplied Standard Schema. On success they
 * return the parsed value with full TypeScript inference; on failure they
 * throw `FortressError('VALIDATION_ERROR', 422)` — the same shape every
 * fortress-managed endpoint produces — so the existing SvelteKit error
 * mapping (via `errorToResponse`) formats it identically.
 *
 * Works with any Standard Schema V1 library: Zod, Valibot, ArkType, or
 * fortress's built-in schema builders.
 *
 * @example
 * ```ts
 * // src/routes/api/users/[id]/+server.ts
 * import { vBody, vParam } from '@bajustone/fortress/sveltekit';
 * import { obj, str } from '@bajustone/fortress';
 *
 * const UpdateBody = obj({ name: str() }, 'name');
 * const Params = obj({ id: str() }, 'id');
 *
 * export async function PATCH(event) {
 *   const { id }   = await vParam(event, Params);
 *   const { name } = await vBody(event, UpdateBody);
 *   // ...
 * }
 * ```
 *
 * Validation runs per call, so the first failing helper throws and any
 * downstream helpers in the same handler do not run. If you need to
 * aggregate body+query+params issues into a single response, use the
 * framework-agnostic `validateRequest` from `@bajustone/fortress` instead.
 */

import type { StandardSchemaV1 } from '../core/standard-schema';
import type { SvelteKitRequestEvent } from './types';
import { validateValue } from '../core/validation';

/** Infer the output type of a Standard Schema V1 schema. */
export type InferOutput<T extends StandardSchemaV1> = StandardSchemaV1.InferOutput<T>;

/**
 * Extract and validate the JSON request body. Returns the parsed value typed
 * as `InferOutput<T>`, or throws `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vBody<T extends StandardSchemaV1>(
  event: SvelteKitRequestEvent,
  schema: T,
): Promise<InferOutput<T>> {
  const body = await event.request.json().catch(() => undefined);
  return validateValue(schema, body, 'body');
}

/**
 * Extract and validate route parameters from a `[param]`-style file. Returns
 * the parsed value typed as `InferOutput<T>`, or throws
 * `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vParam<T extends StandardSchemaV1>(
  event: SvelteKitRequestEvent,
  schema: T,
): Promise<InferOutput<T>> {
  return validateValue(schema, event.params, 'params');
}

/**
 * Extract and validate query parameters from `event.url.searchParams`.
 * Returns the parsed value typed as `InferOutput<T>`, or throws
 * `FortressError('VALIDATION_ERROR', 422)`.
 */
export async function vQuery<T extends StandardSchemaV1>(
  event: SvelteKitRequestEvent,
  schema: T,
): Promise<InferOutput<T>> {
  return validateValue(schema, Object.fromEntries(event.url.searchParams), 'query');
}
