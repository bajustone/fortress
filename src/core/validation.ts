/**
 * Runtime request validation using Standard Schema.
 *
 * Validates body/query/params against schemas stored in EndpointInput.
 * Works with any Standard Schema provider (fortress, Zod, Valibot, ArkType).
 */

import type { EndpointInput } from './endpoint';
import type { StandardSchemaV1 } from './standard-schema';
import { Errors } from './errors';

/**
 * Validate request data against endpoint input schemas.
 * Throws FortressError('VALIDATION_ERROR') on failure.
 *
 * Uses `~standard.validate()` from whichever schema is attached
 * (fortress built-in or external Standard Schema).
 */
export async function validateRequest(
  input: EndpointInput | undefined,
  data: { body?: unknown; query?: unknown; params?: unknown },
): Promise<void> {
  if (!input)
    return;

  const allIssues: Array<{ path?: unknown; message: string; location: string }> = [];

  if (input.bodySchema) {
    const issues = await validateSchema(input.bodySchema, data.body, 'body');
    allIssues.push(...issues);
  }

  if (input.querySchema) {
    const issues = await validateSchema(input.querySchema, data.query, 'query');
    allIssues.push(...issues);
  }

  if (input.paramsSchema) {
    const issues = await validateSchema(input.paramsSchema, data.params, 'params');
    allIssues.push(...issues);
  }

  if (allIssues.length > 0) {
    throw Errors.validationError(allIssues);
  }
}

async function validateSchema(
  schema: StandardSchemaV1,
  data: unknown,
  location: string,
): Promise<Array<{ path?: unknown; message: string; location: string }>> {
  const result = await schema['~standard'].validate(data);
  if (result.issues) {
    return result.issues.map(issue => ({
      path: issue.path,
      message: issue.message,
      location,
    }));
  }
  return [];
}

/**
 * Validate a single value against a Standard Schema and return the parsed
 * value, or throw `Errors.validationError` on failure.
 *
 * Used by the per-handler request-extraction helpers (`vBody`/`vParam`/
 * `vQuery`) in each framework adapter. Unlike {@link validateRequest}, which
 * aggregates issues across body+query+params, this validates one location
 * at a time — appropriate for per-handler call sites where a single helper
 * call corresponds to a single piece of request data.
 *
 * The thrown `FortressError` is byte-identical to what `validateRequest`
 * produces (HTTP 422, `VALIDATION_ERROR`, `details: issues[]`), so adapter
 * error handlers format both consistently.
 */
export async function validateValue<T extends StandardSchemaV1>(
  schema: T,
  data: unknown,
  location: 'body' | 'query' | 'params',
): Promise<StandardSchemaV1.InferOutput<T>> {
  const result = await schema['~standard'].validate(data);
  if (result.issues) {
    throw Errors.validationError(
      result.issues.map(issue => ({
        path: issue.path,
        message: issue.message,
        location,
      })),
    );
  }
  return result.value as StandardSchemaV1.InferOutput<T>;
}
