/**
 * Runtime request validation using Standard Schema.
 *
 * Validates body/query/params against schemas stored in EndpointInput.
 * Works with any Standard Schema provider (fortress, Zod, Valibot, ArkType).
 */

import type { EndpointInput } from './endpoint';
import type { JSONSchema } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';
import { fromJSONSchema } from '@bajustone/fetcher/openapi';
import { Errors } from './errors';

// Keep URL numerics deliberately narrower than Number(): no exponent, sign, or
// hexadecimal forms. The spelling must round-trip exactly so precision loss,
// leading zeroes, and other non-canonical values remain validation failures.
const DECIMAL_INTEGER_RE = /^-?\d+$/;
const DECIMAL_NUMBER_RE = /^-?\d+(?:\.\d+)?$/;
const rawSchemaValidators = new WeakMap<object, StandardSchemaV1>();

function standardSchemaFor(schema: StandardSchemaV1 | JSONSchema): StandardSchemaV1 {
  if ('~standard' in schema)
    return schema as StandardSchemaV1;
  let compiled = rawSchemaValidators.get(schema as object);
  if (!compiled) {
    compiled = fromJSONSchema(schema as object) as unknown as StandardSchemaV1;
    rawSchemaValidators.set(schema as object, compiled);
  }
  return compiled;
}

/**
 * Coerce URL-sourced query/params values to the types declared in a JSON
 * Schema before runtime validation. HTTP path and query parameters arrive
 * as strings from URL parsing, but endpoint schemas often declare them as
 * `integer` / `number` / `boolean` for the purposes of OpenAPI docs and
 * type inference. Without coercion, every `:id` / `?limit=10` would fail
 * strict JSON Schema validation.
 *
 * Body data is _not_ run through this — JSON body values already arrive
 * with their native types.
 *
 * Unknown or unparseable values pass through unchanged; the downstream
 * validator produces the actual error if they don't match. Only the four
 * primitive types (`integer`, `number`, `boolean`, `string`) are coerced
 * — nested objects/arrays in query strings are out of scope.
 */
export function coerceBySchema(
  schema: JSONSchema | undefined,
  data: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!schema || !data || schema.type !== 'object' || !schema.properties)
    return data;

  const out: Record<string, unknown> = { ...data };
  for (const [key, propSchema] of Object.entries(schema.properties)) {
    const value = out[key];
    if (typeof value !== 'string')
      continue;
    const coerced = coerceScalar(propSchema as JSONSchema, value);
    if (coerced !== undefined)
      out[key] = coerced;
  }
  return out;
}

function coerceScalar(schema: JSONSchema, value: string): unknown {
  // `enums()` and `literal()` intentionally omit `type`; infer numeric URL
  // parameters from their numeric constraints so `/items?id=1` can satisfy
  // `{ enum: [1, 2] }` and `{ const: 1 }`.
  const type = schema.type ?? numericConstraintType(schema);
  switch (type) {
    case 'integer': {
      if (!DECIMAL_INTEGER_RE.test(value))
        return undefined;
      const n = Number(value);
      if (Number.isFinite(n) && Number.isSafeInteger(n) && String(n) === value)
        return n;
      return undefined;
    }
    case 'number': {
      if (!DECIMAL_NUMBER_RE.test(value))
        return undefined;
      const n = Number(value);
      if (Number.isFinite(n) && (!Number.isInteger(n) || Number.isSafeInteger(n)) && String(n) === value)
        return n;
      return undefined;
    }
    case 'boolean': {
      if (value === 'true')
        return true;
      if (value === 'false')
        return false;
      return undefined;
    }
    default:
      // Leave strings (and anything else) alone.
      return undefined;
  }
}

function numericConstraintType(schema: JSONSchema): 'integer' | 'number' | undefined {
  if (typeof schema.const === 'number')
    return Number.isInteger(schema.const) ? 'integer' : 'number';
  if (schema.enum && schema.enum.length > 0 && schema.enum.every(value => typeof value === 'number'))
    return schema.enum.every(value => Number.isInteger(value as number)) ? 'integer' : 'number';
  return undefined;
}

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

  if (input.bodySchema || input.body) {
    const issues = await validateSchema(input.bodySchema ?? input.body!, data.body, 'body');
    allIssues.push(...issues);
  }

  if (input.querySchema || input.query) {
    const issues = await validateSchema(input.querySchema ?? input.query!, data.query, 'query');
    allIssues.push(...issues);
  }

  if (input.paramsSchema || input.params) {
    const issues = await validateSchema(input.paramsSchema ?? input.params!, data.params, 'params');
    allIssues.push(...issues);
  }

  if (allIssues.length > 0) {
    throw Errors.validationError(allIssues);
  }
}

async function validateSchema(
  schema: StandardSchemaV1 | JSONSchema,
  data: unknown,
  location: string,
): Promise<Array<{ path?: unknown; message: string; location: string }>> {
  const result = await standardSchemaFor(schema)['~standard'].validate(data);
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
