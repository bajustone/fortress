/**
 * JSON Schema types (draft 2020-12 subset) + FortressSchema.
 *
 * FortressSchema<T> extends JSONSchema with Standard Schema V1 support,
 * giving each schema: JSON Schema fields (OpenAPI), runtime validation,
 * and TypeScript type inference — all from one object.
 */

import type { StandardSchemaV1 } from './standard-schema';

/** A subset of JSON Schema (draft 2020-12) sufficient for fortress endpoint definitions and OpenAPI generation. */
export interface JSONSchema {
  type?: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object' | 'null';
  properties?: Record<string, JSONSchema>;
  required?: string[];
  items?: JSONSchema;
  enum?: (string | number | boolean | null)[];
  const?: string | number | boolean | null;
  format?: string;
  description?: string;
  default?: unknown;
  nullable?: boolean;
  oneOf?: JSONSchema[];
  anyOf?: JSONSchema[];
  allOf?: JSONSchema[];
  $ref?: string;
  additionalProperties?: boolean | JSONSchema;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  title?: string;
}

/**
 * A JSON Schema object that also implements Standard Schema V1.
 *
 * - JSON Schema fields → OpenAPI 3.1 spec generation
 * - `~standard.validate()` → runtime validation
 * - `StandardSchemaV1.InferOutput<typeof schema>` → TypeScript type inference
 */
export type FortressSchema<T = unknown> = JSONSchema & StandardSchemaV1<T, T>;

/** Extract the TypeScript type from a FortressSchema or StandardSchemaV1. */
export type Infer<T> = T extends StandardSchemaV1<any, infer O> ? O : unknown;

/** Flatten intersection types for clean IDE tooltips. */
export type Simplify<T> = { [K in keyof T]: T[K] } & {};
