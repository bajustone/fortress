/**
 * Lightweight JSON Schema validator for fortress's built-in schemas.
 *
 * Handles the subset fortress uses — no external deps (no ajv).
 * Returns Standard Schema Result format.
 */

import type { JSONSchema } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';

export function validateJsonSchema(
  schema: JSONSchema,
  data: unknown,
  path: string[] = [],
): StandardSchemaV1.Issue[] {
  const issues: StandardSchemaV1.Issue[] = [];

  // Nullable check
  if (data === null) {
    if (schema.nullable)
      return [];
    if (schema.type === 'null')
      return [];
    issues.push({ message: 'Expected non-null value', path: toPath(path) });
    return issues;
  }

  // Type check
  if (schema.type && data !== null) {
    if (!checkType(schema.type, data)) {
      issues.push({
        message: `Expected ${schema.type}, got ${typeof data}`,
        path: toPath(path),
      });
      return issues; // type mismatch — skip deeper checks
    }
  }

  // Enum
  if (schema.enum) {
    if (!schema.enum.includes(data as string | number | boolean | null)) {
      issues.push({
        message: `Expected one of: ${schema.enum.join(', ')}`,
        path: toPath(path),
      });
    }
  }

  // String constraints
  if (typeof data === 'string') {
    if (schema.minLength !== undefined && data.length < schema.minLength) {
      issues.push({
        message: `String must be at least ${schema.minLength} characters`,
        path: toPath(path),
      });
    }
    if (schema.maxLength !== undefined && data.length > schema.maxLength) {
      issues.push({
        message: `String must be at most ${schema.maxLength} characters`,
        path: toPath(path),
      });
    }
    if (schema.pattern) {
      const re = new RegExp(schema.pattern);
      if (!re.test(data)) {
        issues.push({
          message: `String must match pattern: ${schema.pattern}`,
          path: toPath(path),
        });
      }
    }
  }

  // Number constraints
  if (typeof data === 'number') {
    if (schema.minimum !== undefined && data < schema.minimum) {
      issues.push({
        message: `Number must be >= ${schema.minimum}`,
        path: toPath(path),
      });
    }
    if (schema.maximum !== undefined && data > schema.maximum) {
      issues.push({
        message: `Number must be <= ${schema.maximum}`,
        path: toPath(path),
      });
    }
  }

  // Object: required + properties
  if (schema.type === 'object' && typeof data === 'object' && data !== null) {
    const obj = data as Record<string, unknown>;

    if (schema.required) {
      for (const key of schema.required) {
        if (!(key in obj) || obj[key] === undefined) {
          issues.push({
            message: `Missing required field: ${key}`,
            path: toPath([...path, key]),
          });
        }
      }
    }

    if (schema.properties) {
      for (const [key, propSchema] of Object.entries(schema.properties)) {
        if (key in obj) {
          issues.push(...validateJsonSchema(propSchema, obj[key], [...path, key]));
        }
      }
    }
  }

  // Array: items
  if (schema.type === 'array' && Array.isArray(data)) {
    if (schema.items) {
      for (let i = 0; i < data.length; i++) {
        issues.push(...validateJsonSchema(schema.items, data[i], [...path, String(i)]));
      }
    }
  }

  // oneOf
  if (schema.oneOf) {
    const matches = schema.oneOf.filter(
      s => validateJsonSchema(s, data, path).length === 0,
    );
    if (matches.length !== 1) {
      issues.push({
        message: matches.length === 0
          ? 'Value does not match any of the expected schemas'
          : 'Value matches multiple schemas (expected exactly one)',
        path: toPath(path),
      });
    }
  }

  // anyOf
  if (schema.anyOf) {
    const hasMatch = schema.anyOf.some(
      s => validateJsonSchema(s, data, path).length === 0,
    );
    if (!hasMatch) {
      issues.push({
        message: 'Value does not match any of the expected schemas',
        path: toPath(path),
      });
    }
  }

  return issues;
}

function checkType(type: string, data: unknown): boolean {
  switch (type) {
    case 'string':
      return typeof data === 'string';
    case 'number':
    case 'integer':
      return typeof data === 'number' && (type !== 'integer' || Number.isInteger(data));
    case 'boolean':
      return typeof data === 'boolean';
    case 'object':
      return typeof data === 'object' && data !== null && !Array.isArray(data);
    case 'array':
      return Array.isArray(data);
    case 'null':
      return data === null;
    default:
      return true;
  }
}

function toPath(parts: string[]): StandardSchemaV1.PathSegment[] {
  return parts.map(key => ({ key }));
}
