import type { JSONSchema } from './json-schema';

/** JSON Schema keywords whose values are themselves schemas. */
const SINGLE_SCHEMA_KEYWORDS = new Set([
  'additionalProperties',
  'contains',
  'contentSchema',
  'else',
  'if',
  'items',
  'not',
  'propertyNames',
  'then',
  'unevaluatedItems',
  'unevaluatedProperties',
]);

/** JSON Schema keywords whose values are arrays of schemas. */
const SCHEMA_ARRAY_KEYWORDS = new Set(['allOf', 'anyOf', 'oneOf', 'prefixItems']);

/** JSON Schema keywords whose values are property-name → schema maps. */
const SCHEMA_MAP_KEYWORDS = new Set([
  '$defs',
  'definitions',
  'dependentSchemas',
  'patternProperties',
  'properties',
]);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Visit `$ref` assertions only at schema locations.
 *
 * Property names and annotation data are ordinary JSON data: a property named
 * `$ref`, or `{ default: { $ref: 'literal data' } }`, is not a reference.
 * Traversal therefore follows only keywords whose values are subschemas.
 */
export function visitSchemaRefs(
  schema: unknown,
  visit: (ref: unknown) => void,
  seen: WeakSet<object> = new WeakSet(),
): void {
  if (!isObject(schema) || Array.isArray(schema) || seen.has(schema))
    return;
  seen.add(schema);

  if (Object.hasOwn(schema, '$ref'))
    visit(schema.$ref);

  for (const [keyword, value] of Object.entries(schema)) {
    if (SINGLE_SCHEMA_KEYWORDS.has(keyword)) {
      // Pre-2020 tuple schemas used an array under `items`; supporting it here
      // keeps reference validation aligned with the existing code generator.
      if (Array.isArray(value)) {
        for (const child of value)
          visitSchemaRefs(child, visit, seen);
      }
      else {
        visitSchemaRefs(value, visit, seen);
      }
      continue;
    }

    if (SCHEMA_ARRAY_KEYWORDS.has(keyword)) {
      if (Array.isArray(value)) {
        for (const child of value)
          visitSchemaRefs(child, visit, seen);
      }
      continue;
    }

    if (SCHEMA_MAP_KEYWORDS.has(keyword)) {
      if (isObject(value) && !Array.isArray(value)) {
        for (const child of Object.values(value))
          visitSchemaRefs(child, visit, seen);
      }
      continue;
    }

    // Drafts before 2019 allowed schema-valued entries in `dependencies`.
    if (keyword === 'dependencies' && isObject(value) && !Array.isArray(value)) {
      for (const child of Object.values(value)) {
        if (!Array.isArray(child))
          visitSchemaRefs(child, visit, seen);
      }
    }
  }
}

function enter(value: object, ancestors: Set<object>): void {
  if (ancestors.has(value)) {
    throw new Error(
      'Schema contains a reference cycle; use a local $ref '
      + '(\'#/components/schemas/<name>\') instead of a self-referential object.',
    );
  }
  ancestors.add(value);
}

/** Clone annotation/property-map data without interpreting its keys. */
function cleanData(value: unknown, ancestors: Set<object>): unknown {
  if (!isObject(value))
    return value;

  enter(value, ancestors);
  try {
    if (Array.isArray(value))
      return value.map(entry => cleanData(entry, ancestors));

    return Object.fromEntries(
      Object.entries(value)
        .filter(([, entry]) => typeof entry !== 'function' && entry !== undefined)
        .map(([key, entry]) => [key, cleanData(entry, ancestors)]),
    );
  }
  finally {
    ancestors.delete(value);
  }
}

function cleanSchemaMap(value: unknown, ancestors: Set<object>): unknown {
  if (!isObject(value) || Array.isArray(value))
    return cleanData(value, ancestors);

  enter(value, ancestors);
  try {
    return Object.fromEntries(
      Object.entries(value)
        // Map keys are user data. In particular, `~field` and `$ref` are
        // both legal property names and must survive unchanged.
        .map(([name, child]) => [name, cleanJsonSchema(child as JSONSchema, ancestors)]),
    );
  }
  finally {
    ancestors.delete(value);
  }
}

function cleanSchemaArray(value: unknown, ancestors: Set<object>): unknown {
  if (!Array.isArray(value))
    return cleanData(value, ancestors);

  enter(value, ancestors);
  try {
    return value.map(child => cleanJsonSchema(child as JSONSchema, ancestors));
  }
  finally {
    ancestors.delete(value);
  }
}

/**
 * Remove runtime-only metadata from schema nodes while preserving schema data.
 *
 * Fortress's `~standard` metadata lives on schema objects. Property maps,
 * defaults, discriminator mappings, enum members, unknown extension keywords,
 * and other annotations are data, so their keys are cloned verbatim.
 */
export function cleanJsonSchema<T extends JSONSchema>(
  schema: T,
  ancestors: Set<object> = new Set(),
): T {
  if (!isObject(schema) || Array.isArray(schema))
    return cleanData(schema, ancestors) as T;

  enter(schema, ancestors);
  try {
    const entries: Array<[string, unknown]> = [];
    for (const [keyword, value] of Object.entries(schema)) {
      if (keyword === '~standard' || typeof value === 'function' || value === undefined)
        continue;

      if (SCHEMA_MAP_KEYWORDS.has(keyword)) {
        entries.push([keyword, cleanSchemaMap(value, ancestors)]);
      }
      else if (SCHEMA_ARRAY_KEYWORDS.has(keyword)) {
        entries.push([keyword, cleanSchemaArray(value, ancestors)]);
      }
      else if (SINGLE_SCHEMA_KEYWORDS.has(keyword)) {
        entries.push([
          keyword,
          Array.isArray(value)
            ? cleanSchemaArray(value, ancestors)
            : isObject(value)
              ? cleanJsonSchema(value as JSONSchema, ancestors)
              : value,
        ]);
      }
      else if (keyword === 'dependencies' && isObject(value) && !Array.isArray(value)) {
        enter(value, ancestors);
        try {
          entries.push([keyword, Object.fromEntries(
            Object.entries(value).map(([name, dependency]) => [
              name,
              Array.isArray(dependency)
                ? cleanData(dependency, ancestors)
                : cleanJsonSchema(dependency as JSONSchema, ancestors),
            ]),
          )]);
        }
        finally {
          ancestors.delete(value);
        }
      }
      else {
        entries.push([keyword, cleanData(value, ancestors)]);
      }
    }
    return Object.fromEntries(entries) as unknown as T;
  }
  finally {
    ancestors.delete(schema);
  }
}
