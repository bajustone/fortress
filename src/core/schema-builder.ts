import type { EndpointDefinition, EndpointResponse, HttpMethod, SecurityRequirement } from './endpoint';
import type { FortressSchema, Infer, JSONSchema, Simplify } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';
import { validateJsonSchema } from './json-schema-validator';

// ── Standard Schema wiring ─────────────────────────────────────────

function createStandardProps<T>(schema: JSONSchema): StandardSchemaV1<T, T>['~standard'] {
  return {
    version: 1,
    vendor: 'fortress',
    validate(value: unknown): StandardSchemaV1.Result<T> {
      const issues = validateJsonSchema(schema, value);
      if (issues.length > 0)
        return { issues };
      return { value: value as T };
    },
  } as StandardSchemaV1<T, T>['~standard'];
}

function toFortressSchema<T>(schema: JSONSchema): FortressSchema<T> {
  return Object.assign(schema, {
    '~standard': createStandardProps<T>(schema),
  }) as FortressSchema<T>;
}

// ── Schema Builders ─────────────────────────────────────────────────

export function str(description?: string): FortressSchema<string> {
  const s: JSONSchema = { type: 'string' };
  if (description)
    s.description = description;
  return toFortressSchema<string>(s);
}

export function num(description?: string): FortressSchema<number> {
  const s: JSONSchema = { type: 'number' };
  if (description)
    s.description = description;
  return toFortressSchema<number>(s);
}

export function int(description?: string): FortressSchema<number> {
  const s: JSONSchema = { type: 'integer' };
  if (description)
    s.description = description;
  return toFortressSchema<number>(s);
}

export function bool(description?: string): FortressSchema<boolean> {
  const s: JSONSchema = { type: 'boolean' };
  if (description)
    s.description = description;
  return toFortressSchema<boolean>(s);
}

export function arr<T>(items: FortressSchema<T>, description?: string): FortressSchema<T[]> {
  const s: JSONSchema = { type: 'array', items };
  if (description)
    s.description = description;
  return toFortressSchema<T[]>(s);
}

export function obj<
  P extends Record<string, FortressSchema<any>>,
  K extends (keyof P & string)[] = [],
>(
  properties: P,
  ...required: K
): FortressSchema<
  Simplify<
    { [Key in K[number]]: Infer<P[Key]> }
    & { [Key in Exclude<keyof P & string, K[number]>]?: Infer<P[Key]> }
  >
> {
  const s: JSONSchema = { type: 'object', properties: properties as Record<string, JSONSchema> };
  if (required.length > 0)
    s.required = required;
  return toFortressSchema(s);
}

export function nullable<T>(schema: FortressSchema<T>): FortressSchema<T | null> {
  const s: JSONSchema = { ...schema, nullable: true };
  return toFortressSchema<T | null>(s);
}

export function oneOf<S extends FortressSchema<any>[]>(
  ...schemas: S
): FortressSchema<Infer<S[number]>> {
  return toFortressSchema<Infer<S[number]>>({ oneOf: schemas as JSONSchema[] });
}

export function anyOf<S extends FortressSchema<any>[]>(
  ...schemas: S
): FortressSchema<Infer<S[number]>> {
  return toFortressSchema<Infer<S[number]>>({ anyOf: schemas as JSONSchema[] });
}

export function ref(name: string): FortressSchema<unknown> {
  return toFortressSchema<unknown>({ $ref: `#/components/schemas/${name}` });
}

export function enums<T extends string | number>(...values: T[]): FortressSchema<T> {
  return toFortressSchema<T>({ enum: values });
}

export function strFormat(format: string, description?: string): FortressSchema<string> {
  const s: JSONSchema = { type: 'string', format };
  if (description)
    s.description = description;
  return toFortressSchema<string>(s);
}

export function nullType(): FortressSchema<null> {
  return toFortressSchema<null>({ type: 'null' });
}

/** An object with unknown additional properties (e.g., plugin data, metadata). */
export function record(description?: string): FortressSchema<Record<string, unknown>> {
  const s: JSONSchema = { type: 'object', additionalProperties: true };
  if (description)
    s.description = description;
  return toFortressSchema<Record<string, unknown>>(s);
}

/** A record where values match a specific schema. */
export function recordOf<T>(valueSchema: FortressSchema<T>, description?: string): FortressSchema<Record<string, T>> {
  const s: JSONSchema = { type: 'object', additionalProperties: valueSchema as JSONSchema };
  if (description)
    s.description = description;
  return toFortressSchema<Record<string, T>>(s);
}

// ── Schema detection helpers ────────────────────────────────────────

/** Check if a value implements Standard Schema V1. */
export function isStandardSchema(value: unknown): value is StandardSchemaV1 {
  return (
    typeof value === 'object'
    && value !== null
    && '~standard' in value
    && typeof (value as any)['~standard']?.validate === 'function'
  );
}

/** Check if a value is a FortressSchema (has both JSON Schema fields and Standard Schema). */
export function isFortressSchema(value: unknown): value is FortressSchema {
  return isStandardSchema(value) && ('type' in (value as any) || '$ref' in (value as any) || 'oneOf' in (value as any) || 'anyOf' in (value as any));
}

/**
 * Extract JSON Schema from a schema input.
 * - FortressSchema: return as-is (it IS JSON Schema)
 * - External Standard Schema: extract via ~standard.jsonSchema if available, otherwise empty object
 */
export function extractJsonSchema(schema: FortressSchema<any> | StandardSchemaV1<any>): JSONSchema {
  if (isFortressSchema(schema)) {
    return schema;
  }
  // External Standard Schema — try StandardJSONSchemaV1 interface
  const std = (schema as any)['~standard'];
  if (std?.jsonSchema?.input) {
    return std.jsonSchema.input({ target: 'draft-2020-12' }) as JSONSchema;
  }
  // Fallback: no JSON Schema available from external schema
  return {};
}

// ── Schema input type for endpoint builder ──────────────────────────

export type SchemaInput = FortressSchema<any> | StandardSchemaV1<any>;

// ── Endpoint Builder ────────────────────────────────────────────────

export class EndpointBuilder {
  private _method: HttpMethod;
  private _path: string;
  private _handler = '';
  private _summary = '';
  private _description?: string;
  private _tags: string[] = [];
  private _security: SecurityRequirement[] = [];
  private _deprecated = false;
  private _permission?: { resource: string; action: string };
  private _body?: SchemaInput;
  private _query?: SchemaInput;
  private _params?: SchemaInput;
  private _responses: Record<number, EndpointResponse> = {};

  constructor(method: HttpMethod, path: string) {
    this._method = method;
    this._path = path;
  }

  summary(s: string): this {
    this._summary = s;
    return this;
  }

  description(s: string): this {
    this._description = s;
    return this;
  }

  tags(...t: string[]): this {
    this._tags.push(...t);
    return this;
  }

  security(...s: SecurityRequirement[]): this {
    this._security.push(...s);
    return this;
  }

  deprecated(): this {
    this._deprecated = true;
    return this;
  }

  permission(resource: string, action: string): this {
    this._permission = { resource, action };
    return this;
  }

  body(schema: SchemaInput): this {
    this._body = schema;
    return this;
  }

  query(schema: SchemaInput): this {
    this._query = schema;
    return this;
  }

  params(schema: SchemaInput): this {
    this._params = schema;
    return this;
  }

  response(status: number, description: string, schema?: JSONSchema): this {
    this._responses[status] = { description, schema };
    return this;
  }

  handler(name: string): this {
    this._handler = name;
    return this;
  }

  build(): EndpointDefinition {
    const def: EndpointDefinition = {
      method: this._method,
      path: this._path,
      handler: this._handler,
    };

    if (this._summary || this._tags.length > 0 || this._security.length > 0 || this._description || this._deprecated || this._permission) {
      def.meta = {
        summary: this._summary,
        ...(this._description && { description: this._description }),
        ...(this._tags.length > 0 && { tags: this._tags }),
        ...(this._security.length > 0 && { security: this._security }),
        ...(this._deprecated && { deprecated: true }),
        ...(this._permission && { permission: this._permission }),
      };
    }

    if (this._body || this._query || this._params) {
      def.input = {};
      if (this._body) {
        def.input.body = extractJsonSchema(this._body);
        if (isStandardSchema(this._body))
          def.input.bodySchema = this._body;
      }
      if (this._query) {
        def.input.query = extractJsonSchema(this._query);
        if (isStandardSchema(this._query))
          def.input.querySchema = this._query;
      }
      if (this._params) {
        def.input.params = extractJsonSchema(this._params);
        if (isStandardSchema(this._params))
          def.input.paramsSchema = this._params;
      }
    }

    if (Object.keys(this._responses).length > 0) {
      def.responses = this._responses;
    }

    return def;
  }
}

export function endpoint(method: HttpMethod, path: string): EndpointBuilder {
  return new EndpointBuilder(method, path);
}
