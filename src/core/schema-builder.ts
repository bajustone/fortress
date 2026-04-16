import type { EndpointDefinition, EndpointResponse, HttpMethod, SecurityRequirement } from './endpoint';
import type { FortressSchema, Infer, JSONSchema, Simplify } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';
import { validateJsonSchema } from './json-schema-validator';

/** Shorthand for the Standard Schema inferred output type. */
type InferSchema<T extends StandardSchemaV1> = StandardSchemaV1.InferOutput<T>;

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

/** Build a string {@link FortressSchema}. */
export function str(description?: string): FortressSchema<string> {
  const s: JSONSchema = { type: 'string' };
  if (description)
    s.description = description;
  return toFortressSchema<string>(s);
}

/** Build a number {@link FortressSchema} (any numeric, integer or float). */
export function num(description?: string): FortressSchema<number> {
  const s: JSONSchema = { type: 'number' };
  if (description)
    s.description = description;
  return toFortressSchema<number>(s);
}

/** Build an integer {@link FortressSchema}. */
export function int(description?: string): FortressSchema<number> {
  const s: JSONSchema = { type: 'integer' };
  if (description)
    s.description = description;
  return toFortressSchema<number>(s);
}

/** Build a boolean {@link FortressSchema}. */
export function bool(description?: string): FortressSchema<boolean> {
  const s: JSONSchema = { type: 'boolean' };
  if (description)
    s.description = description;
  return toFortressSchema<boolean>(s);
}

/** Build an array {@link FortressSchema} whose items match the supplied schema. */
export function arr<T>(items: FortressSchema<T>, description?: string): FortressSchema<T[]> {
  const s: JSONSchema = { type: 'array', items };
  if (description)
    s.description = description;
  return toFortressSchema<T[]>(s);
}

/**
 * Build an object {@link FortressSchema}. Pass property names after `properties`
 * to mark them as required — they become non-optional in the inferred type.
 */
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

/** Wrap a schema so it also accepts `null`. */
export function nullable<T>(schema: FortressSchema<T>): FortressSchema<T | null> {
  const s: JSONSchema = { ...schema, nullable: true };
  return toFortressSchema<T | null>(s);
}

/** Build a discriminated-union schema (exactly one variant must match). */
export function oneOf<S extends FortressSchema<any>[]>(
  ...schemas: S
): FortressSchema<Infer<S[number]>> {
  return toFortressSchema<Infer<S[number]>>({ oneOf: schemas as JSONSchema[] });
}

/** Build a union schema (any one variant may match). */
export function anyOf<S extends FortressSchema<any>[]>(
  ...schemas: S
): FortressSchema<Infer<S[number]>> {
  return toFortressSchema<Infer<S[number]>>({ anyOf: schemas as JSONSchema[] });
}

/**
 * Build a `$ref` schema pointing at an OpenAPI component schema by name.
 *
 * Two forms:
 * - `ref(name)` — untyped `$ref`, returns `FortressSchema<unknown>`. Use when
 *   the referenced component hasn't been declared yet (e.g. self-references
 *   inside a components literal).
 * - `ref(name, schema)` — typed `$ref`. The `schema` argument is never read at
 *   runtime; it's there purely so TypeScript can copy its inferred type onto
 *   the returned ref. Use when you already have a reference to the component
 *   schema and want downstream response types to flow through.
 *
 * For the common case (typed refs against a known components map), prefer
 * {@link defineComponents} — it returns a bound `ref` that only needs a name.
 */
export function ref<T>(name: string, schema: FortressSchema<T>): FortressSchema<T>;
export function ref(name: string): FortressSchema<unknown>;
export function ref<T>(name: string, _schema?: FortressSchema<T>): FortressSchema<T> {
  return toFortressSchema<T>({ $ref: `#/components/schemas/${name}` });
}

/**
 * Declare a typed registry of OpenAPI component schemas and return a bound
 * `ref` function that preserves each component's inferred TypeScript type.
 *
 * ```ts
 * const User = obj({ id: int(), email: str() }, 'id', 'email');
 * const { components, ref } = defineComponents({ User });
 *
 * const ep = endpoint('GET', '/me')
 *   .response(200, 'Current user', ref('User'))
 *   //                             ^ FortressSchema<{ id: number; email: string }>
 *   .handler('me')
 *   .build();
 * ```
 *
 * The returned `components` is the same object you passed in (useful for
 * OpenAPI spec emission). The returned `ref` is a generic function that
 * looks up each key in `T` and returns a `$ref` schema carrying the
 * inferred type of the referenced component.
 */
export function defineComponents<T extends Record<string, FortressSchema<any>>>(
  components: T,
): {
  components: T;
  ref: <K extends keyof T & string>(name: K) => FortressSchema<Infer<T[K]>>;
} {
  return {
    components,
    ref: <K extends keyof T & string>(name: K): FortressSchema<Infer<T[K]>> => {
      return toFortressSchema<Infer<T[K]>>({ $ref: `#/components/schemas/${String(name)}` });
    },
  };
}

/** Build an enum {@link FortressSchema} from a fixed set of string or number literal values. */
export function enums<T extends string | number>(...values: T[]): FortressSchema<T> {
  return toFortressSchema<T>({ enum: values });
}

/** Build a string {@link FortressSchema} with an OpenAPI `format` annotation (e.g. `email`, `uri`, `uuid`). */
export function strFormat(format: string, description?: string): FortressSchema<string> {
  const s: JSONSchema = { type: 'string', format };
  if (description)
    s.description = description;
  return toFortressSchema<string>(s);
}

/** Build a {@link FortressSchema} that only accepts the literal `null`. */
export function nullType(): FortressSchema<null> {
  return toFortressSchema<null>({ type: 'null' });
}

/** An object {@link FortressSchema} with unknown additional properties (e.g. plugin data, metadata). */
export function record(description?: string): FortressSchema<Record<string, unknown>> {
  const s: JSONSchema = { type: 'object', additionalProperties: true };
  if (description)
    s.description = description;
  return toFortressSchema<Record<string, unknown>>(s);
}

/** An object {@link FortressSchema} where every property value matches the supplied schema. */
export function recordOf<T>(valueSchema: FortressSchema<T>, description?: string): FortressSchema<Record<string, T>> {
  const s: JSONSchema = { type: 'object', additionalProperties: valueSchema as JSONSchema };
  if (description)
    s.description = description;
  return toFortressSchema<Record<string, T>>(s);
}

// ── Schema detection helpers ────────────────────────────────────────

/** Type guard — `true` if the value implements Standard Schema V1. */
export function isStandardSchema(value: unknown): value is StandardSchemaV1 {
  return (
    typeof value === 'object'
    && value !== null
    && '~standard' in value
    && typeof (value as any)['~standard']?.validate === 'function'
  );
}

/** Type guard — `true` if the value is a {@link FortressSchema} (has both JSON Schema fields and Standard Schema wiring). */
export function isFortressSchema(value: unknown): value is FortressSchema {
  return isStandardSchema(value)
    && (value as any)['~standard'].vendor === 'fortress'
    && ('type' in (value as any) || '$ref' in (value as any) || 'oneOf' in (value as any) || 'anyOf' in (value as any));
}

/**
 * Extract a {@link JSONSchema} from any schema input.
 *
 * - {@link FortressSchema}: returned as-is (it already _is_ JSON Schema).
 * - External Standard Schema: extracted via the `~standard.jsonSchema`
 *   adapter if the implementation provides one (Zod, Valibot, ArkType, etc).
 * - Anything else: empty object fallback.
 */
export function extractJsonSchema(schema: FortressSchema<any> | StandardSchemaV1<any>): JSONSchema {
  // Fortress schemas ARE JSON Schema — return directly
  if (isFortressSchema(schema)) {
    return schema;
  }
  // External Standard Schema — try ~standard.jsonSchema interface
  if (isStandardSchema(schema)) {
    const std = (schema as any)['~standard'];
    if (std?.jsonSchema?.input) {
      return std.jsonSchema.input({ target: 'draft-2020-12' }) as JSONSchema;
    }
  }
  // Fallback
  return {};
}

// ── Schema input type for endpoint builder ──────────────────────────

/** Schema input accepted by `EndpointBuilder.body/query/params` — a fortress schema or any Standard Schema V1 implementation. */
export type SchemaInput = FortressSchema<any> | StandardSchemaV1<any>;

// ── Endpoint Builder ────────────────────────────────────────────────

/**
 * Fluent builder for {@link EndpointDefinition} objects. Construct via the
 * {@link endpoint} factory and chain `summary`, `body`, `response`, etc.
 * before calling `build()`.
 *
 * The four type parameters accumulate as schemas are declared: each call to
 * `.body()`, `.query()`, `.params()`, and `.response()` returns a new
 * builder type with the inferred schema baked in. By the time `.build()` is
 * called, the returned {@link EndpointDefinition} carries complete phantom
 * type information about its request/response shape, which the
 * `InferEndpoint*` helpers and the `fortress.call.*` proxy read at the call
 * site.
 */
export class EndpointBuilder<
  // eslint-disable-next-line ts/no-empty-object-type
  TBody = {},
  // eslint-disable-next-line ts/no-empty-object-type
  TQuery = {},
  // eslint-disable-next-line ts/no-empty-object-type
  TParams = {},
  // eslint-disable-next-line ts/no-empty-object-type
  TResponses extends Record<number, unknown> = {},
> {
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

  body<T extends StandardSchemaV1>(
    schema: T,
  ): EndpointBuilder<InferSchema<T>, TQuery, TParams, TResponses> {
    this._body = schema;
    return this as unknown as EndpointBuilder<InferSchema<T>, TQuery, TParams, TResponses>;
  }

  query<T extends StandardSchemaV1>(
    schema: T,
  ): EndpointBuilder<TBody, InferSchema<T>, TParams, TResponses> {
    this._query = schema;
    return this as unknown as EndpointBuilder<TBody, InferSchema<T>, TParams, TResponses>;
  }

  params<T extends StandardSchemaV1>(
    schema: T,
  ): EndpointBuilder<TBody, TQuery, InferSchema<T>, TResponses> {
    this._params = schema;
    return this as unknown as EndpointBuilder<TBody, TQuery, InferSchema<T>, TResponses>;
  }

  /**
   * Declare a response for a given status code. Three call shapes:
   *
   * - `.response(200, 'Ok', schema)` — typed. The inferred output type of
   *   `schema` becomes the response body at that status.
   * - `.response(401, 'Unauthorized', schema)` — also typed. Error bodies
   *   are inferred the same way as success bodies; the `fortress.call.*`
   *   proxy treats non-2xx as throws and only exposes 2xx responses.
   * - `.response(204, 'No content')` — untyped. Use when there's no body.
   */
  response<S extends number, T extends StandardSchemaV1>(
    status: S,
    description: string,
    schema: T,
  ): EndpointBuilder<TBody, TQuery, TParams, TResponses & { [K in S]: InferSchema<T> }>;
  response<S extends number>(
    status: S,
    description: string,
  ): EndpointBuilder<TBody, TQuery, TParams, TResponses & { [K in S]: unknown }>;
  response<S extends number>(
    status: S,
    description: string,
    schema?: StandardSchemaV1 | JSONSchema,
  ): EndpointBuilder<TBody, TQuery, TParams, any> {
    const stored: EndpointResponse = { description };
    if (schema !== undefined) {
      stored.schema = isStandardSchema(schema) ? extractJsonSchema(schema as FortressSchema<any>) : schema as JSONSchema;
    }
    this._responses[status] = stored;
    return this as unknown as EndpointBuilder<TBody, TQuery, TParams, any>;
  }

  handler(name: string): this {
    this._handler = name;
    return this;
  }

  build(): EndpointDefinition<TBody, TQuery, TParams, TResponses> {
    const def: EndpointDefinition<TBody, TQuery, TParams, TResponses> = {
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

/** Start building a new {@link EndpointDefinition} for the given HTTP method and path. */
// eslint-disable-next-line ts/no-empty-object-type
export function endpoint(method: HttpMethod, path: string): EndpointBuilder<{}, {}, {}, {}> {
  return new EndpointBuilder(method, path);
}
