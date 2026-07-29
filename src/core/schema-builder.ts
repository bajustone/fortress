import type { EndpointDefinition, EndpointResponse, HttpMethod, SecurityRequirement } from './endpoint';
import type { FortressSchema, Infer, JSONSchema, Simplify } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';
import { fromJSONSchema } from '@bajustone/fetcher/openapi';
import { date as fDate, datetime as fDatetime, email as fEmail, time as fTime, url as fUrl, uuid as fUuid } from '@bajustone/fetcher/schema';
import { isHttpMethod } from './endpoint';
import { assertComponentName } from './openapi-ref';

/** Shorthands for the Standard Schema wire-input and validated-output types. */
type InferSchemaInput<T extends StandardSchemaV1> = StandardSchemaV1.InferInput<T>;
type InferSchema<T extends StandardSchemaV1> = StandardSchemaV1.InferOutput<T>;

type IsAny<T> = 0 extends (1 & T) ? true : false;
type IsUnknown<T> = IsAny<T> extends true ? false : unknown extends T ? [keyof T] extends [never] ? true : false : false;
type NoInferCompat<T> = [T][T extends any ? 0 : never];
type FunctionPropertyKeys<T> = {
  [K in keyof T]-?: Exclude<T[K], undefined> extends (...args: any[]) => any ? K : never;
}[keyof T];
type IsFlatInputObject<T> = IsAny<T> extends true
  ? true
  : IsUnknown<T> extends true
    ? true
    : [T] extends [object]
        ? [Extract<T, Date | readonly unknown[] | ((...args: any[]) => any)>] extends [never]
            ? [FunctionPropertyKeys<T>] extends [never] ? true : false
            : false
        : false;

/** Compile-time diagnostic for request locations incompatible with the flat call contract. */
interface FlatEndpointInputRequired {
  readonly 'fortress:input-error': 'endpoint body/query/params schemas must accept and return a flat object';
}

type FlatInputSchemaConstraint<T extends StandardSchemaV1>
  = IsFlatInputObject<StandardSchemaV1.InferInput<T>> extends true
    ? IsFlatInputObject<StandardSchemaV1.InferOutput<T>> extends true
      ? unknown
      : FlatEndpointInputRequired
    : FlatEndpointInputRequired;

const FLAT_INPUT_JSON_SCHEMA_TYPES = new Set(['string', 'number', 'integer', 'boolean', 'array', 'object', 'null']);

function assertFlatInputSchema(location: 'body' | 'query' | 'params', schema: StandardSchemaV1): void {
  const type = (schema as StandardSchemaV1 & { type?: unknown }).type;
  if (typeof type === 'string' && FLAT_INPUT_JSON_SCHEMA_TYPES.has(type) && type !== 'object')
    throw new TypeError(`Endpoint ${location} schema must describe a flat object`);
}

/** Distribute a union into an intersection — `A | B` → `A & B`. Used by {@link intersect}. */
type UnionToIntersection<U> = (U extends any ? (k: U) => void : never) extends (k: infer I) => void ? I : never;

/** Options accepted by the {@link str} builder (string constraints + annotations). */
export interface StringOptions {
  description?: string;
  /** Minimum length (`minLength`), enforced at runtime. */
  min?: number;
  /** Maximum length (`maxLength`), enforced at runtime. */
  max?: number;
  /** Regular-expression source (`pattern`), enforced at runtime. */
  pattern?: string;
  /** OpenAPI `format` annotation (e.g. `email`, `uuid`). Annotation-only unless paired with `pattern`. */
  format?: string;
}

/** Options accepted by the {@link num}/{@link int} builders (numeric bounds + annotations). */
export interface NumberOptions {
  description?: string;
  /** Inclusive minimum (`minimum`), enforced at runtime. */
  min?: number;
  /** Inclusive maximum (`maximum`), enforced at runtime. */
  max?: number;
}

// ── Standard Schema wiring ─────────────────────────────────────────

/**
 * Collect the component names referenced by `$ref` anywhere in a schema tree
 * (the last path segment, e.g. `PermissionInput` for
 * `#/components/schemas/PermissionInput`).
 */
function collectRefNames(schema: JSONSchema | undefined, acc: Set<string>): Set<string> {
  if (!schema || typeof schema !== 'object')
    return acc;
  if (typeof schema.$ref === 'string') {
    const i = schema.$ref.lastIndexOf('/');
    acc.add(i >= 0 ? schema.$ref.slice(i + 1) : schema.$ref);
  }
  if (schema.properties) {
    for (const key of Object.keys(schema.properties))
      collectRefNames(schema.properties[key], acc);
  }
  collectRefNames(schema.items, acc);
  for (const key of ['oneOf', 'anyOf', 'allOf'] as const) {
    const variants = schema[key];
    if (variants) {
      for (const variant of variants)
        collectRefNames(variant, acc);
    }
  }
  if (schema.additionalProperties && typeof schema.additionalProperties === 'object')
    collectRefNames(schema.additionalProperties, acc);
  return acc;
}

/**
 * Component definitions bound to a particular `$ref` schema. A WeakMap keeps
 * this runtime-only context out of emitted JSON Schema and, unlike a global
 * name registry, prevents two independent component maps that both contain a
 * `User` schema from overwriting each other before lazy validation runs.
 */
const refDefinitionContexts = new WeakMap<object, Record<string, JSONSchema>>();

function refName(refPath: string): string {
  const i = refPath.lastIndexOf('/');
  return i >= 0 ? refPath.slice(i + 1) : refPath;
}

// OpenAPI 3.x component-map keys are restricted to this grammar. Rejecting
// unsupported names is safer than emitting an ambiguous JSON Pointer that
// silently resolves to a different final path segment. Shared with the CLI's
// `--module` path so both accept the same names.

/**
 * Build the definitions map fed to `fromJSONSchema`, resolving each `$ref`
 * against the context bound by {@link defineComponents} / typed {@link ref}.
 * Context is inherited while traversing a referenced component, which supports
 * transitive and recursive refs. Bare refs without any same-name definition
 * in the composed schema remain permissive (`{}`); when composed with a bound
 * ref of the same OpenAPI component name, both correctly resolve to that one
 * global component definition.
 */
function resolveRefDefs(schema: JSONSchema): Record<string, JSONSchema> | undefined {
  if (collectRefNames(schema, new Set<string>()).size === 0)
    return undefined;

  const defs = Object.create(null) as Record<string, JSONSchema>;
  const unresolved = new Set<string>();
  const hasOwn = (value: object, key: string): boolean => Object.hasOwn(value, key);

  const visit = (node: JSONSchema | undefined, inherited?: Record<string, JSONSchema>): void => {
    if (!node || typeof node !== 'object')
      return;
    const context = refDefinitionContexts.get(node) ?? inherited;
    if (typeof node.$ref === 'string') {
      const name = refName(node.$ref);
      const component = context && hasOwn(context, name) ? context[name] : undefined;
      if (component) {
        if (hasOwn(defs, name) && !unresolved.has(name) && defs[name] !== component) {
          throw new Error(`Conflicting component definitions for $ref '${name}'`);
        }
        const firstResolution = !hasOwn(defs, name) || unresolved.delete(name);
        defs[name] = component;
        if (firstResolution)
          visit(component, context);
      }
      else if (!hasOwn(defs, name)) {
        defs[name] = {};
        unresolved.add(name);
      }
    }
    if (node.properties) {
      for (const child of Object.values(node.properties))
        visit(child, context);
    }
    visit(node.items, context);
    for (const key of ['oneOf', 'anyOf', 'allOf'] as const) {
      for (const child of node[key] ?? [])
        visit(child, context);
    }
    if (node.additionalProperties && typeof node.additionalProperties === 'object')
      visit(node.additionalProperties, context);
  };

  visit(schema);
  return defs;
}

/**
 * Build the `~standard` props for a fortress schema. Runtime validation is
 * delegated to `@bajustone/fetcher`'s `fromJSONSchema`, which compiles the
 * JSON Schema object into a Standard Schema V1 validator (lazily, on first
 * use, then memoized). fortress schemas keep `vendor: 'fortress'` and remain
 * plain JSON Schema objects — only the validation engine is fetcher's.
 *
 * `$ref` nodes are resolved against context bound by {@link defineComponents}
 * / typed {@link ref}: the referenced component's JSON
 * Schema (and any components it transitively references) is threaded into the
 * compiled validator so ref'd request bodies are enforced. A `$ref` whose
 * component is unavailable anywhere in the composed schema stays permissive
 * (compiled against `{}`), and surrounding inline fields are always validated
 * strictly.
 */
function createStandardProps<T>(schema: JSONSchema): StandardSchemaV1<T, T>['~standard'] {
  type ValidateFn = (value: unknown) => StandardSchemaV1.Result<T> | Promise<StandardSchemaV1.Result<T>>;
  let validateFn: ValidateFn | undefined;
  return {
    version: 1,
    vendor: 'fortress',
    validate(value: unknown): StandardSchemaV1.Result<T> | Promise<StandardSchemaV1.Result<T>> {
      if (!validateFn) {
        const defs = resolveRefDefs(schema);
        validateFn = fromJSONSchema<T>(schema, defs)['~standard'].validate as ValidateFn;
      }
      return validateFn(value);
    },
  } as StandardSchemaV1<T, T>['~standard'];
}

/**
 * Standard Schema validation for builder `oneOf`: JSON Schema requires that
 * exactly one branch succeeds, while some validator bridges treat it as an
 * ordinary union. Validate each branch directly so this invariant is retained
 * independently of the bridge, including for branches backed by `$ref`.
 */
function createExactOneOfProps<T>(schemas: readonly FortressSchema<any>[]): StandardSchemaV1<T, T>['~standard'] {
  type Result = StandardSchemaV1.Result<T>;
  type ValidateFn = (value: unknown) => Result | Promise<Result>;
  const validate: ValidateFn = (value) => {
    const results = schemas.map(schema => schema['~standard'].validate(value));
    if (results.some(result => result instanceof Promise)) {
      return Promise.all(results).then(resolved => exactOneResult(resolved));
    }
    return exactOneResult(results as Result[]);
  };
  return {
    version: 1,
    vendor: 'fortress',
    validate,
  };
}

function exactOneResult<T>(results: readonly StandardSchemaV1.Result<T>[]): StandardSchemaV1.Result<T> {
  const successes = results.filter((result): result is StandardSchemaV1.SuccessResult<T> => !result.issues);
  if (successes.length === 1) {
    const [success] = successes;
    if (success === undefined)
      throw new Error('oneOf validation invariant violated: one success has no result');
    return { value: success.value };
  }
  return {
    issues: [{
      message: successes.length === 0
        ? 'Value must match exactly one oneOf variant'
        : 'Value must match exactly one oneOf variant; multiple variants matched',
    }],
  };
}

function toFortressSchema<T>(
  schema: JSONSchema,
  refDefinitions?: Record<string, JSONSchema>,
  standardProps?: StandardSchemaV1<T, T>['~standard'],
): FortressSchema<T> {
  if (refDefinitions)
    refDefinitionContexts.set(schema, refDefinitions);
  return Object.assign(schema, {
    '~standard': standardProps ?? createStandardProps<T>(schema),
  }) as FortressSchema<T>;
}

// ── Schema Builders ─────────────────────────────────────────────────

/**
 * Build a string {@link FortressSchema}.
 *
 * Pass a string for just a description, or an options object to set
 * `minLength`/`maxLength`/`pattern`/`format` — the length and pattern
 * constraints are enforced at runtime by the validator.
 */
export function str(opts?: string | StringOptions): FortressSchema<string> {
  const o = typeof opts === 'string' ? { description: opts } : opts ?? {};
  const s: JSONSchema = { type: 'string' };
  if (o.description)
    s.description = o.description;
  if (o.min !== undefined)
    s.minLength = o.min;
  if (o.max !== undefined)
    s.maxLength = o.max;
  if (o.pattern !== undefined)
    s.pattern = o.pattern;
  if (o.format !== undefined)
    s.format = o.format;
  return toFortressSchema<string>(s);
}

/**
 * Build a number {@link FortressSchema} (any numeric, integer or float).
 *
 * Pass a string for just a description, or an options object to set
 * `minimum`/`maximum` — both are enforced at runtime by the validator.
 */
export function num(opts?: string | NumberOptions): FortressSchema<number> {
  const o = typeof opts === 'string' ? { description: opts } : opts ?? {};
  const s: JSONSchema = { type: 'number' };
  if (o.description)
    s.description = o.description;
  if (o.min !== undefined)
    s.minimum = o.min;
  if (o.max !== undefined)
    s.maximum = o.max;
  return toFortressSchema<number>(s);
}

/**
 * Build an integer {@link FortressSchema}.
 *
 * Pass a string for just a description, or an options object to set
 * `minimum`/`maximum` — both are enforced at runtime by the validator.
 */
export function int(opts?: string | NumberOptions): FortressSchema<number> {
  const o = typeof opts === 'string' ? { description: opts } : opts ?? {};
  const s: JSONSchema = { type: 'integer' };
  if (o.description)
    s.description = o.description;
  if (o.min !== undefined)
    s.minimum = o.min;
  if (o.max !== undefined)
    s.maximum = o.max;
  return toFortressSchema<number>(s);
}

/**
 * Build a subject-id {@link FortressSchema}.
 *
 * IDs are opaque strings at the fortress API surface (RFC 7519 §4.1.2 for
 * JWT `sub`). Numeric-keyed adapters stringify on read and parse on write
 * at the adapter boundary; consumers never see the underlying representation.
 */
export function id(description?: string): FortressSchema<string> {
  const s: JSONSchema = { type: 'string', minLength: 1 };
  if (description)
    s.description = description;
  return toFortressSchema<string>(s);
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
  // Fetcher's JSON-Schema bridge resolves `$ref` before OpenAPI's legacy
  // `nullable` sibling. Use a real union for refs so null is enforced
  // correctly; keep the established compact shape for inline schemas.
  if (typeof schema.$ref === 'string')
    return toFortressSchema<T | null>({ oneOf: [schema, { type: 'null' }] });
  const s: JSONSchema = { ...schema, nullable: true };
  return toFortressSchema<T | null>(s, refDefinitionContexts.get(schema));
}

/** Build a discriminated-union schema (exactly one variant must match). */
export function oneOf<S extends FortressSchema<any>[]>(
  ...schemas: S
): FortressSchema<Infer<S[number]>> {
  const schema: JSONSchema = { oneOf: schemas as JSONSchema[] };
  return toFortressSchema<Infer<S[number]>>(
    schema,
    undefined,
    createExactOneOfProps<Infer<S[number]>>(schemas),
  );
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
 * - `ref(name, schema)` — typed and runtime-bound `$ref`. The supplied schema
 *   provides both the inferred TypeScript type and the component definition
 *   used for runtime validation. Use when you already have the component
 *   schema and want downstream types and validation to flow through.
 *
 * For the common case (typed refs against a known components map), prefer
 * {@link defineComponents} — it returns a bound `ref` that only needs a name.
 */
export function ref<T>(name: string, schema: FortressSchema<T>): FortressSchema<T>;
export function ref(name: string): FortressSchema<unknown>;
export function ref<T>(name: string, schema?: FortressSchema<T>): FortressSchema<T> {
  assertComponentName(name);
  // Typed refs bind the real component schema. Bare `ref(name)` has no local
  // definition context; it stays permissive unless the composed schema binds
  // the same global OpenAPI component name elsewhere.
  const definitions = schema ? { [name]: schema } : undefined;
  return toFortressSchema<T>({ $ref: `#/components/schemas/${name}` }, definitions);
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
 *   //                             ^ FortressSchema<{ id: string; email: string }>
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
  for (const name of Object.keys(components))
    assertComponentName(name);
  // Snapshot the name→schema bindings now. Validators compile lazily, so
  // retaining the caller's mutable registry would otherwise make replacement
  // before first validation behave differently from replacement afterward.
  const definitions = Object.assign(
    Object.create(null) as Record<string, JSONSchema>,
    components,
  );
  return {
    components,
    ref: <K extends keyof T & string>(name: K): FortressSchema<Infer<T[K]>> => {
      assertComponentName(name);
      return toFortressSchema<Infer<T[K]>>(
        { $ref: `#/components/schemas/${String(name)}` },
        definitions,
      );
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

/**
 * Build a literal {@link FortressSchema} accepting exactly one constant value
 * (`const`). The value is enforced at runtime and the inferred type narrows to
 * the literal (e.g. `literal('admin')` infers `'admin'`).
 */
export function literal<const V extends string | number | boolean>(value: V, description?: string): FortressSchema<V> {
  const s: JSONSchema = { const: value };
  if (description)
    s.description = description;
  return toFortressSchema<V>(s);
}

/**
 * Build an intersection {@link FortressSchema} (`allOf`) — a value must satisfy
 * every supplied schema. The inferred type is the intersection of each schema's
 * inferred type.
 */
export function intersect<S extends FortressSchema<any>[]>(
  ...schemas: S
): FortressSchema<UnionToIntersection<Infer<S[number]>>> {
  return toFortressSchema<UnionToIntersection<Infer<S[number]>>>({ allOf: schemas as JSONSchema[] });
}

/**
 * Close an object {@link FortressSchema} — sets `additionalProperties: false`,
 * so the validator rejects any key not declared in `properties`. Use to harden
 * request bodies against over-posting (mass assignment).
 */
export function strict<T>(schema: FortressSchema<T>): FortressSchema<T> {
  return toFortressSchema<T>(
    { ...schema, additionalProperties: false },
    refDefinitionContexts.get(schema),
  );
}

/**
 * Build a discriminated-union {@link FortressSchema}. Emits `oneOf` plus an
 * OpenAPI `discriminator`, which the validator uses to dispatch on
 * `propertyName` (faster, with precise per-variant errors) instead of trying
 * every branch.
 */
export function discriminatedUnion<S extends FortressSchema<any>[]>(
  propertyName: string,
  ...variants: S
): FortressSchema<Infer<S[number]>> {
  return toFortressSchema<Infer<S[number]>>({
    oneOf: variants as JSONSchema[],
    discriminator: { propertyName },
  });
}

// ── Enforced string formats ─────────────────────────────────────────
// Each lifts the `format` + ReDoS-safe `pattern` from the corresponding
// `@bajustone/fetcher/schema` format builder (the single source of truth), so
// the value is BOTH documented (`format`) and enforced at runtime (`pattern`),
// while the schema stays a plain fortress JSON Schema object.

/** Build a string format builder by lifting `{ format, pattern }` from a fetcher format factory. */
function makeFormatBuilder(factory: () => unknown): (description?: string) => FortressSchema<string> {
  const f = factory() as { format?: string; pattern?: string };
  return (description?: string): FortressSchema<string> => {
    const s: JSONSchema = { type: 'string' };
    if (f.format)
      s.format = f.format;
    if (f.pattern)
      s.pattern = f.pattern;
    if (description)
      s.description = description;
    return toFortressSchema<string>(s);
  };
}

/** Email string schema (`format: 'email'`) — enforces the WHATWG HTML5 email grammar at runtime. */
export const email: (description?: string) => FortressSchema<string> = makeFormatBuilder(fEmail);

/** UUID string schema (`format: 'uuid'`) — enforces RFC 9562 versions 1–8 plus nil/max at runtime. */
export const uuid: (description?: string) => FortressSchema<string> = makeFormatBuilder(fUuid);

/** URL string schema (`format: 'uri'`) — enforces an explicit `scheme://` authority at runtime. */
export const url: (description?: string) => FortressSchema<string> = makeFormatBuilder(fUrl);

/** RFC 3339 date-time string schema (`format: 'date-time'`) — field ranges enforced at runtime. */
export const datetime: (description?: string) => FortressSchema<string> = makeFormatBuilder(fDatetime);

/** RFC 3339 full-date string schema (`format: 'date'`) — field ranges enforced at runtime. */
export const date: (description?: string) => FortressSchema<string> = makeFormatBuilder(fDate);

/** RFC 3339 time string schema (`format: 'time'`) — field ranges enforced at runtime. */
export const time: (description?: string) => FortressSchema<string> = makeFormatBuilder(fTime);

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

/** Valid JSON Schema type values per the spec. */
const JSON_SCHEMA_TYPES = new Set(['string', 'number', 'integer', 'boolean', 'object', 'array', 'null']);

/**
 * `true` if the value carries structural JSON Schema props directly on the
 * object — a valid `type` value, or `$ref`/`oneOf`/`anyOf`/`allOf`. Libraries
 * that implement Standard Schema over a JSON Schema object (fortress, fetcher)
 * match this; wrapper schemas like Zod do not (their `type` holds internal
 * kind strings like `'ZodObject'`, not JSON Schema types).
 */
function hasJsonSchemaShape(value: unknown): boolean {
  if (typeof value !== 'object' || value === null)
    return false;
  const v = value as any;
  if ('$ref' in v || 'oneOf' in v || 'anyOf' in v || 'allOf' in v)
    return true;
  if (typeof v.type === 'string' && JSON_SCHEMA_TYPES.has(v.type))
    return true;
  if (Array.isArray(v.type) && v.type.every((t: unknown) => typeof t === 'string' && JSON_SCHEMA_TYPES.has(t)))
    return true;
  return false;
}

/**
 * Extract a {@link JSONSchema} from any schema input.
 *
 * - {@link FortressSchema}: returned as-is (it already _is_ JSON Schema).
 * - External Standard Schema with a `~standard.jsonSchema.input()` adapter
 *   (Zod, Valibot, ArkType, etc.): extracted via the adapter.
 * - External Standard Schema that already IS a JSON Schema object (fetcher,
 *   etc.): returned as-is.
 * - Anything else: empty object fallback.
 */
export function extractJsonSchema(schema: FortressSchema<any> | StandardSchemaV1<any>): JSONSchema {
  // Fortress schemas ARE JSON Schema — return directly
  if (isFortressSchema(schema)) {
    return schema;
  }
  if (isStandardSchema(schema)) {
    const std = (schema as any)['~standard'];
    // Wrapper Standard Schemas that expose a JSON Schema adapter (Zod, Valibot, ...)
    if (std?.jsonSchema?.input) {
      return std.jsonSchema.input({ target: 'draft-2020-12' }) as JSONSchema;
    }
    // Standard Schemas that already ARE JSON Schema objects (fetcher, ...)
    if (hasJsonSchemaShape(schema)) {
      return schema as JSONSchema;
    }
  }
  // Fallback
  return {};
}

// ── Schema input type for endpoint builder ──────────────────────────

/** Schema input accepted by `EndpointBuilder.body/query/params` — a fortress schema or any Standard Schema V1 implementation. */
export type SchemaInput = FortressSchema<any> | StandardSchemaV1<any>;

// ── Canonical error envelope ───────────────────────────────────────

/**
 * Canonical fortress error response body — the exact wire shape emitted by
 * {@link import('./errors').FortressError.toJSON}. Reference this from
 * endpoint `.response(4xx|5xx, ...)` declarations so host APIs document the
 * same error contract Fortress's own routes produce, and so clients can use
 * a single error parser everywhere.
 *
 * Shape:
 * ```ts
 * {
 *   code: string,       // FortressErrorCode
 *   message: string,    // human-readable
 *   statusCode: number, // HTTP status
 *   details?: unknown,  // optional structured payload (e.g. validation issues)
 * }
 * ```
 *
 * See {@link EndpointBuilder.errorResponse} for a shorthand that wires this
 * schema into a status declaration in one call.
 */
export interface ErrorEnvelopeBody {
  code: string;
  message: string;
  statusCode: number;
  details?: unknown;
}

export const ErrorEnvelope: FortressSchema<ErrorEnvelopeBody> = obj({
  code: str('Machine-readable error code'),
  message: str('Human-readable error message'),
  statusCode: int('HTTP status code'),
  details: toFortressSchema<unknown>({ description: 'Optional structured error details' }),
}, 'code', 'message', 'statusCode');

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
  THandler extends string = string,
  TMethod extends HttpMethod = HttpMethod,
  TPath extends string = string,
  TBodyInput = TBody,
  TQueryInput = TQuery,
  TParamsInput = TParams,
> {
  private _method: TMethod;
  private _path: TPath;
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

  constructor(method: TMethod, path: TPath) {
    this._method = method;
    this._path = path;
  }

  /**
   * Clone the builder before any operation that changes its phantom type.
   * This prevents an aliased builder from mutating the runtime definition
   * behind a previously inferred body/query/params/response/handler type.
   */
  private clone(): EndpointBuilder<TBody, TQuery, TParams, TResponses, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput> {
    const next = new EndpointBuilder<TBody, TQuery, TParams, TResponses, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput>(
      this._method,
      this._path,
    );
    next._handler = this._handler;
    next._summary = this._summary;
    next._description = this._description;
    next._tags = [...this._tags];
    next._security = [...this._security];
    next._deprecated = this._deprecated;
    next._permission = this._permission ? { ...this._permission } : undefined;
    next._body = this._body;
    next._query = this._query;
    next._params = this._params;
    next._responses = { ...this._responses };
    return next;
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
    schema: T & FlatInputSchemaConstraint<NoInferCompat<T>>,
  ): EndpointBuilder<InferSchema<T>, TQuery, TParams, TResponses, THandler, TMethod, TPath, InferSchemaInput<T>, TQueryInput, TParamsInput> {
    assertFlatInputSchema('body', schema);
    const next = this.clone();
    next._body = schema;
    return next as unknown as EndpointBuilder<InferSchema<T>, TQuery, TParams, TResponses, THandler, TMethod, TPath, InferSchemaInput<T>, TQueryInput, TParamsInput>;
  }

  query<T extends StandardSchemaV1>(
    schema: T & FlatInputSchemaConstraint<NoInferCompat<T>>,
  ): EndpointBuilder<TBody, InferSchema<T>, TParams, TResponses, THandler, TMethod, TPath, TBodyInput, InferSchemaInput<T>, TParamsInput> {
    assertFlatInputSchema('query', schema);
    const next = this.clone();
    next._query = schema;
    return next as unknown as EndpointBuilder<TBody, InferSchema<T>, TParams, TResponses, THandler, TMethod, TPath, TBodyInput, InferSchemaInput<T>, TParamsInput>;
  }

  params<T extends StandardSchemaV1>(
    schema: T & FlatInputSchemaConstraint<NoInferCompat<T>>,
  ): EndpointBuilder<TBody, TQuery, InferSchema<T>, TResponses, THandler, TMethod, TPath, TBodyInput, TQueryInput, InferSchemaInput<T>> {
    assertFlatInputSchema('params', schema);
    const next = this.clone();
    next._params = schema;
    return next as unknown as EndpointBuilder<TBody, TQuery, InferSchema<T>, TResponses, THandler, TMethod, TPath, TBodyInput, TQueryInput, InferSchemaInput<T>>;
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
  ): EndpointBuilder<TBody, TQuery, TParams, TResponses & { [K in S]: InferSchema<T> }, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput>;
  response<S extends number>(
    status: S,
    description: string,
  ): EndpointBuilder<TBody, TQuery, TParams, TResponses & { [K in S]: unknown }, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput>;
  response<S extends number>(
    status: S,
    description: string,
    schema?: StandardSchemaV1 | JSONSchema,
  ): EndpointBuilder<TBody, TQuery, TParams, any, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput> {
    const next = this.clone();
    const stored: EndpointResponse = { description };
    if (schema !== undefined) {
      stored.schema = isStandardSchema(schema) ? extractJsonSchema(schema as FortressSchema<any>) : schema as JSONSchema;
    }
    next._responses[status] = stored;
    return next as unknown as EndpointBuilder<TBody, TQuery, TParams, any, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput>;
  }

  /**
   * Declare an error response that returns the canonical {@link ErrorEnvelope}
   * body. Shorthand for `.response(status, description, ErrorEnvelope)`.
   *
   * Aligns host endpoint error responses with what Fortress's own routes
   * emit, so a single client-side error parser works everywhere.
   *
   * ```ts
   * endpoint('GET', '/schools/:id')
   *   .summary('Get a school')
   *   .params(obj({ id: str() }, 'id'))
   *   .response(200, 'OK', SchoolEnvelope)
   *   .errorResponse(404, 'School not found')
   *   .errorResponse(403, 'Forbidden')
   *   .build();
   * ```
   */
  errorResponse<S extends number>(
    status: S,
    description: string,
  ): EndpointBuilder<TBody, TQuery, TParams, TResponses & { [K in S]: InferSchema<typeof ErrorEnvelope> }, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput> {
    return this.response(status, description, ErrorEnvelope);
  }

  /**
   * Name the plugin method this route dispatches to. The literal name is
   * captured in the definition's `THandler` phantom so `definePlugin` can
   * statically verify the handler exists and matches the endpoint's I/O.
   */
  handler<H extends string>(name: H): EndpointBuilder<TBody, TQuery, TParams, TResponses, H, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput> {
    const next = this.clone();
    next._handler = name;
    return next as unknown as EndpointBuilder<TBody, TQuery, TParams, TResponses, H, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput>;
  }

  build(): EndpointDefinition<TBody, TQuery, TParams, TResponses, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput> {
    const def: EndpointDefinition<TBody, TQuery, TParams, TResponses, THandler, TMethod, TPath, TBodyInput, TQueryInput, TParamsInput> = {
      method: this._method,
      path: this._path,
      handler: this._handler as THandler,
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
/* eslint-disable ts/no-empty-object-type -- builder starts with empty phantom input/response slots */
export function endpoint<const TMethod extends HttpMethod, const TPath extends string>(
  method: TMethod,
  path: TPath,
): EndpointBuilder<{}, {}, {}, {}, string, TMethod, TPath> {
  if (!isHttpMethod(method))
    throw new TypeError(`Unsupported endpoint method: ${String(method)}`);
  return new EndpointBuilder(method, path);
}
/* eslint-enable ts/no-empty-object-type */
