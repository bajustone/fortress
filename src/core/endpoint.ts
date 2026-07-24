import type { JSONSchema, Simplify } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';

/** HTTP method an {@link EndpointDefinition} can declare. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

/** Authentication scheme required to call an endpoint. */
export type SecurityRequirement = 'bearer' | 'basic' | 'apiKey' | 'none';

/** A required IAM permission, expressed as a `(resource, action)` pair. */
export interface EndpointPermission {
  resource: string;
  action: string;
}

/** OpenAPI / IAM metadata attached to an {@link EndpointDefinition}. */
export interface EndpointMeta {
  summary: string;
  description?: string;
  tags?: string[];
  security?: SecurityRequirement[];
  deprecated?: boolean;
  /** IAM permission required to access this endpoint. Enforced by RBAC middleware. */
  permission?: EndpointPermission;
  /**
   * What kind of bearer token this route accepts.
   *
   * - `'jwt'` (default) — the route expects a Fortress session JWT in
   *   `Authorization: Bearer <jwt>` (or the cookie). The dispatcher runs
   *   the plugin principal chain, JWT verification, and RBAC enforcement
   *   automatically before invoking the handler.
   * - `'oauth'` — the route's bearer is an OAuth 2.0 access token (or no
   *   token at all, e.g. `/oauth/authorize`). The dispatcher skips its
   *   auth pipeline entirely and the handler self-parses the bearer
   *   (typical for `/oauth/userinfo`, `/oauth/token`, etc.). Body parsing
   *   and validation are also skipped, since OAuth bodies are
   *   `application/x-www-form-urlencoded` per RFC 6749.
   *
   * Routes that don't set this field default to `'jwt'`. Without this
   * marker, the OAuth plugin's consent-flow endpoints
   * (`/oauth/flows/:flowId{,/approve,/deny}`) — which are SPA-driven and
   * require a Fortress JWT — used to be silently unauthenticated due to
   * a path-based `startsWith('/oauth/')` short-circuit in the dispatcher,
   * forcing every host app to ship a workaround shim. Setting
   * `bearerKind: 'oauth'` only on the actual protocol routes lets the
   * dispatcher honour `security: ['bearer']` everywhere else.
   */
  bearerKind?: 'jwt' | 'oauth';
}

/** Request input declarations for an endpoint — JSON Schemas for OpenAPI plus Standard Schemas for runtime validation. */
export interface EndpointInput {
  /** JSON Schema for OpenAPI spec generation. */
  body?: JSONSchema;
  query?: JSONSchema;
  params?: JSONSchema;
  /** Standard Schema references for runtime validation (set by endpoint builder). */
  bodySchema?: StandardSchemaV1;
  querySchema?: StandardSchemaV1;
  paramsSchema?: StandardSchemaV1;
}

/** A single OpenAPI response definition (description plus optional JSON Schema). */
export interface EndpointResponse {
  description: string;
  schema?: JSONSchema;
}

/**
 * Declarative description of one HTTP endpoint.
 *
 * The generic parameters are **phantom types** — they're populated by the
 * fluent {@link EndpointBuilder} as schemas are declared via `.body()`,
 * `.query()`, `.params()`, `.response()`, and `.handler()`, and then
 * extracted at the call site by the `InferEndpoint*` helpers (and by the
 * typed `fortress.call.*` tree). None of them exist at runtime.
 *
 * The input defaults are `{}` (empty object), not `unknown`, so that the
 * intersection-based `InferEndpointCallInput` collapses cleanly for
 * endpoints that only declare one of the three input slots. `THandler`
 * captures the literal handler name so `definePlugin` can statically check
 * that every route dispatches to an existing, signature-compatible plugin
 * method.
 */
export interface EndpointDefinition<
  // eslint-disable-next-line ts/no-empty-object-type -- default must be {} so the input intersection collapses
  TBody = {},
  // eslint-disable-next-line ts/no-empty-object-type
  TQuery = {},
  // eslint-disable-next-line ts/no-empty-object-type
  TParams = {},
  // eslint-disable-next-line ts/no-empty-object-type
  TResponses extends Record<number, unknown> = {},
  THandler extends string = string,
> {
  method: HttpMethod;
  path: string;
  handler: THandler;
  meta?: EndpointMeta;
  input?: EndpointInput;
  responses?: Record<number, EndpointResponse>;
  /** Phantom — never present at runtime. Consumed by `InferEndpoint*` helpers. */
  __types?: {
    body: TBody;
    query: TQuery;
    params: TParams;
    responses: TResponses;
  };
}

/** Any endpoint definition, regardless of its inferred generics. */
export type AnyEndpointDefinition = EndpointDefinition<any, any, any, any, any>;

// ── Endpoint type inference helpers ────────────────────────────────

/** Extract the request-body type from an {@link EndpointDefinition}. */
export type InferEndpointBody<E> = E extends EndpointDefinition<infer B, any, any, any, any> ? B : never;
/** Extract the query-string type from an {@link EndpointDefinition}. */
export type InferEndpointQuery<E> = E extends EndpointDefinition<any, infer Q, any, any, any> ? Q : never;
/** Extract the path-params type from an {@link EndpointDefinition}. */
export type InferEndpointParams<E> = E extends EndpointDefinition<any, any, infer P, any, any> ? P : never;
/** Extract the full `Record<status, body>` response map from an {@link EndpointDefinition}. */
export type InferEndpointResponses<E> = E extends EndpointDefinition<any, any, any, infer R, any> ? R : never;
/** Extract the literal handler name from an {@link EndpointDefinition}. */
export type InferEndpointHandler<E> = E extends EndpointDefinition<any, any, any, any, infer H> ? H : never;

/**
 * Extract the success-response body from an {@link EndpointDefinition}.
 *
 * Tries `200`, then `201`, then `204`, then falls back to `unknown`.
 * This matches the behavior of the `fortress.call.*` proxy, which always
 * resolves to the first successful status declared.
 */
export type InferEndpointSuccessResponse<E>
  = InferEndpointResponses<E> extends infer R
    ? R extends { 200: infer T } ? T
      : R extends { 201: infer T } ? T
        : R extends { 204: infer T } ? T
          : unknown
    : never;

/**
 * The flat input shape accepted by the typed `fortress.call.<handler>(input)`
 * proxy — the intersection of body, query, and params. For endpoints that
 * only declare one of the three, the other slots are `{}` and disappear from
 * the intersection.
 */
export type InferEndpointCallInput<E> = Simplify<
  InferEndpointBody<E> & InferEndpointQuery<E> & InferEndpointParams<E>
>;

/**
 * Component schemas are reusable JSON Schema definitions
 * that endpoints reference via $ref (e.g., '#/components/schemas/User').
 */
export interface ComponentSchemas {
  [name: string]: JSONSchema;
}
