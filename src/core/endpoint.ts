import type { JSONSchema, Simplify } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';

/** HTTP method an {@link EndpointDefinition} can declare. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

const HTTP_METHODS = new Set<HttpMethod>(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);

/** Runtime guard matching the public {@link HttpMethod} union. */
export function isHttpMethod(value: unknown): value is HttpMethod {
  return typeof value === 'string' && HTTP_METHODS.has(value as HttpMethod);
}

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
  // Internal marker for OAuth's bespoke positional dispatch convention.
  dispatchKind?: 'oauth';
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
 * method. `TMethod` and `TPath` preserve route identity so an intentional
 * plugin override can remove the conflicting core callable.
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
  TMethod extends HttpMethod = HttpMethod,
  TPath extends string = string,
> {
  method: TMethod;
  path: TPath;
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

/**
 * Any endpoint definition, regardless of its inferred phantom contract.
 * Runtime fields retain their real constraints so wildcard consumers cannot
 * accidentally admit unsupported methods or non-string handlers/paths.
 */
export type AnyEndpointDefinition = EndpointDefinition<any, any, any, any, string, HttpMethod, string>;

/** Select the lowest numeric 2xx response key, defaulting to 200. */
export function endpointSuccessStatus(endpoint: EndpointDefinition): number {
  const statuses = Object.keys(endpoint.responses ?? {})
    .map(Number)
    .filter(status => Number.isInteger(status) && status >= 200 && status < 300);
  return statuses.length > 0 ? Math.min(...statuses) : 200;
}

// ── Endpoint type inference helpers ────────────────────────────────

/** Extract the request-body type from an {@link EndpointDefinition}. */
export type InferEndpointBody<E> = E extends EndpointDefinition<infer B, any, any, any, any, any, any> ? B : never;
/** Extract the query-string type from an {@link EndpointDefinition}. */
export type InferEndpointQuery<E> = E extends EndpointDefinition<any, infer Q, any, any, any, any, any> ? Q : never;
/** Extract the path-params type from an {@link EndpointDefinition}. */
export type InferEndpointParams<E> = E extends EndpointDefinition<any, any, infer P, any, any, any, any> ? P : never;
/** Extract the full `Record<status, body>` response map from an {@link EndpointDefinition}. */
export type InferEndpointResponses<E> = E extends EndpointDefinition<any, any, any, infer R, any, any, any> ? R : never;
/** Extract the literal handler name from an {@link EndpointDefinition}. */
export type InferEndpointHandler<E> = E extends EndpointDefinition<any, any, any, any, infer H, any, any> ? H : never;

/** Ordered exact HTTP success statuses used by hand-authored definitions. */
/* eslint-disable antfu/consistent-list-newline -- grouped by decade for readability */
type HttpSuccessStatuses = readonly [
  200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
  210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
  220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
  230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
  240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
  250, 251, 252, 253, 254, 255, 256, 257, 258, 259,
  260, 261, 262, 263, 264, 265, 266, 267, 268, 269,
  270, 271, 272, 273, 274, 275, 276, 277, 278, 279,
  280, 281, 282, 283, 284, 285, 286, 287, 288, 289,
  290, 291, 292, 293, 294, 295, 296, 297, 298, 299,
];
/* eslint-enable antfu/consistent-list-newline */

/**
 * Select the body for the lowest exact numeric 2xx key. A numeric index
 * signature means the status set is not statically known, so correlation must
 * remain `unknown` even when a later literal response is also declared.
 */
type TwoXxResponse<R, Statuses extends readonly number[] = HttpSuccessStatuses>
  = number extends keyof R
    ? unknown
    : Statuses extends readonly [infer Status extends number, ...infer Rest extends number[]]
      ? Status extends keyof R ? R[Status] : TwoXxResponse<R, Rest>
      : never;

/**
 * Extract the body correlated with the status dispatch will actually use:
 * the lowest exact numeric 2xx response key. Every endpoint definition uses
 * the same response-map projection; all statuses remain available through
 * {@link InferEndpointResponses}.
 */
export type InferEndpointSuccessResponse<E>
  = InferEndpointResponses<E> extends infer Responses
    ? [TwoXxResponse<Responses>] extends [never] ? unknown : TwoXxResponse<Responses>
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
