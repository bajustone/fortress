/**
 * Typed in-process client for fortress endpoints.
 *
 * `buildCall` takes a flat map of `EndpointDefinition`s (keyed by handler
 * name) and returns an object with one callable per entry. Each callable:
 *
 * 1. Splits the flat input object into `body`, `query`, and `params` based
 *    on the endpoint's declared schemas.
 * 2. Substitutes `:param` placeholders in the path.
 * 3. Serializes the query string.
 * 4. Builds a web-standard `Request` with a JSON body (when applicable).
 * 5. Delegates to `fortress.handleRequest`, exercising the full pipeline
 *    (plugin middleware → token verification → RBAC → validation →
 *    dispatch → cookie attachment).
 * 6. Parses the JSON response body. On non-2xx, throws a structured
 *    `FortressError` reconstructed via `Errors.fromHttpResponse`.
 *
 * This is the foundation of the typed client SDK: the same code works
 * in-process today and will work over the network tomorrow by swapping
 * `handleRequest` for `fetch`. All of the type machinery lives on the
 * `EndpointDefinition` generic parameters and the `InferEndpoint*` helpers
 * in `src/core/endpoint.ts`.
 *
 * **Authentication.** Protected endpoints expect a bearer token. Callers
 * pass it via the optional second argument: `call.me({}, { headers:
 * { authorization: 'Bearer …' } })`. The in-process client does not share
 * state with any active session; it is purely a typed wire formatter.
 *
 * **Runs the full pipeline.** Because each call lands in
 * `fortress.handleRequest`, the following all fire: plugin middleware (incl.
 * rate limits), principal resolution, RBAC, JSON Schema / Standard Schema
 * validation, auth observers, IAM observers, OpenTelemetry spans, and any
 * `wrapAdapter` hooks. This is intentional — it's the same code path a
 * network client would hit, so tests that exercise `fortress.call.*` give
 * the same behavioral guarantees as production traffic.
 *
 * **Bypassing hooks in tests.** If a test fixture needs to create users or
 * log in *without* tripping rate limits, emitting audit entries, or running
 * observers, call the service layer directly — `fortress.auth.createUser`,
 * `fortress.auth.login`, `fortress.iam.createRole` — instead of the typed
 * call surface. The service layer still validates inputs but skips the
 * middleware chain.
 */

import type { CallClient } from '../call-tree';
import type { FortressHttpRuntime } from '../capabilities';
import type { EndpointDefinitionLike } from '../endpoint';
import { Errors } from '../errors';

/** Optional per-call options. */
export interface CallOptions {
  /** Extra headers to attach to the synthesized request (e.g. bearer auth). */
  headers?: Record<string, string>;
}

/** Extract the top-level keys of an input JSON Schema so input can be split into body/query/params. */
function schemaKeys(schema: unknown): Set<string> {
  if (!schema || typeof schema !== 'object')
    return new Set();
  const props = (schema as { properties?: Record<string, unknown> }).properties;
  if (!props)
    return new Set();
  return new Set(Object.keys(props));
}

/**
 * Build an object of typed callables from a keyed {@link EndpointDefinition}
 * map. Each callable invokes `fortress.handleRequest` with a synthesized
 * `Request` and returns the parsed JSON body on success.
 *
 * The returned {@link CallClient} preserves each endpoint's wire-input and
 * success-response phantoms. `createFortress` composes these clients into its
 * namespaced `CallTree` without changing their per-handler contracts.
 */
export function buildCall<const TEndpoints extends Record<string, EndpointDefinitionLike>>(
  fortress: Pick<FortressHttpRuntime, 'handleRequest'>,
  endpoints: TEndpoints,
): CallClient<TEndpoints> {
  const out = Object.create(null) as Record<string, (input?: Record<string, unknown>, options?: CallOptions) => Promise<unknown>>;

  for (const [key, ep] of Object.entries(endpoints)) {
    const bodyKeys = schemaKeys(ep.input?.body);
    const queryKeys = schemaKeys(ep.input?.query);
    const paramsKeys = schemaKeys(ep.input?.params);

    out[key] = async (input: Record<string, unknown> = {}, options: CallOptions = {}): Promise<unknown> => {
      // Split the flat input into body/query/params by schema membership.
      // Params take priority (path substitution), then query, then body.
      const body = Object.create(null) as Record<string, unknown>;
      const query = Object.create(null) as Record<string, unknown>;
      const params = Object.create(null) as Record<string, unknown>;
      for (const [k, v] of Object.entries(input)) {
        if (paramsKeys.has(k))
          params[k] = v;
        else if (queryKeys.has(k))
          query[k] = v;
        else if (bodyKeys.has(k))
          body[k] = v;
        else
          // Unknown key — default to body so callers can pass extra fields
          // without tripping the splitter. Server-side validation is the
          // authority on accepted shapes.
          body[k] = v;
      }

      // Substitute `:param` placeholders in the path.
      let path = ep.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`:${k}`, encodeURIComponent(String(v)));
      }

      // Build URL with query string. `http://fortress.local` is a dummy
      // origin — `handleRequest` only reads `url.pathname` + `searchParams`.
      const url = new URL(`http://fortress.local${path}`);
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null)
          url.searchParams.set(k, String(v));
      }

      // Build request. GET/HEAD never carry a body; other methods get a
      // JSON body when at least one body field was provided.
      const headers: Record<string, string> = {
        'content-type': 'application/json',
        ...options.headers,
      };
      const init: RequestInit = {
        method: ep.method,
        headers,
      };
      const methodHasBody = ep.method !== 'GET';
      if (methodHasBody && Object.keys(body).length > 0) {
        init.body = JSON.stringify(body);
      }

      const res = await fortress.handleRequest(new Request(url, init));
      const contentType = res.headers.get('content-type') ?? '';
      const payload: unknown = contentType.includes('json')
        ? await res.clone().json().catch(() => null)
        : await res.clone().text().catch(() => null);

      if (!res.ok) {
        throw Errors.fromHttpResponse(res.status, payload);
      }
      return payload;
    };
  }

  return out as unknown as CallClient<TEndpoints>;
}
