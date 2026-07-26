/**
 * Definition-site validation for endpoint collections.
 *
 * `defineEndpoints()` is the authoring companion to the `endpoint()` builder:
 * it accepts a keyed record of built `EndpointDefinition`s, rejects any
 * non-endpoint member with a compile error on that property, and returns the
 * record with its exact literal keys and per-endpoint generics intact plus a
 * phantom {@link DefinedEndpoints} brand recording that validation happened.
 *
 * Because a defined collection is exact by construction, downstream call
 * clients are plain mapped types (see `CallClient` in
 * `src/core/call-tree.ts`) — no key filtering, no fallback branches.
 */

import type { AnyEndpointDefinition } from './endpoint';
import { isHttpMethod } from './endpoint';
import { Errors } from './errors';

declare const DEFINED_ENDPOINTS: unique symbol;

/**
 * Phantom brand carried by collections returned from {@link defineEndpoints}.
 * Never present at runtime — it only records, in the type system, that every
 * member was validated as an exact endpoint definition at its declaration
 * site.
 */
export type DefinedEndpoints<T> = T & { readonly [DEFINED_ENDPOINTS]?: true };

/**
 * Maps every member of a candidate collection to itself when it is an
 * endpoint definition, and to `never` otherwise — so an invalid member fails
 * on its own property, at the definition site, instead of silently vanishing
 * from derived call surfaces.
 */
export type ValidEndpointRecord<T> = {
  [K in keyof T]: T[K] extends AnyEndpointDefinition ? T[K] : never;
};

/**
 * Validate and brand an exact endpoint collection at its definition site.
 *
 * ```ts
 * const authEndpoints = defineEndpoints({
 *   login: endpoint('POST', '/auth/login')...build(),
 *   register: endpoint('POST', '/auth/register')...build(),
 * });
 * ```
 *
 * Guarantees:
 * - every non-endpoint property is a compile error on that property;
 * - literal keys and full `EndpointDefinition<TBody, TQuery, TParams,
 *   TResponses, THandler>` generics are preserved;
 * - no string index signature is introduced;
 * - the runtime record is also validated (shape of `method`/`path`/`handler`)
 *   as defense in depth for untyped callers.
 */
export function defineEndpoints<const T extends Record<string, AnyEndpointDefinition>>(
  endpoints: T & ValidEndpointRecord<T>,
): DefinedEndpoints<T> {
  for (const [key, ep] of Object.entries(endpoints)) {
    if (
      !ep || typeof ep !== 'object'
      || !isHttpMethod(ep.method)
      || typeof ep.path !== 'string'
      || typeof ep.handler !== 'string'
    ) {
      throw Errors.badRequest(
        `defineEndpoints: property '${key}' is not an endpoint definition — build it with endpoint(method, path)...build()`,
      );
    }
  }
  return endpoints;
}
