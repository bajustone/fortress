import type { OpenAPISpec, SpecBuilderOptions } from '../plugins/openapi/spec-builder';
import type { ComponentSchemas, EndpointDefinition } from './endpoint';
import { buildOpenAPISpec } from '../plugins/openapi/spec-builder';

/** Options accepted by {@link toOpenAPI}. */
export interface ToOpenAPIOptions extends Partial<SpecBuilderOptions> {
  /** Additional reusable schemas to place under `components.schemas`. */
  schemas?: ComponentSchemas;
}

/**
 * Emit an OpenAPI 3.1 spec from a set of Fortress endpoint definitions.
 *
 * This is the env/DB-free helper for build scripts and codegen pipelines.
 * If you already have a configured Fortress instance, prefer
 * `fortress.toOpenAPI()` so the endpoint list defaults to everything that
 * instance knows about.
 *
 * ```ts
 * import { toOpenAPI } from '@bajustone/fortress';
 * import { appEndpointList } from './routes/v1/endpoints';
 *
 * export const OPENAPI_SPEC = toOpenAPI(appEndpointList, {
 *   title: 'My API',
 *   version: '0.0.0',
 *   servers: [{ url: 'http://localhost:3001' }],
 *   tags: [{ name: 'Schools' }],
 * });
 * ```
 *
 * Defaults to endpoint `handler` values for `operationId`, matching host
 * route-contract names. Pass `operationId: 'methodPath'` for Fortress's
 * historical generated IDs.
 */
export function toOpenAPI(
  endpoints: readonly EndpointDefinition[],
  opts: ToOpenAPIOptions = {},
): OpenAPISpec {
  return buildOpenAPISpec([...endpoints], opts.schemas ?? {}, {
    title: opts.title ?? 'Fortress API',
    version: opts.version ?? '1.0.0',
    description: opts.description,
    servers: opts.servers,
    tags: opts.tags,
    operationId: opts.operationId ?? 'handler',
  });
}
