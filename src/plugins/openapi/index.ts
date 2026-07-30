/**
 * OpenAPI 3.1 generator plugin for fortress.
 *
 * Walks every registered endpoint definition (auth, IAM, and any plugin
 * routes), folds in their JSON Schema component definitions, and emits a
 * complete OpenAPI 3.1 specification. Pairs with Scalar UI for an
 * interactive docs page mounted by the framework adapters.
 *
 * @module
 */

import type { ComponentSchemas, EndpointDefinition, EndpointDefinitionLike } from '../../core/endpoint';
import type { ResourceFile } from '../../core/iam/resource-sync';
import type { JSONSchema } from '../../core/json-schema';
import type { FortressPlugin, PluginContext } from '../../core/plugin';
import type { OpenAPISpec, SpecBuilderOptions } from './spec-builder';
import { authComponentSchemas, authEndpoints } from '../../core/auth/auth-endpoints';
import { iamComponentSchemas, iamEndpoints } from '../../core/iam/iam-endpoints';
import { definePlugin } from '../../core/plugin';
import { snapshotPluginMembership } from '../../core/plugin-membership';
import { HOST_ROUTES_PLUGIN_NAME } from '../../core/route-assembly';
import { buildOpenAPISpec } from './spec-builder';

export interface OpenAPIConfig {
  /** API title (default: 'Fortress Auth API') */
  title?: string;
  /** API version (default: '1.0.0') */
  version?: string;
  /** API description */
  description?: string;
  /** Server URL(s) for the spec */
  servers?: Array<{ url: string; description?: string }>;
  /** Optional top-level OpenAPI tags. */
  tags?: Array<{ name: string; description?: string }>;
  /** Operation ID strategy. Default: historical method+path IDs. */
  operationId?: SpecBuilderOptions['operationId'];
  /** Path to serve the JSON spec (default: '/openapi.json') */
  specPath?: string;
  /** Path to serve the Scalar UI (default: '/openapi') */
  uiPath?: string;
  /** Disable Scalar UI (default: false) */
  disableUI?: boolean;
  /** Include core auth endpoints in spec (default: true) */
  includeCoreAuth?: boolean;
  /** Include core IAM endpoints in spec (default: true) */
  includeCoreIam?: boolean;
  /** Additional component schemas to include */
  additionalSchemas?: ComponentSchemas;
  /** Additional endpoint definitions to include in the spec (for app-specific routes) */
  additionalEndpoints?: readonly EndpointDefinitionLike[];
}

export interface OpenAPIMethods {
  generateSpec: () => Promise<OpenAPISpec>;
  getSpec: () => Promise<Record<string, unknown>>;
  getUI: () => string;
}

/* eslint-disable ts/consistent-type-definitions, ts/no-empty-object-type -- alias preserves Record compatibility; these routes declare no phantom contract */
type OpenAPIBaseRoutes = {
  getSpec: EndpointDefinition<{}, {}, {}, {}, 'getSpec', 'GET', string>;
};
type OpenAPIUIRoute = {
  getUI: EndpointDefinition<{}, {}, {}, {}, 'getUI', 'GET', string>;
};
type IsAny<T> = 0 extends (1 & T) ? true : false;
type DisableUIValues<C extends OpenAPIConfig> = C extends unknown
  ? 'disableUI' extends keyof C ? C['disableUI'] : false
  : never;
type OpenAPIRoutes<C extends OpenAPIConfig> = OpenAPIBaseRoutes
  & (IsAny<C> extends true
    ? Record<never, never>
    : true extends DisableUIValues<C> ? Record<never, never> : OpenAPIUIRoute);
/* eslint-enable ts/consistent-type-definitions, ts/no-empty-object-type */

function computeRelativeUrl(fromPath: string, toPath: string): string {
  const fromParts = fromPath.split('/').slice(0, -1);
  const toParts = toPath.split('/');
  let common = 0;
  while (common < fromParts.length && common < toParts.length && fromParts[common] === toParts[common]) {
    common++;
  }
  const ups = fromParts.length - common;
  const rest = toParts.slice(common).join('/');
  if (ups === 0)
    return `./${rest}`;
  return '../'.repeat(ups) + rest;
}

function buildScalarHTML(specPath: string, title: string): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>${title} — API Reference</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>
  <script id="api-reference" data-url="${specPath}"></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>`;
}

/**
 * Build a single `oneOf` branch for a resource: `resource` is `const`,
 * `action` is `enum` over the resource's valid actions, plus shared fields.
 */
function buildResourceBranch(
  resourceName: string,
  actions: string[],
  sharedProps: Record<string, JSONSchema>,
  requiredFields: string[],
): JSONSchema {
  const actionSchema: JSONSchema = actions.length > 0
    ? { type: 'string', enum: actions, description: 'Action name' }
    : { type: 'string', description: 'Action name' };

  return {
    type: 'object',
    properties: {
      resource: { type: 'string', const: resourceName, description: 'Resource name' },
      action: actionSchema,
      ...sharedProps,
    },
    required: requiredFields,
  };
}

/**
 * Enrich `Permission` and `PermissionInput` component schemas with
 * per-resource `oneOf` discriminated branches, and patch the `/iam/check`
 * endpoint's inline body with flat resource/action enums.
 *
 * Mutates `componentSchemas` and returns an endpoint array with a cloned,
 * enriched `/iam/check` container. Published inputs are never reassigned.
 */
function enrichIamSchemas(
  componentSchemas: ComponentSchemas,
  allEndpoints: readonly EndpointDefinitionLike[],
  resourceFile: ResourceFile,
): EndpointDefinitionLike[] {
  const entries = Object.entries(resourceFile.resources);
  if (entries.length === 0)
    return [...allEndpoints];

  // Shared fields for Permission (response schema — has id, description, conditions)
  const permissionShared: Record<string, JSONSchema> = {
    id: { type: 'integer', description: 'Permission ID' },
    effect: { type: 'string', enum: ['ALLOW', 'DENY'] },
    conditions: componentSchemas.Permission?.properties?.conditions ?? { type: 'array' },
    description: { type: 'string', description: 'Permission description', nullable: true },
  };

  // Shared fields for PermissionInput (request schema — no id)
  const permissionInputShared: Record<string, JSONSchema> = {
    effect: { type: 'string', enum: ['ALLOW', 'DENY'] },
    conditions: componentSchemas.PermissionInput?.properties?.conditions ?? { type: 'array' },
  };

  // Build oneOf branches
  const permissionBranches: JSONSchema[] = [];
  const permissionInputBranches: JSONSchema[] = [];

  for (const [name, def] of entries) {
    permissionBranches.push(
      buildResourceBranch(name, def.actions, permissionShared, ['id', 'resource', 'action', 'effect']),
    );
    permissionInputBranches.push(
      buildResourceBranch(name, def.actions, permissionInputShared, ['resource', 'action']),
    );
  }

  // Replace component schemas with oneOf
  componentSchemas.Permission = { oneOf: permissionBranches };
  componentSchemas.PermissionInput = { oneOf: permissionInputBranches };

  // Patch /iam/check inline body with flat enums
  const allResourceNames = entries.map(([name]) => name).sort();
  const allActions = [...new Set(entries.flatMap(([, def]) => def.actions))].sort();
  let enriched = false;

  return allEndpoints.map((ep) => {
    if (enriched || ep.path !== '/iam/check' || !ep.input?.body)
      return ep;
    enriched = true;
    // Clone to avoid mutating the static endpoint definition
    const bodyClone: JSONSchema = JSON.parse(JSON.stringify(ep.input.body)) as JSONSchema;
    // The body is a `oneOf` of the subject and legacy user forms, so each
    // branch carries its own copy of the flat enums.
    const branches = (bodyClone.oneOf ?? [bodyClone]) as JSONSchema[];
    for (const branch of branches) {
      if (!branch.properties)
        continue;
      if (branch.properties.resource) {
        branch.properties.resource = { ...branch.properties.resource, enum: allResourceNames };
      }
      if (branch.properties.action && allActions.length > 0) {
        branch.properties.action = { ...branch.properties.action, enum: allActions };
      }
    }
    return { ...ep, input: { ...ep.input, body: bodyClone } };
  });
}

/**
 * OpenAPI plugin factory. Returns a {@link FortressPlugin} that walks every
 * registered endpoint definition and emits a complete OpenAPI 3.1 spec,
 * pairable with Scalar UI for interactive documentation.
 */
export function openapi(): FortressPlugin<'openapi', OpenAPIMethods, OpenAPIRoutes<Record<never, never>>> & { routes: OpenAPIRoutes<Record<never, never>> };
export function openapi(config: undefined): FortressPlugin<'openapi', OpenAPIMethods, OpenAPIRoutes<Record<never, never>>> & { routes: OpenAPIRoutes<Record<never, never>> };
export function openapi<const C extends OpenAPIConfig>(config: C): FortressPlugin<'openapi', OpenAPIMethods, OpenAPIRoutes<C>> & { routes: OpenAPIRoutes<C> };
export function openapi(config: OpenAPIConfig | undefined): FortressPlugin<'openapi', OpenAPIMethods, OpenAPIRoutes<OpenAPIConfig>> & { routes: OpenAPIRoutes<OpenAPIConfig> };
export function openapi(config: OpenAPIConfig = {}): FortressPlugin<'openapi', OpenAPIMethods, OpenAPIRoutes<OpenAPIConfig>> & { routes: OpenAPIRoutes<OpenAPIConfig> } {
  const specPath = config.specPath ?? '/openapi.json';
  const uiPath = config.uiPath ?? '/openapi';
  const title = config.title ?? 'Fortress Auth API';
  const version = config.version ?? '1.0.0';

  let cachedSpec: OpenAPISpec | null = null;

  const getSpecRoute = {
    method: 'GET',
    path: specPath,
    handler: 'getSpec' as const,
    meta: { summary: 'OpenAPI specification', tags: ['OpenAPI'], security: ['none'] },
    responses: { 200: { description: 'OpenAPI 3.1 JSON spec' } },
  } satisfies EndpointDefinition;
  const getUIRoute = {
    method: 'GET',
    path: uiPath,
    handler: 'getUI' as const,
    meta: { summary: 'API reference (Scalar)', tags: ['OpenAPI'], security: ['none'] },
    responses: { 200: { description: 'Scalar API reference HTML' } },
  } satisfies EndpointDefinition;
  const routes = {
    getSpec: getSpecRoute,
    ...(!config.disableUI ? { getUI: getUIRoute } : {}),
  };

  return definePlugin({
    name: 'openapi',

    routes,

    methods: (ctx: PluginContext) => {
      const plugins = snapshotPluginMembership(ctx);
      async function generateSpec(): Promise<OpenAPISpec> {
        if (cachedSpec)
          return cachedSpec;

        // Collect all endpoints from the fortress config
        let allEndpoints: EndpointDefinitionLike[] = [];

        // Add core auth endpoints
        if (config.includeCoreAuth !== false) {
          allEndpoints.push(...Object.values(authEndpoints) as EndpointDefinition[]);
        }

        // Add core IAM endpoints
        if (config.includeCoreIam !== false) {
          allEndpoints.push(...Object.values(iamEndpoints) as EndpointDefinition[]);
        }

        // Add top-level host routes. These are synthesized into the
        // Fortress instance at runtime, but ctx.config keeps the caller's
        // original object; include them explicitly so the OpenAPI plugin sees
        // `createFortress({ routes })` just like `fortress.toOpenAPI()` does.
        if (ctx.config.routes) {
          allEndpoints.push(...Object.values(ctx.config.routes) as EndpointDefinition[]);
        }

        // Add plugin endpoints (excluding our own)
        for (const plugin of plugins) {
          if (plugin.name === 'openapi' || plugin.name === HOST_ROUTES_PLUGIN_NAME || !plugin.routes)
            continue;
          allEndpoints.push(...Object.values(plugin.routes) as EndpointDefinition[]);
        }

        // Add consumer-provided endpoints
        if (config.additionalEndpoints) {
          allEndpoints.push(...config.additionalEndpoints);
        }

        // Merge component schemas
        const componentSchemas: ComponentSchemas = {
          ...(config.includeCoreAuth !== false ? authComponentSchemas : {}),
          ...(config.includeCoreIam !== false ? iamComponentSchemas : {}),
          ...(config.additionalSchemas ?? {}),
        };

        // Enrich IAM schemas with dynamic resource/action enums from the DB
        if (config.includeCoreIam !== false && ctx.iam) {
          try {
            const resourceFile = await ctx.iam.getResources();
            allEndpoints = enrichIamSchemas(componentSchemas, allEndpoints, resourceFile);
          }
          catch {
            // If resource fetch fails, fall back to plain string schemas
          }
        }

        cachedSpec = buildOpenAPISpec(allEndpoints, componentSchemas, {
          title,
          version,
          description: config.description,
          servers: config.servers,
          tags: config.tags,
          operationId: config.operationId,
        });

        return cachedSpec;
      }

      return {
        generateSpec,

        async getSpec(): Promise<Record<string, unknown>> {
          return await generateSpec() as unknown as Record<string, unknown>;
        },

        getUI(): string {
          return buildScalarHTML(computeRelativeUrl(uiPath, specPath), title);
        },
      };
    },
  } satisfies FortressPlugin<'openapi', OpenAPIMethods>) as unknown as FortressPlugin<'openapi', OpenAPIMethods, OpenAPIRoutes<OpenAPIConfig>> & { routes: OpenAPIRoutes<OpenAPIConfig> };
}
