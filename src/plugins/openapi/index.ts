import type { ComponentSchemas, EndpointDefinition } from '../../core/endpoint';
import type { FortressPlugin, PluginContext } from '../../core/plugin';
import type { OpenAPISpec } from './spec-builder';
import { authComponentSchemas, authEndpoints } from '../../core/auth/auth-endpoints';
import { iamComponentSchemas, iamEndpoints } from '../../core/iam/iam-endpoints';
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
}

export interface OpenAPIMethods {
  generateSpec: () => OpenAPISpec;
  getSpec: () => Record<string, unknown>;
  getUI: () => string;
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

export function openapi(config: OpenAPIConfig = {}): FortressPlugin & { readonly name: 'openapi' } {
  const specPath = config.specPath ?? '/openapi.json';
  const uiPath = config.uiPath ?? '/openapi';
  const title = config.title ?? 'Fortress Auth API';
  const version = config.version ?? '1.0.0';

  let cachedSpec: OpenAPISpec | null = null;

  const routes: FortressPlugin['routes'] = [
    {
      method: 'GET',
      path: specPath,
      handler: 'getSpec',
      meta: { summary: 'OpenAPI specification', tags: ['OpenAPI'], security: ['none'] },
      responses: { 200: { description: 'OpenAPI 3.1 JSON spec' } },
    },
  ];

  if (!config.disableUI) {
    routes.push({
      method: 'GET',
      path: uiPath,
      handler: 'getUI',
      meta: { summary: 'API reference (Scalar)', tags: ['OpenAPI'], security: ['none'] },
      responses: { 200: { description: 'Scalar API reference HTML' } },
    });
  }

  return {
    name: 'openapi',

    routes,

    methods: (ctx: PluginContext) => {
      function generateSpec(): OpenAPISpec {
        if (cachedSpec)
          return cachedSpec;

        // Collect all endpoints from the fortress config
        const allEndpoints: EndpointDefinition[] = [];
        const plugins = ctx.config.plugins ?? [];

        // Add core auth endpoints
        if (config.includeCoreAuth !== false) {
          allEndpoints.push(...authEndpoints);
        }

        // Add core IAM endpoints
        if (config.includeCoreIam !== false) {
          allEndpoints.push(...iamEndpoints);
        }

        // Add plugin endpoints (excluding our own)
        for (const plugin of plugins) {
          if (plugin.name === 'openapi' || !plugin.routes)
            continue;
          allEndpoints.push(...plugin.routes);
        }

        // Merge component schemas
        const componentSchemas: ComponentSchemas = {
          ...(config.includeCoreAuth !== false ? authComponentSchemas : {}),
          ...(config.includeCoreIam !== false ? iamComponentSchemas : {}),
          ...(config.additionalSchemas ?? {}),
        };

        cachedSpec = buildOpenAPISpec(allEndpoints, componentSchemas, {
          title,
          version,
          description: config.description,
          servers: config.servers,
        });

        return cachedSpec;
      }

      return {
        generateSpec,

        getSpec(): Record<string, unknown> {
          return generateSpec() as unknown as Record<string, unknown>;
        },

        getUI(): string {
          return buildScalarHTML(specPath, title);
        },
      };
    },
  };
}
