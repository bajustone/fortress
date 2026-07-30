import type {
  AnyPublishedEndpointDefinition,
  DatabaseAdapter,
  EndpointDefinition,
  Fortress,
  FortressManifestRuntime,
  InferEndpointBody,
  InferEndpointBodyInput,
  InferEndpointHandler,
  InferEndpointParams,
  InferEndpointParamsInput,
  InferEndpointQuery,
  InferEndpointQueryInput,
  InferEndpointResponses,
  JSONSchema,
  PublishedEndpointDefinition,
  PublishedRouteManifest,
  PublishedRouteManifestEntry,
  StandardSchemaV1,
} from '@bajustone/fortress';
import {
  buildRouteManifest,
  createFortress,
  detectRouteManifestDrift,
  protect,
  resolveProtectedEndpoint,
  toOpenAPI,
} from '@bajustone/fortress';
import { openapi } from '@bajustone/fortress/plugins/openapi';
import { checkPublicRoutes, checkRouteManifestDrift } from '@bajustone/fortress/testing';

declare const database: DatabaseAdapter;
declare const standardSchema: StandardSchemaV1;

const jsonSchema: JSONSchema = {
  type: 'object',
  title: 'Mutable schema',
  properties: { value: { type: 'string' } },
};

// Configuration-time endpoint declarations remain mutable at every layer.
const declared: EndpointDefinition = {
  method: 'POST',
  path: '/published-fixture/:id',
  handler: 'publishedFixture',
  meta: {
    summary: 'Published fixture',
    tags: ['fixture'],
    security: ['bearer'],
    permission: { resource: 'fixture', action: 'read' },
  },
  input: { body: jsonSchema, bodySchema: standardSchema },
  responses: { 200: { description: 'OK', schema: jsonSchema } },
};
declared.method = 'PATCH';
declared.path = '/published-fixture/:fixtureId';
declared.handler = 'adjustedPublishedFixture';
declared.meta = { summary: 'Adjusted' };
declared.meta.summary = 'Adjusted again';
declared.meta.tags = ['adjusted'];
declared.meta.tags.push('mutable');
declared.meta.security = ['none'];
declared.meta.security.splice(0, 1, 'bearer');
declared.meta.permission = { resource: 'fixture', action: 'write' };
declared.meta.permission.resource = 'adjusted-fixture';
declared.meta.deprecated = true;
declared.meta.bearerKind = 'jwt';
declared.meta.dispatchKind = 'oauth';
declared.input = { query: jsonSchema };
declared.input.body = jsonSchema;
declared.input.query = jsonSchema;
declared.input.params = jsonSchema;
declared.input.bodySchema = standardSchema;
declared.input.querySchema = standardSchema;
declared.input.paramsSchema = standardSchema;
declared.responses = { 201: { description: 'Created', schema: jsonSchema } };
declared.responses[201] = { description: 'Adjusted response', schema: jsonSchema };
declared.responses[201]!.description = 'Adjusted again';
declared.responses[201]!.schema = jsonSchema;
jsonSchema.title = 'Still mutable';

const fortress = createFortress({
  database,
  jwt: { key: 'published-snapshot-fixture-secret' },
  routes: { adjustedPublishedFixture: declared },
});

// Direct manifest generation remains an intentional mutable adjustment surface.
const adjustableManifest = buildRouteManifest(fortress);
adjustableManifest.push({ ...adjustableManifest[0]! });
adjustableManifest.splice(0, 1);
adjustableManifest[0]!.path = '/adjusted';
adjustableManifest[0]!.security.push('none');
if (adjustableManifest[0]!.permission)
  adjustableManifest[0]!.permission.action = 'adjusted';

const published = fortress.endpoints[0]!;

// The published endpoint array and every runtime-frozen endpoint layer reject mutation.
// @ts-expect-error published endpoint arrays are frozen
fortress.endpoints.push(declared);
// @ts-expect-error published endpoint arrays cannot be spliced
fortress.endpoints.splice(0, 1);
// @ts-expect-error published methods are frozen
published.method = 'PATCH';
// @ts-expect-error published paths are frozen
published.path = '/changed';
// @ts-expect-error published handlers are frozen
published.handler = 'changed';
// @ts-expect-error published metadata containers are frozen
published.meta = { summary: 'Changed' };
// @ts-expect-error published input containers are frozen
published.input = {};
// @ts-expect-error published response maps cannot be replaced
published.responses = {};
// @ts-expect-error published metadata fields are frozen
published.meta!.summary = 'Changed';
// @ts-expect-error published metadata fields are frozen
published.meta!.description = 'Changed';
// @ts-expect-error published tag arrays cannot be replaced
published.meta!.tags = [];
// @ts-expect-error published tag arrays are frozen
published.meta!.tags!.push('changed');
// @ts-expect-error published tag arrays cannot be spliced
published.meta!.tags!.splice(0, 1);
// @ts-expect-error published security arrays cannot be replaced
published.meta!.security = [];
// @ts-expect-error published security arrays are frozen
published.meta!.security!.push('none');
// @ts-expect-error published deprecation metadata is frozen
published.meta!.deprecated = true;
// @ts-expect-error published bearer metadata is frozen
published.meta!.bearerKind = 'oauth';
// @ts-expect-error published dispatch metadata is frozen
published.meta!.dispatchKind = 'oauth';
// @ts-expect-error published permissions cannot be replaced
published.meta!.permission = { resource: 'changed', action: 'changed' };
// @ts-expect-error published permission resources are frozen
published.meta!.permission!.resource = 'changed';
// @ts-expect-error published permission actions are frozen
published.meta!.permission!.action = 'changed';
// @ts-expect-error published input fields cannot be replaced
published.input!.body = jsonSchema;
// @ts-expect-error published input fields cannot be replaced
published.input!.query = jsonSchema;
// @ts-expect-error published input fields cannot be replaced
published.input!.params = jsonSchema;
// @ts-expect-error published Standard Schema references cannot be replaced
published.input!.bodySchema = standardSchema;
// @ts-expect-error published Standard Schema references cannot be replaced
published.input!.querySchema = standardSchema;
// @ts-expect-error published Standard Schema references cannot be replaced
published.input!.paramsSchema = standardSchema;
// @ts-expect-error published response-map entries cannot be replaced
published.responses![200] = { description: 'Changed' };
// @ts-expect-error published response-map entries cannot be deleted
delete published.responses![200];
// @ts-expect-error published response descriptions are frozen
published.responses![200]!.description = 'Changed';
// @ts-expect-error published response schema references cannot be replaced
published.responses![200]!.schema = jsonSchema;

// Schemas hanging off frozen containers deliberately remain shared/mutable references.
published.input!.body!.title = 'Schema remains mutable';
published.responses![200]!.schema!.title = 'Response schema remains mutable';

const manifestEntry = fortress.manifest[0]!;
const namedManifest: PublishedRouteManifest = fortress.manifest;
const namedEntry: PublishedRouteManifestEntry = manifestEntry;
void [namedManifest, namedEntry];
// @ts-expect-error published manifest arrays are frozen
fortress.manifest.push(adjustableManifest[0]!);
// @ts-expect-error published manifest arrays cannot be spliced
fortress.manifest.splice(0, 1);
// @ts-expect-error published manifest methods are frozen
manifestEntry.method = 'PATCH';
// @ts-expect-error published manifest paths are frozen
manifestEntry.path = '/changed';
// @ts-expect-error published manifest handlers are frozen
manifestEntry.handler = 'changed';
// @ts-expect-error published manifest owners are frozen
manifestEntry.plugin = 'changed';
// @ts-expect-error published manifest classifications are frozen
manifestEntry.classification = 'public';
// @ts-expect-error published manifest permissions cannot be replaced
manifestEntry.permission = { resource: 'changed', action: 'changed' };
// @ts-expect-error published manifest permission fields are frozen
manifestEntry.permission!.resource = 'changed';
// @ts-expect-error published manifest permission fields are frozen
manifestEntry.permission!.action = 'changed';
// @ts-expect-error published manifest bearer metadata is frozen
manifestEntry.bearerKind = 'oauth';
// @ts-expect-error published manifest security arrays cannot be replaced
manifestEntry.security = [];
// @ts-expect-error published manifest security arrays are frozen
manifestEntry.security.push('none');
// @ts-expect-error published manifest CSRF metadata is frozen
manifestEntry.csrfApplicable = false;
// @ts-expect-error published manifest rate-limit metadata is frozen
manifestEntry.rateLimited = false;
// @ts-expect-error published manifest mount metadata is frozen
manifestEntry.mounted = false;

// Defaults, overrides, drift helpers, checks, and manifest generation consume snapshots naturally.
fortress.toOpenAPI();
fortress.toOpenAPI({ endpoints: fortress.endpoints });
toOpenAPI(fortress.endpoints);
fortress.syncPermissionsFromManifest({ endpoints: fortress.endpoints });
detectRouteManifestDrift(fortress, { manifest: fortress.manifest });
checkRouteManifestDrift(fortress);
checkPublicRoutes(fortress);
buildRouteManifest(fortress);
openapi({ additionalEndpoints: fortress.endpoints });

// Erased capabilities must admit every valid phantom contract, including
// null/primitive body and wire-input slots with literal route identity.
// eslint-disable-next-line ts/consistent-type-definitions -- numeric literal maps do not satisfy Record<number, unknown> as interfaces
type NullResponses = { 204: null };
declare const nullPublishedEndpoint: PublishedEndpointDefinition<
  null,
  string,
  number,
  NullResponses,
  'nullPublishedFixture',
  'PATCH',
  '/null-published-fixture',
  string,
  boolean,
  bigint
>;
const wildcardRuntime: FortressManifestRuntime = {
  ...fortress,
  endpoints: [nullPublishedEndpoint],
};
const nullMethod: 'PATCH' = nullPublishedEndpoint.method;
const nullPath: '/null-published-fixture' = nullPublishedEndpoint.path;
toOpenAPI(wildcardRuntime.endpoints);
fortress.toOpenAPI({ endpoints: wildcardRuntime.endpoints });
fortress.syncPermissionsFromManifest({ endpoints: wildcardRuntime.endpoints });
buildRouteManifest(wildcardRuntime);
detectRouteManifestDrift(wildcardRuntime);
openapi({ additionalEndpoints: wildcardRuntime.endpoints });
void [nullMethod, nullPath];

interface TypedBody { value: string }
interface TypedBodyInput { value: string | number }
interface TypedQuery { include: boolean }
interface TypedQueryInput { include: string | boolean }
interface TypedParams { id: string }
interface TypedParamsInput { id: number | string }
// eslint-disable-next-line ts/consistent-type-definitions -- numeric literal maps do not satisfy Record<number, unknown> as interfaces
type TypedResponses = { 200: { ok: true }; 404: { error: string } };
type TypedPublishedEndpoint = PublishedEndpointDefinition<
  TypedBody,
  TypedQuery,
  TypedParams,
  TypedResponses,
  'typedPublishedFixture',
  'POST',
  '/typed-published-fixture/:id',
  TypedBodyInput,
  TypedQueryInput,
  TypedParamsInput
>;
type TypedMutableEndpoint = EndpointDefinition<
  TypedBody,
  TypedQuery,
  TypedParams,
  TypedResponses,
  'typedMutableFixture',
  'POST',
  '/typed-mutable-fixture/:id',
  TypedBodyInput,
  TypedQueryInput,
  TypedParamsInput
>;
declare const typedMutableEndpoint: TypedMutableEndpoint;

function isTypedPublishedEndpoint(
  endpoint: AnyPublishedEndpointDefinition,
): endpoint is TypedPublishedEndpoint {
  return endpoint.handler === 'typedPublishedFixture';
}
const selected = fortress.endpoints.find(isTypedPublishedEndpoint)!;

// All ten endpoint generics survive publication and flow through protect().
const inferredBody: InferEndpointBody<typeof selected> = { value: 'validated' };
const inferredBodyInput: InferEndpointBodyInput<typeof selected> = { value: 1 };
const inferredQuery: InferEndpointQuery<typeof selected> = { include: true };
const inferredQueryInput: InferEndpointQueryInput<typeof selected> = { include: 'true' };
const inferredParams: InferEndpointParams<typeof selected> = { id: '1' };
const inferredParamsInput: InferEndpointParamsInput<typeof selected> = { id: 1 };
const inferredResponses: InferEndpointResponses<typeof selected> = { 200: { ok: true }, 404: { error: 'missing' } };
const inferredHandler: InferEndpointHandler<typeof selected> = 'typedPublishedFixture';
const inferredMethod: 'POST' = selected.method;
const inferredPath: '/typed-published-fixture/:id' = selected.path;
// @ts-expect-error published body projection must not widen to any
const wrongBody: InferEndpointBody<typeof selected> = { value: 1 };
// @ts-expect-error published body-input projection must not widen to any
const wrongBodyInput: InferEndpointBodyInput<typeof selected> = { value: false };
// @ts-expect-error published query projection must not widen to any
const wrongQuery: InferEndpointQuery<typeof selected> = { include: 'true' };
// @ts-expect-error published query-input projection must not widen to any
const wrongQueryInput: InferEndpointQueryInput<typeof selected> = { include: 1 };
// @ts-expect-error published params projection must not widen to any
const wrongParams: InferEndpointParams<typeof selected> = { id: 1 };
// @ts-expect-error published params-input projection must not widen to any
const wrongParamsInput: InferEndpointParamsInput<typeof selected> = { id: false };
// @ts-expect-error published response projection must not widen to any
const wrongResponses: InferEndpointResponses<typeof selected> = { 200: { ok: false }, 404: { error: 'missing' } };
// @ts-expect-error published handler projection must preserve its literal
const wrongHandler: InferEndpointHandler<typeof selected> = 'other';
// @ts-expect-error published method projection must preserve its literal
const wrongMethod: 'GET' = selected.method;
// @ts-expect-error published path projection must preserve its literal
const wrongPath: '/other' = selected.path;
void [
  inferredBody,
  inferredBodyInput,
  inferredQuery,
  inferredQueryInput,
  inferredParams,
  inferredParamsInput,
  inferredResponses,
  inferredHandler,
  inferredMethod,
  inferredPath,
  wrongBody,
  wrongBodyInput,
  wrongQuery,
  wrongQueryInput,
  wrongParams,
  wrongParamsInput,
  wrongResponses,
  wrongHandler,
  wrongMethod,
  wrongPath,
];

protect(fortress, selected, (ctx) => {
  const body: TypedBody = ctx.body;
  const query: TypedQuery = ctx.query;
  const params: TypedParams = ctx.params;
  const input: TypedBody & TypedQuery & TypedParams = ctx.input;
  const endpointPath: '/typed-published-fixture/:id' = ctx.endpoint.path;
  // @ts-expect-error published-target contexts expose a frozen endpoint path
  ctx.endpoint.path = '/changed';
  // @ts-expect-error published-target contexts expose frozen endpoint metadata
  ctx.endpoint.meta = { summary: 'Changed' };
  // @ts-expect-error published-target contexts expose a frozen security array
  ctx.endpoint.meta!.security!.push('none');
  // @ts-expect-error published-target contexts expose a frozen response map
  ctx.endpoint.responses![200] = { description: 'Changed' };
  ctx.respond(404, { error: 'missing' });
  // @ts-expect-error published endpoint inference rejects undeclared response statuses
  ctx.respond(201, { ok: true });
  // @ts-expect-error published endpoint inference retains response-body correlation
  ctx.respond(404, { ok: true });
  return { body, query, params, input, endpointPath };
});

protect(fortress, typedMutableEndpoint, (ctx) => {
  const body: TypedBody = ctx.body;
  const endpointPath: '/typed-mutable-fixture/:id' = ctx.endpoint.path;
  // @ts-expect-error mutable-target contexts still expose the frozen snapshot path
  ctx.endpoint.path = '/changed';
  // @ts-expect-error mutable-target contexts expose frozen endpoint metadata
  ctx.endpoint.meta = { summary: 'Changed' };
  // @ts-expect-error mutable-target contexts expose a frozen security array
  ctx.endpoint.meta!.security!.push('none');
  // @ts-expect-error mutable-target contexts expose a frozen response map
  ctx.endpoint.responses![200] = { description: 'Changed' };
  return { body, endpointPath };
});

const resolvedMutable = resolveProtectedEndpoint(fortress, typedMutableEndpoint);
const resolvedMutablePath: '/typed-mutable-fixture/:id' = resolvedMutable.path;
// @ts-expect-error eager resolution also returns a frozen published projection
resolvedMutable.path = '/changed';
void resolvedMutablePath;

// Capability aliases continue to accept the concrete published instance.
const erased: Fortress = fortress;
void erased;
