import type {
  AnyPublishedEndpointDefinition,
  AuthCookiePayload,
  AuthEndpointsMap,
  AuthService,
  CookieConfig,
  CreateServiceAccountInput,
  CsrfConfig,
  DatabaseAdapter,
  EndpointDefinitionLike,
  EndpointPermission,
  IamEndpointsMap,
  JsonOf,
  LogFn,
  LogLevel,
  OpenAPIMethods,
  PluginRouteContext,
  ProtectableEndpointDefinition,
  PublishedEndpointDefinition,
  PublishedEndpointInput,
  PublishedEndpointMeta,
  PublishedEndpointOf,
  PublishedEndpointPermission,
  PublishedEndpointResponse,
  PublishedRouteManifest,
  PublishedRouteManifestEntry,
  ResolvedCookieConfig,
  ResolvedPrincipal,
  RouteInputNotFlat,
  RouteManifestEntryLike,
  ServiceAccount,
  SessionInfo,
  Subject,
  ValidatedRequestData,
} from '@bajustone/fortress';
import type { ExpressCsrfConfig } from '@bajustone/fortress/express';
import type { HonoCsrfConfig } from '@bajustone/fortress/hono';
import type { ConformanceRunner } from '@bajustone/fortress/testing';
import { runAdapterTests } from '@bajustone/fortress/testing';

/**
 * Every type named in a root public signature must be importable from the
 * package root, with no deep import into `dist/` internals. Dropping any export
 * from `src/index.ts` breaks this fixture under both the source and the built
 * declaration contract.
 */
export interface RootTypeInventory {
  authService: AuthService;
  authCookiePayload: AuthCookiePayload;
  cookieConfig: CookieConfig;
  resolvedCookieConfig: ResolvedCookieConfig;
  resolvedPrincipal: ResolvedPrincipal;
  csrfConfig: CsrfConfig;
  pluginRouteContext: PluginRouteContext;
  sessionInfo: SessionInfo;
  serviceAccount: ServiceAccount;
  createServiceAccountInput: CreateServiceAccountInput;
}

/**
 * Types reachable from root signatures but previously unnameable by consumers.
 * `Subject` is the load-bearing one: it is the parameter type of several
 * `IamService` methods and the type of `ResolvedPrincipal.subject`.
 */
export interface ReachableCoreTypes {
  subject: Subject;
  principalSubject: ResolvedPrincipal['subject'];
  endpointPermission: EndpointPermission;
  validatedRequestData: ValidatedRequestData;
  logLevel: LogLevel;
  logFn: LogFn;
  authEndpointsMap: AuthEndpointsMap;
  iamEndpointsMap: IamEndpointsMap;
  serialized: JsonOf<{ when: Date; nested: { count: number } }>;
  routeInputNotFlat: RouteInputNotFlat<'handlerName'>;
  anyPublishedEndpoint: AnyPublishedEndpointDefinition;
  endpointDefinitionLike: EndpointDefinitionLike;
  protectableEndpoint: ProtectableEndpointDefinition;
  publishedEndpoint: PublishedEndpointDefinition;
  publishedEndpointInput: PublishedEndpointInput;
  publishedEndpointMeta: PublishedEndpointMeta;
  publishedEndpointOf: PublishedEndpointOf<EndpointDefinitionLike>;
  publishedEndpointPermission: PublishedEndpointPermission;
  publishedEndpointResponse: PublishedEndpointResponse;
  publishedManifest: PublishedRouteManifest;
  publishedManifestEntry: PublishedRouteManifestEntry;
  routeManifestEntryLike: RouteManifestEntryLike;
}

/** Every plugin method surface is reachable from root, including OpenAPI's. */
export interface PluginMethodSurfaces {
  openapi: OpenAPIMethods;
}

/**
 * The core policy type and both framework-specific shapes have to coexist in a
 * single module. The core one owns the plain `CsrfConfig` name; the adapters
 * provide unambiguous aliases so a consumer never has to rename on import.
 */
export interface CsrfNamingContract {
  core: CsrfConfig;
  hono: HonoCsrfConfig;
  express: ExpressCsrfConfig;
}

/**
 * Adapter conformance is supported public API: reachable from `/testing`, and
 * runner-neutral so the caller supplies `describe`/`it`/`beforeEach`.
 */
export const declareConformanceSuite: (
  createAdapter: () => DatabaseAdapter,
  runner: ConformanceRunner,
) => void = runAdapterTests;

export function declareRunnerShape(runner: ConformanceRunner): ConformanceRunner {
  return runner;
}
