import type { AnyEndpointDefinition, AnyPublishedEndpointDefinition, EndpointDefinitionLike } from './endpoint';
import type {
  FortressPlugin,
  MiddlewareDefinition,
  ModelConstraint,
  ModelDefinition,
  PluginDependency,
  PluginHooks,
  PluginMethod,
  PostAuthGateProvider,
  RuntimeFortressPlugin,
} from './plugin';
import { Errors } from './errors';
import { endpointOwner, snapshotEndpointDefinition } from './route-assembly';

/** Non-forgeable proof for arrays created by this exact module instance. */
const capabilityViews = new WeakSet<object>();

const MIDDLEWARE_HTTP_METHODS = new Set([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'DELETE',
  'CONNECT',
  'OPTIONS',
  'TRACE',
  'PATCH',
]);

const PLUGIN_FIELDS = [
  'name',
  'models',
  'dependencies',
  'hooks',
  'routes',
  'coreOverrides',
  'middleware',
  'wrapAdapter',
  'enrichTokenClaims',
  'scopeRules',
  'resolvePrincipal',
  'methods',
] as const;

type PluginField = typeof PLUGIN_FIELDS[number];
type MaterializedPlugin = RuntimeFortressPlugin;
type CapabilityView = readonly RuntimeFortressPlugin[];

type ControllerState
  = { phase: 'constructing'; sources: readonly RuntimeFortressPlugin[] }
    | { phase: 'final'; plugins: readonly MaterializedPlugin[] }
    | { phase: 'failed' };

export interface PluginCapabilityController {
  readonly plugins: CapabilityView;
  finalize: (plugins: readonly MaterializedPlugin[]) => void;
  fail: () => void;
}

function capabilityError(pluginName: string, field: string, message: string): never {
  throw Errors.badRequest(`Plugin "${pluginName}" ${field} ${message}`, {
    details: { plugin: pluginName, field },
  });
}

function readKnown(source: object, field: PluginField): unknown {
  return Reflect.get(source, field);
}

function captureCallable(
  pluginName: string,
  field: string,
  value: unknown,
  receiver: object,
): PluginMethod | undefined {
  if (value === undefined)
    return undefined;
  if (typeof value !== 'function')
    capabilityError(pluginName, field, 'must be callable');
  const callable = value as PluginMethod;
  return function capturedPluginCallable(...args: any[]): any {
    return Reflect.apply(callable, receiver, args);
  };
}

function denseArray(pluginName: string, field: string, value: unknown): unknown[] {
  if (!Array.isArray(value))
    capabilityError(pluginName, field, 'must be an array');
  const captured: unknown[] = [];
  const length = value.length;
  for (let index = 0; index < length; index++) {
    if (!Object.hasOwn(value, index))
      capabilityError(pluginName, `${field}[${index}]`, 'must not contain holes or undefined');
    const item = Reflect.get(value, index) as unknown;
    if (item === undefined)
      capabilityError(pluginName, `${field}[${index}]`, 'must not contain holes or undefined');
    captured.push(item);
  }
  return captured;
}

function snapshotStringList(pluginName: string, field: string, value: unknown): readonly string[] | undefined {
  if (value === undefined)
    return undefined;
  const list = denseArray(pluginName, field, value);
  for (let index = 0; index < list.length; index++) {
    const item = list[index];
    if (typeof item !== 'string' || item.length === 0)
      capabilityError(pluginName, `${field}[${index}]`, 'must be a non-empty string');
  }
  return Object.freeze([...list]) as readonly string[];
}

function snapshotDependencies(pluginName: string, value: unknown): readonly PluginDependency[] | undefined {
  if (value === undefined)
    return undefined;
  const dependencies = denseArray(pluginName, 'dependencies', value);
  return Object.freeze(dependencies.map((dependency, index) => {
    if (!dependency || typeof dependency !== 'object' || Array.isArray(dependency))
      capabilityError(pluginName, `dependencies[${index}]`, 'must be an object');
    const name = Reflect.get(dependency, 'plugin') as unknown;
    if (typeof name !== 'string' || name.length === 0)
      capabilityError(pluginName, `dependencies[${index}].plugin`, 'must be a non-empty string');
    const methods = snapshotStringList(pluginName, `dependencies[${index}].methods`, Reflect.get(dependency, 'methods'));
    return Object.freeze({ plugin: name, ...(methods ? { methods } : {}) });
  }));
}

function snapshotConstraints(pluginName: string, modelIndex: number, value: unknown): readonly ModelConstraint[] | undefined {
  if (value === undefined)
    return undefined;
  const constraints = denseArray(pluginName, `models[${modelIndex}].constraints`, value);
  return Object.freeze(constraints.map((constraint, index) => {
    if (!constraint || typeof constraint !== 'object' || Array.isArray(constraint))
      capabilityError(pluginName, `models[${modelIndex}].constraints[${index}]`, 'must be an object');
    const type = Reflect.get(constraint, 'type') as unknown;
    if (type !== 'unique' && type !== 'index')
      capabilityError(pluginName, `models[${modelIndex}].constraints[${index}].type`, 'must be unique or index');
    const fields = snapshotStringList(pluginName, `models[${modelIndex}].constraints[${index}].fields`, Reflect.get(constraint, 'fields'));
    if (!fields)
      capabilityError(pluginName, `models[${modelIndex}].constraints[${index}].fields`, 'must be an array');
    const name = Reflect.get(constraint, 'name') as unknown;
    if (name !== undefined && typeof name !== 'string')
      capabilityError(pluginName, `models[${modelIndex}].constraints[${index}].name`, 'must be a string');
    return Object.freeze({
      type,
      fields: fields as unknown as string[],
      ...(name !== undefined ? { name } : {}),
    }) as ModelConstraint;
  }));
}

function snapshotModels(pluginName: string, value: unknown): readonly ModelDefinition[] | undefined {
  if (value === undefined)
    return undefined;
  const models = denseArray(pluginName, 'models', value);
  return Object.freeze(models.map((model, modelIndex) => {
    if (!model || typeof model !== 'object' || Array.isArray(model))
      capabilityError(pluginName, `models[${modelIndex}]`, 'must be an object');
    const name = Reflect.get(model, 'name') as unknown;
    const fieldsValue = Reflect.get(model, 'fields') as unknown;
    if (typeof name !== 'string' || name.length === 0)
      capabilityError(pluginName, `models[${modelIndex}].name`, 'must be a non-empty string');
    if (!fieldsValue || typeof fieldsValue !== 'object' || Array.isArray(fieldsValue))
      capabilityError(pluginName, `models[${modelIndex}].fields`, 'must be an object');
    const fields = Object.create(null) as ModelDefinition['fields'];
    for (const [fieldName, fieldValue] of Object.entries(fieldsValue)) {
      if (!fieldValue || typeof fieldValue !== 'object' || Array.isArray(fieldValue))
        capabilityError(pluginName, `models[${modelIndex}].fields.${fieldName}`, 'must be an object');
      const type = Reflect.get(fieldValue, 'type') as unknown;
      if (!['string', 'number', 'boolean', 'date'].includes(type as string))
        capabilityError(pluginName, `models[${modelIndex}].fields.${fieldName}.type`, 'is invalid');
      const required = Reflect.get(fieldValue, 'required') as unknown;
      const unique = Reflect.get(fieldValue, 'unique') as unknown;
      if (required !== undefined && typeof required !== 'boolean')
        capabilityError(pluginName, `models[${modelIndex}].fields.${fieldName}.required`, 'must be boolean');
      if (unique !== undefined && typeof unique !== 'boolean')
        capabilityError(pluginName, `models[${modelIndex}].fields.${fieldName}.unique`, 'must be boolean');
      const referenceValue = Reflect.get(fieldValue, 'references') as unknown;
      let references: { model: string; field: string } | undefined;
      if (referenceValue !== undefined) {
        if (!referenceValue || typeof referenceValue !== 'object' || Array.isArray(referenceValue))
          capabilityError(pluginName, `models[${modelIndex}].fields.${fieldName}.references`, 'must be an object');
        const referenceModel = Reflect.get(referenceValue, 'model') as unknown;
        const referenceField = Reflect.get(referenceValue, 'field') as unknown;
        if (typeof referenceModel !== 'string' || typeof referenceField !== 'string')
          capabilityError(pluginName, `models[${modelIndex}].fields.${fieldName}.references`, 'must contain string model and field');
        references = Object.freeze({ model: referenceModel, field: referenceField });
      }
      fields[fieldName] = Object.freeze({
        type: type as 'string' | 'number' | 'boolean' | 'date',
        ...(required !== undefined ? { required } : {}),
        ...(unique !== undefined ? { unique } : {}),
        ...(references ? { references } : {}),
      });
    }
    Object.freeze(fields);
    const constraints = snapshotConstraints(pluginName, modelIndex, Reflect.get(model, 'constraints'));
    return Object.freeze({
      name,
      fields,
      ...(constraints ? { constraints: constraints as unknown as ModelConstraint[] } : {}),
    });
  }));
}

function snapshotMiddleware(pluginName: string, value: unknown): readonly MiddlewareDefinition[] | undefined {
  if (value === undefined)
    return undefined;
  const middlewareList = denseArray(pluginName, 'middleware', value);
  return Object.freeze(middlewareList.map((middleware, index) => {
    if (!middleware || typeof middleware !== 'object' || Array.isArray(middleware))
      capabilityError(pluginName, `middleware[${index}]`, 'must be an object');
    const path = Reflect.get(middleware, 'path') as unknown;
    const position = Reflect.get(middleware, 'position') as unknown;
    const handler = Reflect.get(middleware, 'handler') as unknown;
    if (typeof path !== 'string' || path.length === 0)
      capabilityError(pluginName, `middleware[${index}].path`, 'must be a non-empty string');
    if (!['before-auth', 'after-auth', 'after-rbac'].includes(position as string))
      capabilityError(pluginName, `middleware[${index}].position`, 'is invalid');
    const capturedHandler = captureCallable(
      pluginName,
      `middleware[${index}].handler`,
      handler,
      middleware,
    );
    if (!capturedHandler)
      capabilityError(pluginName, `middleware[${index}].handler`, 'must be callable');
    const methodsValue = Reflect.get(middleware, 'methods') as unknown;
    let methods: readonly string[] | undefined;
    if (methodsValue !== undefined) {
      const methodList = denseArray(pluginName, `middleware[${index}].methods`, methodsValue);
      for (let methodIndex = 0; methodIndex < methodList.length; methodIndex++) {
        const method = methodList[methodIndex];
        if (typeof method !== 'string' || !MIDDLEWARE_HTTP_METHODS.has(method.toUpperCase()))
          capabilityError(pluginName, `middleware[${index}].methods[${methodIndex}]`, 'must be a valid HTTP method');
      }
      methods = Object.freeze([...methodList]) as readonly string[];
    }
    return Object.freeze({
      path,
      position,
      handler: capturedHandler,
      ...(methods ? { methods: methods as string[] } : {}),
    }) as MiddlewareDefinition;
  }));
}

const HOOK_NAMES = [
  'beforeLogin',
  'beforeRegister',
  'beforeTokenRefresh',
  'beforeLogout',
  'onLoginFailure',
  'afterLogin',
  'afterRegister',
  'afterTokenRefresh',
] as const;

function snapshotPostAuthGate(pluginName: string, value: unknown): PostAuthGateProvider | undefined {
  if (value === undefined)
    return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value))
    capabilityError(pluginName, 'hooks.postAuthGate', 'must be an object');
  const reason = Reflect.get(value, 'reason') as unknown;
  const maxAttempts = Reflect.get(value, 'maxAttempts') as unknown;
  const cooldownSeconds = Reflect.get(value, 'cooldownSeconds') as unknown;
  const evaluate = Reflect.get(value, 'evaluate') as unknown;
  const verify = Reflect.get(value, 'verify') as unknown;
  if (!['two-factor', 'webauthn', 'email-verification', 'magic-link'].includes(reason as string))
    capabilityError(pluginName, 'hooks.postAuthGate.reason', 'is invalid');
  if (maxAttempts !== undefined && (!Number.isInteger(maxAttempts) || (maxAttempts as number) <= 0))
    capabilityError(pluginName, 'hooks.postAuthGate.maxAttempts', 'must be a positive integer');
  if (cooldownSeconds !== undefined && (!Number.isFinite(cooldownSeconds) || (cooldownSeconds as number) < 0))
    capabilityError(pluginName, 'hooks.postAuthGate.cooldownSeconds', 'must be a non-negative number');
  const capturedEvaluate = captureCallable(
    pluginName,
    'hooks.postAuthGate.evaluate',
    evaluate,
    value,
  );
  const capturedVerify = captureCallable(
    pluginName,
    'hooks.postAuthGate.verify',
    verify,
    value,
  );
  if (!capturedEvaluate)
    capabilityError(pluginName, 'hooks.postAuthGate.evaluate', 'must be callable');
  if (!capturedVerify)
    capabilityError(pluginName, 'hooks.postAuthGate.verify', 'must be callable');
  return Object.freeze({
    reason: reason as PostAuthGateProvider['reason'],
    ...(maxAttempts !== undefined ? { maxAttempts: maxAttempts as number } : {}),
    ...(cooldownSeconds !== undefined ? { cooldownSeconds: cooldownSeconds as number } : {}),
    evaluate: capturedEvaluate,
    verify: capturedVerify,
  });
}

function snapshotHooks(pluginName: string, value: unknown): PluginHooks | undefined {
  if (value === undefined)
    return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value))
    capabilityError(pluginName, 'hooks', 'must be an object');
  const hooks: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const hookName of HOOK_NAMES) {
    const hook = Reflect.get(value, hookName) as unknown;
    if (hook !== undefined)
      hooks[hookName] = captureCallable(pluginName, `hooks.${hookName}`, hook, value);
  }
  const postAuthGate = snapshotPostAuthGate(pluginName, Reflect.get(value, 'postAuthGate'));
  if (postAuthGate)
    hooks.postAuthGate = postAuthGate;
  return Object.freeze(hooks) as PluginHooks;
}

function snapshotRoutes(pluginName: string, value: unknown): FortressPlugin['routes'] {
  if (value === undefined)
    return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value))
    capabilityError(pluginName, 'routes', 'must be an object');
  const routes = Object.create(null) as Record<string, EndpointDefinitionLike>;
  for (const key of Object.keys(value)) {
    const endpoint = Reflect.get(value, key) as unknown;
    routes[key] = snapshotEndpointDefinition(endpoint as AnyEndpointDefinition);
  }
  return Object.freeze(routes) as unknown as FortressPlugin['routes'];
}

/** Materialize every known descriptor slot once after all factories return. */
export function materializePluginCapabilities(
  sources: readonly RuntimeFortressPlugin[],
): readonly MaterializedPlugin[] {
  const plugins = Object.freeze(sources.map((source, index) => {
    if (!source || typeof source !== 'object' || Array.isArray(source))
      throw Errors.badRequest(`Plugin at index ${index} must be an object`);
    const name = readKnown(source, 'name');
    if (typeof name !== 'string' || name.length === 0)
      throw Errors.badRequest(`Plugin at index ${index} name must be a non-empty string`);

    const models = snapshotModels(name, readKnown(source, 'models'));
    const dependencies = snapshotDependencies(name, readKnown(source, 'dependencies'));
    const hooks = snapshotHooks(name, readKnown(source, 'hooks'));
    const routes = snapshotRoutes(name, readKnown(source, 'routes'));
    const coreOverrides = snapshotStringList(name, 'coreOverrides', readKnown(source, 'coreOverrides'));
    const middleware = snapshotMiddleware(name, readKnown(source, 'middleware'));
    const wrapAdapter = captureCallable(name, 'wrapAdapter', readKnown(source, 'wrapAdapter'), source);
    const enrichTokenClaims = captureCallable(name, 'enrichTokenClaims', readKnown(source, 'enrichTokenClaims'), source);
    const scopeRules = captureCallable(name, 'scopeRules', readKnown(source, 'scopeRules'), source);
    const resolvePrincipal = captureCallable(name, 'resolvePrincipal', readKnown(source, 'resolvePrincipal'), source);
    const methods = captureCallable(name, 'methods', readKnown(source, 'methods'), source);

    return Object.freeze({
      name,
      ...(models ? { models: models as unknown as ModelDefinition[] } : {}),
      ...(dependencies ? { dependencies } : {}),
      ...(hooks ? { hooks } : {}),
      ...(routes ? { routes } : {}),
      ...(coreOverrides ? { coreOverrides } : {}),
      ...(middleware ? { middleware: middleware as unknown as MiddlewareDefinition[] } : {}),
      ...(wrapAdapter ? { wrapAdapter } : {}),
      ...(enrichTokenClaims ? { enrichTokenClaims } : {}),
      ...(scopeRules ? { scopeRules } : {}),
      ...(resolvePrincipal ? { resolvePrincipal } : {}),
      ...(methods ? { methods } : {}),
    }) as MaterializedPlugin;
  }));
  const gateReasons = new Set<string>();
  for (const plugin of plugins) {
    const reason = plugin.hooks?.postAuthGate?.reason;
    if (reason !== undefined && gateReasons.has(reason))
      capabilityError(plugin.name, 'hooks.postAuthGate.reason', `duplicates auth gate reason '${reason}'`);
    if (reason !== undefined)
      gateReasons.add(reason);
  }
  return plugins;
}

/** Replace candidate route records with the authoritative published endpoints. */
export function bindPublishedPluginRoutes(
  plugins: readonly MaterializedPlugin[],
  endpoints: readonly AnyPublishedEndpointDefinition[],
): readonly MaterializedPlugin[] {
  const byOwnerAndRoute = new Map<string, AnyPublishedEndpointDefinition>();
  for (const endpoint of endpoints) {
    const owner = endpointOwner(endpoint);
    if (typeof owner === 'string')
      byOwnerAndRoute.set(`${owner}\0${endpoint.method.toUpperCase()}\0${endpoint.path}`, endpoint);
  }
  return Object.freeze(plugins.map((plugin) => {
    let routes: FortressPlugin['routes'];
    if (plugin.routes) {
      const published = Object.create(null) as Record<string, AnyPublishedEndpointDefinition>;
      for (const [key, endpoint] of Object.entries(plugin.routes)) {
        const snapshot = byOwnerAndRoute.get(`${plugin.name}\0${endpoint.method.toUpperCase()}\0${endpoint.path}`);
        if (!snapshot)
          throw Errors.badRequest(`Plugin "${plugin.name}" route "${key}" has no published endpoint snapshot`);
        published[key] = snapshot;
      }
      routes = Object.freeze(published) as unknown as FortressPlugin['routes'];
    }
    const descriptor = Object.create(null) as Record<string, unknown>;
    for (const field of PLUGIN_FIELDS) {
      if (field === 'routes') {
        if (routes)
          descriptor.routes = routes;
        continue;
      }
      const value = Reflect.get(plugin, field) as unknown;
      if (value !== undefined)
        descriptor[field] = value;
    }
    return Object.freeze(descriptor) as unknown as MaterializedPlugin;
  }));
}

function provenView(plugins: readonly RuntimeFortressPlugin[]): CapabilityView {
  const view = [...plugins];
  capabilityViews.add(view);
  return Object.freeze(view);
}

export function isPluginCapabilityView(value: readonly RuntimeFortressPlugin[]): boolean {
  return Array.isArray(value) && Object.isFrozen(value) && capabilityViews.has(value);
}

/** Stable facades let built-in factories capture one array before finalization. */
export function createPluginCapabilityController(
  sources: readonly RuntimeFortressPlugin[],
): PluginCapabilityController {
  let state: ControllerState = { phase: 'constructing', sources };
  const facades = sources.map((_source, index) => {
    const facade = Object.create(null) as Record<string, unknown>;
    for (const field of PLUGIN_FIELDS) {
      Object.defineProperty(facade, field, {
        enumerable: true,
        configurable: false,
        get: () => {
          if (state.phase === 'failed')
            throw new TypeError('Fortress plugin capability view belongs to a failed construction');
          const plugin = state.phase === 'final' ? state.plugins[index] : state.sources[index];
          if (!plugin)
            throw new TypeError('Fortress plugin capability view is invalid');
          return Reflect.get(plugin, field);
        },
      });
    }
    return Object.freeze(facade) as unknown as RuntimeFortressPlugin;
  });
  const plugins = provenView(facades);
  return {
    plugins,
    finalize: (finalPlugins) => {
      if (state.phase !== 'constructing' || finalPlugins.length !== sources.length)
        throw new TypeError('Fortress plugin capability view cannot be finalized');
      state = { phase: 'final', plugins: finalPlugins };
    },
    fail: () => {
      state = { phase: 'failed' };
    },
  };
}

/** First-use fallback for focused capability fixtures. */
export function snapshotPluginCapabilities(
  sources: readonly RuntimeFortressPlugin[],
): CapabilityView {
  if (isPluginCapabilityView(sources))
    return sources;
  const materialized = materializePluginCapabilities(sources);
  const published = materialized.map((plugin) => {
    const descriptor = Object.create(null) as Record<string, unknown>;
    for (const field of PLUGIN_FIELDS) {
      const value = Reflect.get(plugin, field);
      if (value !== undefined)
        descriptor[field] = value;
    }
    return Object.freeze(descriptor) as unknown as RuntimeFortressPlugin;
  });
  return provenView(published);
}
