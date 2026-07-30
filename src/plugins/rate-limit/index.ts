/**
 * Sliding-window rate limiting plugin for fortress.
 *
 * Protects built-in Fortress auth endpoints (`login`, `register`, `refresh`,
 * plus OAuth token issuance and API-key creation when those plugins are
 * mounted) and exposes a `check()` method + per-framework middleware
 * wrappers so consumers can rate-limit any of their own routes.
 *
 * Ships with an in-memory store; bring-your-own store via the
 * {@link RateLimitStore} interface for distributed deployments (Redis, etc).
 *
 * @module
 */

import type { PluginRequestContext } from '../../core/http/plugin-middleware';
import type { FortressPlugin, MiddlewareDefinition, PluginContext, PluginHooks } from '../../core/plugin';
import type { RateLimitStore } from './memory-store';
import { Errors } from '../../core/errors';
import { definePlugin } from '../../core/plugin';
import { createMemoryStore } from './memory-store';

export type { RateLimitStore } from './memory-store';

/**
 * A single rate-limit rule. At least one of `maxPerIp` / `maxPerUser` must be
 * set; if neither is set the rule is a no-op. Keys are checked independently
 * and the first to exceed short-circuits with a `rateLimited` error.
 */
export interface RateLimitRule {
  /** Max requests per client IP in the window. */
  maxPerIp?: number;
  /** Max requests per authenticated user in the window. Ignored if the check has no userId. */
  maxPerUser?: number;
  /** Sliding window length in seconds. */
  windowSeconds: number;
  /** Optional key-namespace override. Defaults to the rule name. */
  keyPrefix?: string;
}

/** Rate-limit config block for login (per-account adds an email-scoped key). */
export interface LoginRateLimit {
  maxPerIp?: number;
  maxPerAccount?: number;
  windowSeconds?: number;
}

export interface SimpleRateLimit {
  maxPerIp?: number;
  maxPerUser?: number;
  windowSeconds?: number;
}

/** Sentinel passed to the `login` / `register` blocks to opt out of the always-on defaults. */
export interface DisabledBlock {
  disabled: true;
}

export interface RateLimitConfig {
  /**
   * Limit for `POST /auth/login`. **Always on with defaults** when the plugin
   * is registered — pass `{ disabled: true }` to turn it off. This is a gate
   * plugin; leaving the default protects against silent loss of auth DoS
   * protection on upgrade.
   */
  login?: LoginRateLimit | DisabledBlock;
  /**
   * Limit for `POST /auth/register`. Same default-on / explicit-disable
   * behavior as `login` — both are security-critical gates.
   */
  register?: { maxPerIp?: number; windowSeconds?: number } | DisabledBlock;
  /** Limit for `POST /auth/refresh` (runs in `beforeTokenRefresh` hook). */
  refresh?: SimpleRateLimit;
  /** Limit for OAuth `POST /oauth/token` (IP-scoped; client_id lives in the form body). */
  oauthToken?: { maxPerIp?: number; windowSeconds?: number };
  /** Limit for API-key issuance `POST /api-key/keys` (requires authenticated user). */
  apiKeyIssue?: SimpleRateLimit;

  /**
   * Named rules referenced by `methods.check(name, keys)` and the
   * per-framework middleware wrappers. Use these for your own app routes
   * or for Fortress endpoints that don't have a dedicated config block
   * (magic-link, 2FA verify, email verification — these are methods-only,
   * so wire the limiter in your own handler).
   */
  rules?: Record<string, RateLimitRule>;

  /**
   * Extra path-based bindings for any route served by `fortress.handleRequest`.
   * Each entry binds a named rule (or inline rule) to a path glob.
   */
  paths?: PathBinding[];

  /** Custom store for rate-limit counters. Default: in-memory sliding window. */
  store?: RateLimitStore;
}

/**
 * Declarative rate-limit binding for a Fortress-dispatched path. Only fires
 * for routes that flow through `fortress.handleRequest`.
 *
 * **When to use `paths` vs the framework wrappers**:
 * - Framework wrappers (`honoRateLimit` / `expressRateLimit` /
 *   `svelteKitRateLimit`) — use when you have a middleware layer around your
 *   routes. Mount on any path, Fortress-owned or user-owned.
 * - `paths` — use in serverless / framework-less deployments that call
 *   `fortress.handleRequest` directly, or when you prefer declarative config
 *   co-located with the rest of the rate-limit setup.
 *
 * Both target the same store. **Don't stack both on the same path** — each
 * match increments the counter, so double-wrapping halves the effective
 * limit.
 */
export interface PathBinding {
  /** Path glob (supports `*` and `:param`). */
  match: string;
  /** HTTP methods to restrict to (uppercase). Omit to match all methods. */
  methods?: string[];
  /** Pipeline phase. `after-auth` required when keying per user. Default: `before-auth`. */
  position?: 'before-auth' | 'after-auth';
  /** Named rule key in `config.rules`, or an inline rule. */
  rule: string | RateLimitRule;
}

const DEFAULT_LOGIN = { maxPerIp: 10, maxPerAccount: 5, windowSeconds: 900 };
const DEFAULT_REGISTER = { maxPerIp: 3, windowSeconds: 3600 };
const DEFAULT_REFRESH = { maxPerIp: 60, maxPerUser: 60, windowSeconds: 60 };
const DEFAULT_OAUTH_TOKEN = { maxPerIp: 60, windowSeconds: 60 };
const DEFAULT_API_KEY_ISSUE = { maxPerIp: 10, maxPerUser: 10, windowSeconds: 3600 };

/**
 * Normalize an IPv6 address to its /64 prefix to prevent bypass via address rotation.
 * IPv4 addresses are returned as-is.
 */
export function normalizeIp(ip: string | undefined | null): string {
  if (!ip)
    return 'unknown';
  if (ip.startsWith('::ffff:'))
    return ip.slice(7);
  if (ip.includes(':'))
    return ip.split(':').slice(0, 4).join(':');
  return ip;
}

/** Canonical key for account-scoped login limits. */
export function normalizeAccountIdentifier(identifier: string): string {
  return identifier.trim().normalize('NFC').toLowerCase();
}

function firstForwardedIp(value: string): string {
  const [firstHop] = value.split(',');
  if (firstHop === undefined)
    throw new Error('Forwarded IP invariant violated: header has no first hop');
  return firstHop.trim();
}

/** Read an IP from a standard web Request's forwarding headers. */
function ipFromRequest(request: Request): string {
  const xff = request.headers.get('x-forwarded-for');
  if (xff)
    return firstForwardedIp(xff);
  return request.headers.get('x-real-ip') ?? '';
}

export interface RateLimitCheckKeys {
  ip?: string | null;
  userId?: string | null;
}

export interface RateLimitMethods {
  check: (ruleName: string, keys: RateLimitCheckKeys) => Promise<void>;
  listRules: () => string[];
}

async function runRule(
  store: RateLimitStore,
  ruleName: string,
  rule: RateLimitRule,
  keys: RateLimitCheckKeys,
): Promise<void> {
  const windowMs = rule.windowSeconds * 1000;
  const prefix = rule.keyPrefix ?? ruleName;

  // IP-keyed check: normalize undefined → 'unknown' so missing client IP
  // still increments (matches legacy behavior and guards against request
  // smuggling via omitted headers). Skip only when `maxPerIp` is unset.
  if (rule.maxPerIp != null) {
    const ip = normalizeIp(keys.ip);
    const res = await store.increment(`${prefix}:ip:${ip}`, windowMs);
    if (res.count > rule.maxPerIp) {
      const retryAfter = Math.max(Math.ceil((res.resetAt - Date.now()) / 1000), 1);
      throw Errors.rateLimited(retryAfter);
    }
  }

  // User-keyed check: only runs when a userId is actually present — no
  // fallback identifier, as unauthenticated requests can't be rate-limited
  // per account here.
  if (rule.maxPerUser != null && keys.userId != null) {
    const res = await store.increment(`${prefix}:user:${keys.userId}`, windowMs);
    if (res.count > rule.maxPerUser) {
      const retryAfter = Math.max(Math.ceil((res.resetAt - Date.now()) / 1000), 1);
      throw Errors.rateLimited(retryAfter);
    }
  }
}

/**
 * Rate limit plugin factory. Returns a {@link FortressPlugin} that enforces
 * sliding-window limits on Fortress's sensitive auth endpoints and exposes a
 * programmatic `check()` method for rate-limiting arbitrary user routes.
 *
 * @example Basic usage
 * ```ts
 * rateLimit({
 *   login: { maxPerIp: 10, maxPerAccount: 5, windowSeconds: 900 },
 *   refresh: { maxPerIp: 60, windowSeconds: 60 },
 *   rules: {
 *     api: { maxPerIp: 100, windowSeconds: 60 },
 *   },
 * })
 * ```
 *
 * @example Rate-limiting your own routes (Hono)
 * ```ts
 * import { honoRateLimit } from '@bajustone/fortress/plugins/rate-limit/hono';
 * app.use('/api/*', honoRateLimit(fortress, 'api'));
 * ```
 */
/** True when the user passed `{ disabled: true }` to opt out of a gate block. */
function isDisabled(
  block: LoginRateLimit | { maxPerIp?: number; windowSeconds?: number } | DisabledBlock | undefined,
): block is DisabledBlock {
  return !!block && 'disabled' in block && block.disabled === true;
}

export function rateLimit(config: RateLimitConfig = {}): FortressPlugin<'rate-limit', RateLimitMethods, undefined> {
  const store = config.store ?? createMemoryStore();

  // Gate blocks — always on with defaults; `{ disabled: true }` opts out.
  const loginCfg = isDisabled(config.login)
    ? undefined
    : { ...DEFAULT_LOGIN, ...(config.login as LoginRateLimit | undefined) };
  const registerCfg = isDisabled(config.register)
    ? undefined
    : { ...DEFAULT_REGISTER, ...(config.register as { maxPerIp?: number; windowSeconds?: number } | undefined) };
  // Opt-in blocks — stay off unless the block is present.
  const refreshCfg = config.refresh ? { ...DEFAULT_REFRESH, ...config.refresh } : undefined;
  const oauthTokenCfg = config.oauthToken ? { ...DEFAULT_OAUTH_TOKEN, ...config.oauthToken } : undefined;
  const apiKeyIssueCfg = config.apiKeyIssue ? { ...DEFAULT_API_KEY_ISSUE, ...config.apiKeyIssue } : undefined;

  // Build the rule registry. User rules first, then built-in names (built-ins
  // win on collision — prevents accidental override of the auth-endpoint limits).
  const rules: Record<string, RateLimitRule> = { ...config.rules };

  if (loginCfg) {
    rules.login = { maxPerIp: loginCfg.maxPerIp, windowSeconds: loginCfg.windowSeconds };
    // Per-account limit uses the login rule's window but a distinct key prefix.
    if (loginCfg.maxPerAccount != null) {
      rules['login:account'] = {
        maxPerUser: loginCfg.maxPerAccount,
        windowSeconds: loginCfg.windowSeconds,
        keyPrefix: 'login:account',
      };
    }
  }
  if (registerCfg)
    rules.register = { maxPerIp: registerCfg.maxPerIp, windowSeconds: registerCfg.windowSeconds };
  if (refreshCfg) {
    rules.refresh = {
      maxPerIp: refreshCfg.maxPerIp,
      maxPerUser: refreshCfg.maxPerUser,
      windowSeconds: refreshCfg.windowSeconds,
    };
  }
  if (oauthTokenCfg)
    rules.oauthToken = { maxPerIp: oauthTokenCfg.maxPerIp, windowSeconds: oauthTokenCfg.windowSeconds };
  if (apiKeyIssueCfg) {
    rules.apiKeyIssue = {
      maxPerIp: apiKeyIssueCfg.maxPerIp,
      maxPerUser: apiKeyIssueCfg.maxPerUser,
      windowSeconds: apiKeyIssueCfg.windowSeconds,
    };
  }

  async function check(ruleName: string, keys: RateLimitCheckKeys): Promise<void> {
    const rule = rules[ruleName];
    if (!rule)
      throw new Error(`rate-limit: unknown rule '${ruleName}' — declare it in config.rules or add the matching endpoint config block`);
    await runRule(store, ruleName, rule, keys);
  }

  // Build MiddlewareDefinition entries for each bound endpoint config block +
  // user-provided `paths`. Each handler rate-checks then calls next().
  const middleware: MiddlewareDefinition[] = [];

  const bindBuiltin = (
    ruleName: string,
    match: string,
    methodFilter: string[] | undefined,
    position: 'before-auth' | 'after-auth',
  ): void => {
    const runtimeMethods = methodFilter ? Object.freeze([...methodFilter]) : undefined;
    const descriptorMethods = runtimeMethods ? [...runtimeMethods] : undefined;
    middleware.push({
      path: match,
      position,
      ...(descriptorMethods ? { methods: descriptorMethods } : {}),
      handler: async (_ctx: PluginContext, request: PluginRequestContext, next: () => Promise<void>) => {
        const req = request.request;
        if (!(req instanceof Request))
          throw Errors.badRequest('PluginRequestContext.request is required');
        if (runtimeMethods && !runtimeMethods.includes(req.method)) {
          await next();
          return;
        }
        const { fortressUserId: userId } = request;
        await check(ruleName, { ip: ipFromRequest(req), userId });
        await next();
      },
    });
  };

  if (oauthTokenCfg)
    bindBuiltin('oauthToken', '/oauth/token', ['POST'], 'before-auth');
  if (apiKeyIssueCfg)
    bindBuiltin('apiKeyIssue', '/api-key/keys', ['POST'], 'after-auth');

  for (const binding of config.paths ?? []) {
    const inlineRule = typeof binding.rule === 'object' ? binding.rule : null;
    const ruleName = typeof binding.rule === 'string' ? binding.rule : `path:${binding.match}`;
    if (inlineRule)
      rules[ruleName] = inlineRule;
    else if (!rules[ruleName])
      throw new Error(`rate-limit: unknown rule reference '${binding.rule}' in paths config`);

    const position = binding.position ?? 'before-auth';
    const methodFilter = binding.methods?.map(m => m.toUpperCase());
    const runtimeMethods = methodFilter ? Object.freeze([...methodFilter]) : undefined;
    const descriptorMethods = runtimeMethods ? [...runtimeMethods] : undefined;
    middleware.push({
      path: binding.match,
      position,
      ...(descriptorMethods ? { methods: descriptorMethods } : {}),
      handler: async (_ctx: PluginContext, request: PluginRequestContext, next: () => Promise<void>) => {
        const req = request.request;
        if (!(req instanceof Request))
          throw Errors.badRequest('PluginRequestContext.request is required');
        if (runtimeMethods && !runtimeMethods.includes(req.method)) {
          await next();
          return;
        }
        const { fortressUserId: userId } = request;
        await check(ruleName, { ip: ipFromRequest(req), userId });
        await next();
      },
    });
  }

  const hooks: PluginHooks = {};
  if (loginCfg) {
    hooks.beforeLogin = async (ctx) => {
      const ip = ctx.meta?.ipAddress;
      const email = ctx.email;
      // Per-IP
      if (loginCfg.maxPerIp != null)
        await check('login', { ip });
      // Per-account (identifier keyed as userId slot on the synthetic rule)
      if (loginCfg.maxPerAccount != null)
        await check('login:account', { userId: normalizeAccountIdentifier(email) });
    };
  }
  if (registerCfg) {
    hooks.beforeRegister = async (ctx) => {
      await check('register', { ip: ctx.meta?.ipAddress });
    };
  }
  if (refreshCfg) {
    hooks.beforeTokenRefresh = async (ctx) => {
      const ip = ctx.meta?.ipAddress;
      // Best-effort per-user limit: the hook runs before the refresh token
      // is verified, so userId isn't known yet. IP-only here; per-user is
      // enforced via the `/auth/refresh`-aware middleware when you mount
      // refresh under a user-scoped wrapper in your own code.
      await check('refresh', { ip });
    };
  }

  return definePlugin({
    name: 'rate-limit',

    ...(middleware.length > 0 ? { middleware } : {}),
    ...(Object.keys(hooks).length > 0 ? { hooks } : {}),

    methods: (_ctx: PluginContext) => ({
      check,
      /** Read-only view of the resolved rule registry (debug / introspection). */
      listRules: (): string[] => Object.keys(rules),
    }),
  } satisfies FortressPlugin<'rate-limit', RateLimitMethods>);
}
