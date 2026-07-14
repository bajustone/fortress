import { Errors } from '../errors';
import { createOutboundClient } from '../http/outbound';
import { normalizePasswordInput } from './password';

export type PasswordBreachFailureMode = 'open' | 'closed';

export interface PasswordBreachDegradedEvent {
  failureMode: PasswordBreachFailureMode;
  status?: number;
  error?: unknown;
}

/** Called whenever the HIBP control is unavailable, regardless of failure mode. */
export type PasswordPolicyObserver = (event: PasswordBreachDegradedEvent) => void;

export interface PasswordPolicyConfig {
  /** Minimum password length. Default: 15 (NIST 800-63B). */
  minLength?: number;
  /** Maximum password length. Default: 128 (NIST 800-63B). */
  maxLength?: number;
  /** Check password against HIBP breached password database via k-anonymity API. Default: false. */
  checkBreached?: boolean;
  /** Cache TTL for HIBP range responses in milliseconds. Default: 86400000 (24h). */
  breachedCacheTtlMs?: number;
  /** Maximum cached HIBP range responses. Default: 1000. Set to 0 to disable caching. */
  breachedCacheMaxEntries?: number;
  /** Whether HIBP unavailability permits password writes. Default: 'open'. */
  breachedFailureMode?: PasswordBreachFailureMode;
}

type HibpCache = Map<string, { data: string; expiresAt: number }>;

export interface PasswordBreachCheckOptions {
  cacheTtlMs?: number;
  cacheMaxEntries?: number;
  failureMode?: PasswordBreachFailureMode;
  observer?: PasswordPolicyObserver;
  /** Internal per-Fortress-instance cache supplied by validatePassword. */
  cache?: HibpCache;
}

const DEFAULT_MIN_LENGTH = 15;
const DEFAULT_MAX_LENGTH = 128;
const DEFAULT_CACHE_TTL_MS = 86_400_000; // 24 hours
const DEFAULT_CACHE_MAX_ENTRIES = 1_000;
// Tighter timeout than the default outbound budget: the breach check runs in
// the password-validation hot path, so a slow HIBP must not stall writes.
const HIBP_TIMEOUT_MS = 6_000;
const hibpOutboundClient = createOutboundClient(HIBP_TIMEOUT_MS);

// Direct isPasswordBreached callers share this convenience cache. Fortress
// instances use a cache keyed by their own PasswordPolicyConfig object so one
// tenant's bound/eviction policy cannot mutate a co-resident instance's cache.
const directHibpCache: HibpCache = new Map();
const policyCaches = new WeakMap<PasswordPolicyConfig, HibpCache>();
const knownCaches = new Set<HibpCache>([directHibpCache]);

function cacheForPolicy(config: PasswordPolicyConfig): HibpCache {
  let cache = policyCaches.get(config);
  if (!cache) {
    cache = new Map();
    policyCaches.set(config, cache);
    knownCaches.add(cache);
  }
  return cache;
}

/**
 * Validate a password against the configured policy.
 * Throws `Errors.badRequest()` if the password does not meet requirements.
 */
export async function validatePassword(
  password: string,
  config: PasswordPolicyConfig = {},
  observer?: PasswordPolicyObserver,
): Promise<void> {
  const normalizedPassword = normalizePasswordInput(password);
  const minLength = config.minLength ?? DEFAULT_MIN_LENGTH;
  const maxLength = config.maxLength ?? DEFAULT_MAX_LENGTH;
  if (!Number.isInteger(minLength) || minLength <= 0)
    throw Errors.badRequest('passwordPolicy.minLength must be a positive integer');
  if (!Number.isInteger(maxLength) || maxLength <= 0)
    throw Errors.badRequest('passwordPolicy.maxLength must be a positive integer');
  if (minLength > maxLength)
    throw Errors.badRequest('passwordPolicy.minLength cannot exceed maxLength');

  if (normalizedPassword.length < minLength) {
    throw Errors.badRequest(`Password must be at least ${minLength} characters`);
  }

  if (normalizedPassword.length > maxLength) {
    throw Errors.badRequest(`Password must be at most ${maxLength} characters`);
  }

  if (config.checkBreached) {
    const breached = await isPasswordBreached(normalizedPassword, {
      cacheTtlMs: config.breachedCacheTtlMs,
      cacheMaxEntries: config.breachedCacheMaxEntries,
      failureMode: config.breachedFailureMode,
      observer,
      cache: cacheForPolicy(config),
    });
    if (breached) {
      throw Errors.badRequest('This password has appeared in a data breach and cannot be used');
    }
  }
}

function rememberRange(cache: HibpCache, prefix: string, data: string, expiresAt: number, maxEntries: number): void {
  if (maxEntries <= 0)
    return;

  cache.delete(prefix);
  while (cache.size >= maxEntries) {
    const oldest = cache.keys().next().value as string | undefined;
    if (oldest === undefined)
      break;
    cache.delete(oldest);
  }
  cache.set(prefix, { data, expiresAt });
}

function handleDegradedCheck(
  options: PasswordBreachCheckOptions,
  details: { status?: number; error?: unknown },
): false {
  const failureMode = options.failureMode ?? 'open';
  options.observer?.({ failureMode, ...details });

  // Direct callers may not provide an observer. Keep degraded controls visible
  // rather than silently failing open/closed.
  if (!options.observer) {
    const reason = details.status !== undefined
      ? `HTTP ${details.status}`
      : details.error instanceof Error ? details.error.message : String(details.error);
    console.warn(`[fortress/password-policy] HIBP range API unavailable (${reason}); failing ${failureMode}.`);
  }

  if (failureMode === 'closed') {
    throw Errors.serviceUnavailable('Password breach check unavailable', { cause: details.error });
  }
  return false;
}

/**
 * Check if a password appears in the Have I Been Pwned breached password database
 * using the k-anonymity API (only the first 5 characters of the SHA-1 hash are sent).
 */
export async function isPasswordBreached(
  password: string,
  options: PasswordBreachCheckOptions = {},
): Promise<boolean> {
  const cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const cacheMaxEntries = options.cacheMaxEntries ?? DEFAULT_CACHE_MAX_ENTRIES;
  const hibpCache = options.cache ?? directHibpCache;
  if (!Number.isFinite(cacheTtlMs) || cacheTtlMs < 0)
    throw Errors.badRequest('passwordPolicy.breachedCacheTtlMs must be a non-negative number');
  if (!Number.isInteger(cacheMaxEntries) || cacheMaxEntries < 0)
    throw Errors.badRequest('passwordPolicy.breachedCacheMaxEntries must be a non-negative integer');
  if (options.failureMode !== undefined && options.failureMode !== 'open' && options.failureMode !== 'closed')
    throw Errors.badRequest('passwordPolicy.breachedFailureMode must be \'open\' or \'closed\'');

  // SHA-1 hash of the canonical password form.
  const encoded = new TextEncoder().encode(normalizePasswordInput(password));
  const hashBuffer = await crypto.subtle.digest('SHA-1', encoded);
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  // Enforce the active caller's bound before reading as well as writing. This
  // makes `0` a real cache bypass and lets deployments safely lower a bound.
  while (hibpCache.size > cacheMaxEntries) {
    const oldest = hibpCache.keys().next().value as string | undefined;
    if (oldest === undefined)
      break;
    hibpCache.delete(oldest);
  }

  const cached = cacheMaxEntries > 0 ? hibpCache.get(prefix) : undefined;
  if (cached && cached.expiresAt > Date.now()) {
    // Touch the entry so Map insertion order remains LRU order.
    hibpCache.delete(prefix);
    hibpCache.set(prefix, cached);
    return cached.data.includes(suffix);
  }
  if (cached)
    hibpCache.delete(prefix);

  let response: Response;
  try {
    response = await hibpOutboundClient.get(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' },
    });
  }
  catch (error) {
    return handleDegradedCheck(options, { error });
  }

  if (!response.ok)
    return handleDegradedCheck(options, { status: response.status });

  try {
    const data = await response.text();
    rememberRange(hibpCache, prefix, data, Date.now() + cacheTtlMs, cacheMaxEntries);
    return data.includes(suffix);
  }
  catch (error) {
    return handleDegradedCheck(options, { error });
  }
}

/** Clear the HIBP cache. Useful for testing. */
export function clearHibpCache(): void {
  for (const cache of knownCaches)
    cache.clear();
}
