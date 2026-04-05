import type { FortressPlugin } from '../../core/plugin';
import type { RateLimitStore } from './memory-store';
import { Errors } from '../../core/errors';
import { createMemoryStore } from './memory-store';

export type { RateLimitStore } from './memory-store';

export interface RateLimitConfig {
  /** Rate limit for login attempts. */
  login?: {
    /** Max login attempts per IP within the window. Default: 10. */
    maxPerIp?: number;
    /** Max login attempts per account identifier within the window. Default: 5. */
    maxPerAccount?: number;
    /** Sliding window duration in seconds. Default: 900 (15 minutes). */
    windowSeconds?: number;
  };
  /** Rate limit for registration attempts. */
  register?: {
    /** Max registration attempts per IP within the window. Default: 3. */
    maxPerIp?: number;
    /** Sliding window duration in seconds. Default: 3600 (1 hour). */
    windowSeconds?: number;
  };
  /** Custom store for rate limit counters. Default: in-memory sliding window. */
  store?: RateLimitStore;
}

const DEFAULT_LOGIN = { maxPerIp: 10, maxPerAccount: 5, windowSeconds: 900 };
const DEFAULT_REGISTER = { maxPerIp: 3, windowSeconds: 3600 };

/**
 * Normalize an IPv6 address to its /64 prefix to prevent bypass via address rotation.
 * IPv4 addresses are returned as-is.
 */
function normalizeIp(ip: string | undefined): string {
  if (!ip)
    return 'unknown';

  // Handle IPv4-mapped IPv6 (::ffff:1.2.3.4)
  if (ip.startsWith('::ffff:'))
    return ip.slice(7);

  // IPv6: take first 4 groups (/64 prefix)
  if (ip.includes(':')) {
    const expanded = ip.split(':').slice(0, 4).join(':');
    return expanded;
  }

  // IPv4: use as-is
  return ip;
}

/**
 * Rate limiting plugin for Fortress.
 * Protects login and registration endpoints using a sliding window algorithm
 * with dual-key limiting (per-IP and per-account).
 */
export function rateLimit(config: RateLimitConfig = {}): FortressPlugin {
  const store = config.store ?? createMemoryStore();
  const loginConfig = { ...DEFAULT_LOGIN, ...config.login };
  const registerConfig = { ...DEFAULT_REGISTER, ...config.register };

  return {
    name: 'rate-limit',

    hooks: {
      async beforeLogin(ctx) {
        const ip = normalizeIp(ctx.meta?.ipAddress);
        const identifier = ctx.email;
        const windowMs = loginConfig.windowSeconds * 1000;

        // Check per-IP limit
        const ipResult = await store.increment(`login:ip:${ip}`, windowMs);
        if (ipResult.count > loginConfig.maxPerIp) {
          const retryAfter = Math.ceil((ipResult.resetAt - Date.now()) / 1000);
          throw Errors.rateLimited(Math.max(retryAfter, 1));
        }

        // Check per-account limit
        const accountResult = await store.increment(`login:account:${identifier}`, windowMs);
        if (accountResult.count > loginConfig.maxPerAccount) {
          const retryAfter = Math.ceil((accountResult.resetAt - Date.now()) / 1000);
          throw Errors.rateLimited(Math.max(retryAfter, 1));
        }
      },

      async beforeRegister(ctx) {
        const ip = normalizeIp(ctx.meta?.ipAddress);
        const windowMs = registerConfig.windowSeconds * 1000;

        const ipResult = await store.increment(`register:ip:${ip}`, windowMs);
        if (ipResult.count > registerConfig.maxPerIp) {
          const retryAfter = Math.ceil((ipResult.resetAt - Date.now()) / 1000);
          throw Errors.rateLimited(Math.max(retryAfter, 1));
        }
      },
    },
  };
}
