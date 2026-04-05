import { Errors } from '../errors';

export interface PasswordPolicyConfig {
  /** Minimum password length. Default: 8 (NIST 800-63B). */
  minLength?: number;
  /** Maximum password length. Default: 128 (NIST 800-63B). */
  maxLength?: number;
  /** Check password against HIBP breached password database via k-anonymity API. Default: false. */
  checkBreached?: boolean;
  /** Cache TTL for HIBP range responses in milliseconds. Default: 86400000 (24h). */
  breachedCacheTtlMs?: number;
}

const DEFAULT_MIN_LENGTH = 8;
const DEFAULT_MAX_LENGTH = 128;
const DEFAULT_CACHE_TTL_MS = 86_400_000; // 24 hours

// Module-level cache for HIBP range responses (keyed by 5-char prefix)
const hibpCache = new Map<string, { data: string; expiresAt: number }>();

/**
 * Validate a password against the configured policy.
 * Throws `Errors.badRequest()` if the password does not meet requirements.
 */
export async function validatePassword(
  password: string,
  config: PasswordPolicyConfig = {},
): Promise<void> {
  const minLength = config.minLength ?? DEFAULT_MIN_LENGTH;
  const maxLength = config.maxLength ?? DEFAULT_MAX_LENGTH;

  if (password.length < minLength) {
    throw Errors.badRequest(`Password must be at least ${minLength} characters`);
  }

  if (password.length > maxLength) {
    throw Errors.badRequest(`Password must be at most ${maxLength} characters`);
  }

  if (config.checkBreached) {
    const breached = await isPasswordBreached(password, config.breachedCacheTtlMs);
    if (breached) {
      throw Errors.badRequest('This password has appeared in a data breach and cannot be used');
    }
  }
}

/**
 * Check if a password appears in the Have I Been Pwned breached password database
 * using the k-anonymity API (only the first 5 characters of the SHA-1 hash are sent).
 */
export async function isPasswordBreached(
  password: string,
  cacheTtlMs: number = DEFAULT_CACHE_TTL_MS,
): Promise<boolean> {
  // SHA-1 hash of the password
  const encoded = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', encoded);
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  // Check cache
  const cached = hibpCache.get(prefix);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data.includes(suffix);
  }

  // Fetch from HIBP API
  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' },
    });

    if (!response.ok) {
      // Fail open on API errors — don't block registration due to HIBP downtime
      return false;
    }

    const data = await response.text();

    // Cache the response
    hibpCache.set(prefix, { data, expiresAt: Date.now() + cacheTtlMs });

    return data.includes(suffix);
  }
  catch {
    // Fail open on network errors
    return false;
  }
}

/**
 * Clear the HIBP cache. Useful for testing.
 */
export function clearHibpCache(): void {
  hibpCache.clear();
}
