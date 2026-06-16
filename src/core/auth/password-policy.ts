import { Errors } from '../errors';
import { outboundClient } from '../http/outbound';
import { normalizePasswordInput } from './password';

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
// Tighter timeout than the default outbound budget: the breach check runs in
// the password-validation hot path and fails open, so a slow HIBP must not
// stall registration/login.
const HIBP_TIMEOUT_MS = 6_000;

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
  const normalizedPassword = normalizePasswordInput(password);
  const minLength = config.minLength ?? DEFAULT_MIN_LENGTH;
  const maxLength = config.maxLength ?? DEFAULT_MAX_LENGTH;

  if (normalizedPassword.length < minLength) {
    throw Errors.badRequest(`Password must be at least ${minLength} characters`);
  }

  if (normalizedPassword.length > maxLength) {
    throw Errors.badRequest(`Password must be at most ${maxLength} characters`);
  }

  if (config.checkBreached) {
    const breached = await isPasswordBreached(normalizedPassword, config.breachedCacheTtlMs);
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
  // SHA-1 hash of the canonical password form.
  const encoded = new TextEncoder().encode(normalizePasswordInput(password));
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

  // Fetch from HIBP API via the shared outbound client (adds a timeout —
  // native fetch has none). fetcher never throws on transport failure: a
  // network error / timeout resolves to a Response with `ok === false`, so the
  // single `!ok` branch fails open for both non-2xx and unreachable. The body
  // is the plaintext k-anonymity suffix list, so it is read as text, never
  // schema-parsed.
  try {
    const response = await outboundClient.get(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' },
      timeout: HIBP_TIMEOUT_MS,
    });

    if (!response.ok) {
      // Fail open on API errors / unreachable — don't block registration due to
      // HIBP downtime. L-tier: log so operators notice the control is down.
      // `status === 0` indicates a transport failure (timeout/network).
      console.warn(
        `[fortress/password-policy] HIBP range API unavailable (HTTP ${response.status}); failing open for this check.`,
      );
      return false;
    }

    const data = await response.text();

    // Cache the response
    hibpCache.set(prefix, { data, expiresAt: Date.now() + cacheTtlMs });

    return data.includes(suffix);
  }
  catch (err) {
    // Belt-and-suspenders: fetcher's contract makes transport rejections
    // surface as `!ok` above, but a body-read failure could still throw. Fail
    // open and log so operators notice the control is down.
    console.warn(
      `[fortress/password-policy] HIBP range API error (${(err as Error).message ?? err}); failing open for this check.`,
    );
    return false;
  }
}

/**
 * Clear the HIBP cache. Useful for testing.
 */
export function clearHibpCache(): void {
  hibpCache.clear();
}
