/**
 * Refresh token utilities.
 * Tokens are 32 bytes of cryptographic randomness, base64url encoded.
 * Only the SHA256 hash is stored — the raw token is never persisted.
 */

/**
 * Generate a new refresh token and its SHA256 hash.
 */
export async function generateRefreshToken(): Promise<{ raw: string; hash: string }> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const raw = base64UrlEncode(bytes);
  const hash = await hashToken(raw);
  return { raw, hash };
}

/**
 * Generate a random token family ID for rotation tracking.
 */
export function generateTokenFamily(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * SHA256 hash a raw token. Used for storage and lookup.
 */
export async function hashToken(raw: string): Promise<string> {
  const data = new TextEncoder().encode(raw);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return hexEncode(new Uint8Array(hashBuffer));
}

function base64UrlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, b => String.fromCodePoint(b)).join('');
  return btoa(binString)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
