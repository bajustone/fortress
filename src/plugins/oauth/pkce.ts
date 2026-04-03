/**
 * PKCE (Proof Key for Code Exchange) S256 implementation.
 * Used by the OAuth plugin to secure authorization code flows.
 */

/** Generate a cryptographically random code verifier (43-128 chars, URL-safe) */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** Generate S256 code challenge from a code verifier */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/** Verify a code verifier against a stored S256 challenge */
export async function verifyCodeChallenge(
  verifier: string,
  challenge: string,
  method: string,
): Promise<boolean> {
  if (method !== 'S256')
    return false;

  const computed = await generateCodeChallenge(verifier);
  return computed === challenge;
}
