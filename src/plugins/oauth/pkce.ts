/**
 * PKCE (Proof Key for Code Exchange) S256 implementation.
 * Used by the OAuth plugin to secure authorization code flows.
 */

import { timingSafeEqualHex } from '../../core/auth/timing-safe';

/**
 * RFC 7636 §4.1: code_verifier = high-entropy cryptographic random
 * STRING using the unreserved characters [A-Z]/[a-z]/[0-9]/"-"/"."/"_"/"~"
 * with a minimum length of 43 characters and a maximum length of 128.
 */
const CODE_VERIFIER_PATTERN = /^[\w.~-]{43,128}$/;

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

/**
 * Verify a code verifier against a stored S256 challenge.
 *
 * Validates the verifier against RFC 7636 §4.1 (43-128 chars, unreserved
 * URL-safe character set) before computing the challenge — a verifier that
 * fails this check is invalid by definition and must not unlock a code.
 *
 * Uses {@link timingSafeEqualHex} for the final comparison so a remote
 * attacker can't differentiate "wrong verifier" from "wrong verifier with
 * matching prefix" via response timing.
 */
export async function verifyCodeChallenge(
  verifier: string,
  challenge: string,
  method: string,
): Promise<boolean> {
  if (method !== 'S256')
    return false;

  if (!CODE_VERIFIER_PATTERN.test(verifier))
    return false;

  const computed = await generateCodeChallenge(verifier);
  // base64url is a fixed alphabet; `timingSafeEqualHex` works for any
  // single-byte-per-char ASCII string of equal length.
  return timingSafeEqualHex(computed, challenge);
}
