/**
 * Constant-time equality for secret-derived strings.
 *
 * `===` on two strings short-circuits at the first mismatched byte, which —
 * combined with a remote attacker's ability to time HTTP responses — leaks
 * one bit per request about how far into the secret the comparison got.
 * The standard mitigation is to compare every byte regardless of mismatch.
 *
 * Both arms of OAuth's hot paths (client-secret check, access-token /
 * authorization-code lookup) hash the inbound value with SHA-256 before
 * comparing, so both operands here are 64-character lowercase hex. The
 * length check is therefore a no-op in practice but preserved for safety.
 *
 * @see RFC 9700 §2.1.1, OWASP ASVS V2.4
 */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
