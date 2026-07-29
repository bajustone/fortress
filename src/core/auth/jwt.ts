/**
 * JWT signing and verification helpers built on `jose` (Web Crypto API).
 *
 * Provides {@link signAccessToken} and {@link verifyAccessToken} for short-lived
 * access tokens. Refresh tokens are handled separately in
 * `core/auth/refresh-token.ts`. Supports key rotation by accepting an array
 * of keys — the first is used to sign, all are accepted on verify.
 *
 * @module
 */

import type { JWTVerifyOptions } from 'jose';
import type { SubjectType, TokenClaims } from '../types';

import { jwtVerify, SignJWT } from 'jose';
import { Errors } from '../errors';

/**
 * Key material accepted by {@link signAccessToken} / {@link verifyAccessToken}.
 *
 * Today this is just an HS256 shared secret (string) or a rotation array of
 * shared secrets. The alias exists so the public signature is stable when we
 * expand to asymmetric algorithms (RS256 / EdDSA) and JWKS-backed verification.
 *
 * Expected expansion:
 *
 * ```ts
 * import type { CryptoKey, JWK, JWTVerifyGetKey, KeyObject } from 'jose';
 *
 * export type JwtStaticKey =
 *   | string        // HS* shared secret (utf-8)
 *   | Uint8Array    // HS* shared secret (raw bytes)
 *   | CryptoKey     // Web Crypto key (any alg)
 *   | KeyObject     // Node KeyObject (any alg)
 *   | JWK;          // JSON Web Key
 *
 * export type JwtKeyMaterial = JwtStaticKey | readonly JwtStaticKey[];
 *
 * // Verification additionally accepts a resolver (e.g. createRemoteJWKSet):
 * export type JwtVerifyKeyMaterial = JwtKeyMaterial | JWTVerifyGetKey;
 * ```
 *
 * Until then, the runtime helpers ({@link normalizeKeys}) only know how to
 * encode strings — widening the type without widening the helpers would be a
 * lie, so do both together.
 */
export type JwtKeyMaterial = string | string[];

/**
 * JWT claim names fortress controls and that must never be overridable by
 * caller-supplied `customClaims` or by plugin `enrichTokenClaims` output.
 *
 * Letting a caller set `act` would forge an impersonation marker; letting a
 * caller set `sub`/`iss`/`exp` would let them mint a token for any subject
 * or extend its lifetime. The denylist is enforced in {@link signAccessToken}
 * — extra claims are dropped (with a `warn` log in dev) before the safe
 * claims are spread.
 */
export const RESERVED_JWT_CLAIMS: ReadonlySet<string> = new Set([
  'sub',
  'iss',
  'iat',
  'exp',
  'nbf',
  'aud',
  'jti',
  'act',
  'groups',
  'subjectType',
  'name',
]);

export interface SignAccessTokenOptions {
  /** Audience to include in the JWT `aud` claim. Omitted when unset. */
  audience?: string | string[];
}

export interface VerifyAccessTokenOptions {
  /** Expected issuer. When set, jose also requires the `iss` claim to be present. */
  issuer?: string | string[];
  /** Expected audience. When set, jose also requires the `aud` claim to be present. */
  audience?: string | string[];
  /** Clock skew tolerance for `nbf`, `exp`, and max-token-age checks. */
  clockTolerance?: string | number;
  /** Additional claim names that must be present alongside Fortress's required access-token claims. */
  requiredClaims?: string[];
}

const REQUIRED_ACCESS_TOKEN_CLAIMS = ['sub', 'subjectType', 'name', 'groups', 'iss', 'iat', 'exp'] as const;
const SUBJECT_TYPES: readonly SubjectType[] = ['USER', 'GROUP', 'SERVICE_ACCOUNT'];

/**
 * Strip any reserved keys from a custom-claims object. In development we
 * log a warning so library users notice the collision; in production we
 * silently drop (the safe default — a misbehaving plugin shouldn't be able
 * to break token issuance).
 */
export function stripReservedClaims(
  claims: Record<string, unknown> | undefined,
  context: string,
): Record<string, unknown> {
  if (!claims)
    return {};
  const out: Record<string, unknown> = {};
  let stripped: string[] | undefined;
  for (const [key, value] of Object.entries(claims)) {
    if (RESERVED_JWT_CLAIMS.has(key)) {
      (stripped ??= []).push(key);
      continue;
    }
    out[key] = value;
  }
  if (stripped && typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production') {
    console.warn(`[fortress/jwt] dropping reserved claim(s) from ${context}: ${stripped.join(', ')}`);
  }
  return out;
}

/**
 * Encode a shared-secret string to Uint8Array for jose.
 */
function encodeSecret(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

/**
 * Normalize key material to an array of encoded keys.
 * First entry is used for signing, all are used for verification.
 */
function normalizeKeys(key: JwtKeyMaterial): [Uint8Array, ...Uint8Array[]] {
  const keys = Array.isArray(key) ? key : [key];
  const [primary, ...rotated] = keys;
  if (primary === undefined)
    throw new Error('JWT key material must contain at least one key');
  return [encodeSecret(primary), ...rotated.map(encodeSecret)];
}

/**
 * Sign a JWT access token.
 */
export async function signAccessToken(
  claims: Omit<TokenClaims, 'iat' | 'exp' | 'aud'>,
  key: JwtKeyMaterial,
  expiresInSeconds: number,
  options?: SignAccessTokenOptions,
): Promise<string> {
  const [signingKey] = normalizeKeys(key);

  // Strip reserved claim names from customClaims before spreading — a caller
  // (or a plugin contributing via enrichTokenClaims) MUST NOT be able to
  // overwrite `act`, `sub`, `groups`, etc. (See RESERVED_JWT_CLAIMS.)
  const safeCustom = stripReservedClaims(claims.customClaims, 'signAccessToken.customClaims');

  let jwt = new SignJWT({
    name: claims.name,
    subjectType: claims.subjectType,
    groups: claims.groups,
    ...(claims.act ? { act: claims.act } : {}),
    ...safeCustom,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${expiresInSeconds}s`)
    .setIssuer(claims.iss);
  if (options?.audience !== undefined)
    jwt = jwt.setAudience(options.audience);
  return jwt.setSubject(claims.sub).sign(signingKey);
}

/**
 * Verify a JWT access token. Tries each key in order for rotation support.
 *
 * Pins `alg: HS256` and (when supplied) the expected `issuer`. jose already
 * rejects `alg: none` by default; the explicit allowlist is defense in
 * depth against future jose behavioural drift and against confused-deputy
 * attacks if anyone later adds asymmetric key support.
 */
export async function verifyAccessToken(
  token: string,
  key: JwtKeyMaterial,
  options?: VerifyAccessTokenOptions,
): Promise<TokenClaims> {
  const keys = normalizeKeys(key);
  const requiredClaims = [...new Set([...REQUIRED_ACCESS_TOKEN_CLAIMS, ...(options?.requiredClaims ?? [])])];
  const verifyOptions: JWTVerifyOptions = { algorithms: ['HS256'], requiredClaims };
  if (options?.issuer)
    verifyOptions.issuer = options.issuer;
  if (options?.audience)
    verifyOptions.audience = options.audience;
  if (options?.clockTolerance !== undefined)
    verifyOptions.clockTolerance = options.clockTolerance;

  for (const candidate of keys) {
    try {
      const { payload } = await jwtVerify(token, candidate, verifyOptions);
      const subjectType = payload.subjectType;
      const groups = payload.groups;
      const name = payload.name;
      const issuer = payload.iss;
      const audience = payload.aud;
      const issuedAt = payload.iat;
      const expiresAt = payload.exp;

      if (typeof payload.sub !== 'string' || payload.sub.length === 0)
        throw new Error('Invalid sub claim');
      if (typeof subjectType !== 'string' || !SUBJECT_TYPES.includes(subjectType as SubjectType))
        throw new Error('Invalid subjectType claim');
      if (typeof name !== 'string')
        throw new Error('Invalid name claim');
      if (!Array.isArray(groups) || !groups.every(group => typeof group === 'string'))
        throw new Error('Invalid groups claim');
      if (typeof issuer !== 'string' || issuer.length === 0)
        throw new Error('Invalid iss claim');
      if (audience !== undefined && (!Array.isArray(audience) || !audience.every(value => typeof value === 'string')) && typeof audience !== 'string')
        throw new Error('Invalid aud claim');
      if (typeof issuedAt !== 'number')
        throw new Error('Invalid iat claim');
      if (typeof expiresAt !== 'number')
        throw new Error('Invalid exp claim');

      return {
        sub: payload.sub,
        subjectType: subjectType as SubjectType,
        name,
        groups,
        iss: issuer,
        ...(audience !== undefined ? { aud: audience } : {}),
        iat: issuedAt,
        exp: expiresAt,
        act: payload.act as { sub: string; subjectType?: SubjectType } | undefined,
        customClaims: Object.fromEntries(
          Object.entries(payload).filter(([k]) => !RESERVED_JWT_CLAIMS.has(k)),
        ),
      };
    }
    catch {
      continue;
    }
  }

  throw Errors.unauthorized('Invalid or expired token');
}
