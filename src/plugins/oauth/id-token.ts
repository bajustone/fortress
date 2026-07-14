/**
 * OIDC Core 1.0 id_token issuer.
 *
 * Responsibilities:
 * - Build the standard claims (`iss`, `sub`, `aud`, `iat`, `exp`, plus
 *   conditional `nonce`, `auth_time`).
 * - Add scope-gated identity claims (`email`, `email_verified`, `name`,
 *   `preferred_username`) that match what the userinfo endpoint emits, so
 *   RPs that decode the id_token directly see the same view as RPs that
 *   call userinfo.
 * - Sign with the active RS256 key and tag the JWS header with `kid`.
 *
 * @module
 */

import type { FortressUser } from '../../core/types';
import type { ActiveSigningKey } from './jwks';
import { SignJWT } from 'jose';

/** Inputs to {@link issueIdToken}. All times are in seconds. */
export interface IdTokenParams {
  user: FortressUser;
  clientId: string;
  /** OIDC Core \u00a72: same value as the AS issuer URL in discovery. */
  issuerUrl: string;
  /** Lifetime in seconds (default 1h). */
  ttlSeconds?: number;
  /** Echoed verbatim if the authorize request supplied one (\u00a73.1.3.7). */
  nonce?: string;
  /**
   * Unix seconds when the user authenticated (\u00a72). Required when
   * `max_age` was used; harmless to always include.
   */
  authTimeSeconds: number;
  /** Space-separated scope; gates the identity claims. */
  scope: string | null;
  /** Pre-resolved active signing key from {@link getActiveSigningKey}. */
  signingKey: ActiveSigningKey;
}

/**
 * Build and sign an OIDC id_token. Returns the compact JWS string.
 *
 * Claim coverage (OIDC Core \u00a72 + \u00a75.1):
 * - `iss`, `sub`, `aud`, `iat`, `exp`, `auth_time` always
 * - `nonce` when supplied
 * - `email`, `email_verified` only when scope contains `email`
 * - `name`, `preferred_username` when scope contains `profile`
 * - `updated_at` always (mirrors userinfo)
 */
export async function issueIdToken(params: IdTokenParams): Promise<string> {
  const ttl = params.ttlSeconds ?? 3600;
  const now = Math.floor(Date.now() / 1000);
  const scopes = params.scope ? params.scope.split(' ').filter(Boolean) : [];
  const exposeEmail = scopes.includes('email');
  const exposeProfile = scopes.includes('profile');

  // Standard + scope-gated identity claims.
  const claims: Record<string, unknown> = {
    auth_time: params.authTimeSeconds,
  };
  if (params.nonce)
    claims.nonce = params.nonce;
  if (exposeEmail) {
    claims.email = params.user.email;
    if (typeof params.user.emailVerified === 'boolean')
      claims.email_verified = params.user.emailVerified;
  }
  if (exposeProfile) {
    claims.name = params.user.name;
    claims.preferred_username = params.user.email;
  }
  if (params.user.updatedAt) {
    claims.updated_at = Math.floor(new Date(params.user.updatedAt).getTime() / 1000);
  }

  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: params.signingKey.kid, typ: 'JWT' })
    .setIssuer(params.issuerUrl)
    .setSubject(String(params.user.id))
    .setAudience(params.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .sign(params.signingKey.privateKey);
}
