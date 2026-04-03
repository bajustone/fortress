import type { TokenClaims } from '../types';

import { jwtVerify, SignJWT } from 'jose';
import { Errors } from '../errors';

/**
 * Encode a secret string to Uint8Array for jose.
 */
function encodeSecret(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

/**
 * Normalize secret config to an array of encoded secrets.
 * First secret is used for signing, all are used for verification.
 */
function normalizeSecrets(secret: string | string[]): Uint8Array[] {
  const secrets = Array.isArray(secret) ? secret : [secret];
  return secrets.map(encodeSecret);
}

/**
 * Sign a JWT access token.
 */
export async function signAccessToken(
  claims: Omit<TokenClaims, 'iat' | 'exp'>,
  secret: string | string[],
  expiresInSeconds: number,
): Promise<string> {
  const [signingKey] = normalizeSecrets(secret);

  return new SignJWT({
    name: claims.name,
    groups: claims.groups,
    ...(claims.customClaims ?? {}),
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${expiresInSeconds}s`)
    .setIssuer(claims.iss)
    .setSubject(String(claims.sub))
    .sign(signingKey);
}

/**
 * Verify a JWT access token. Tries each secret in order for rotation support.
 */
export async function verifyAccessToken(
  token: string,
  secret: string | string[],
): Promise<TokenClaims> {
  const secrets = normalizeSecrets(secret);

  for (const key of secrets) {
    try {
      const { payload } = await jwtVerify(token, key);
      return {
        sub: Number(payload.sub),
        name: payload.name as string,
        groups: (payload.groups as string[]) ?? [],
        iss: payload.iss ?? '',
        iat: payload.iat ?? 0,
        exp: payload.exp ?? 0,
        customClaims: Object.fromEntries(
          Object.entries(payload).filter(
            ([k]) => !['sub', 'name', 'groups', 'iss', 'iat', 'exp'].includes(k),
          ),
        ),
      };
    }
    catch {
      continue;
    }
  }

  throw Errors.unauthorized('Invalid or expired token');
}
