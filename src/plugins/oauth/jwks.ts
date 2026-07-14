/**
 * RS256 signing-key management for the OAuth plugin's id_token issuance.
 *
 * One active key at a time, persisted in `oauth_signing_key` as a pair of
 * JWK JSON columns (public + private). The active key has `rotatedAt =
 * null`; rotated keys are kept for the JWKS-validation grace window so RPs
 * verifying older id_tokens still find the matching `kid`.
 *
 * The `kid` is the RFC 7638 SHA-256 thumbprint of the public JWK — globally
 * unique, deterministic, and useful for cross-checking by RPs.
 *
 * Why a plugin-local module? Fortress core's JWT module is an HS256-only
 * symmetric-secret signer for access tokens. OIDC id_tokens are RS256 so
 * RPs can verify against a public JWKS without needing the AS's secret;
 * those are different keys with different lifecycles. Keeping them
 * separated stops the JWKS endpoint from accidentally exposing core auth
 * material.
 *
 * @module
 */

import type { JWK } from 'jose';
import type { DatabaseAdapter } from '../../adapters/database';
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importJWK,

} from 'jose';

// jose v6 returns Web Crypto `CryptoKey` for asymmetric keys (and an opaque
// `KeyObject` on Node). The structural type below covers both — we only
// need to pass it back to jose.
type SigningKey = CryptoKey | { type: string };

/** Persisted signing-key row. Stores both public and private JWKs as JSON strings. */
export interface SigningKeyRecord {
  id: string;
  kid: string;
  alg: string;
  publicJwk: string;
  privateJwk: string;
  createdAt: Date;
  /** When non-null, this key is no longer used to mint new tokens; only kept for verification. */
  rotatedAt: Date | null;
}

/**
 * Active signing key resolved into a usable form. The id_token issuer needs
 * the private `KeyLike` to sign; the JWKS endpoint emits the public JWK
 * (with `kid` and `alg` annotations) verbatim.
 */
export interface ActiveSigningKey {
  kid: string;
  alg: 'RS256';
  privateKey: SigningKey;
  publicJwk: JWK & { kid: string; alg: 'RS256'; use: 'sig' };
}

/**
 * Get the current signing key, generating + persisting a fresh RS256
 * keypair if no active key exists. Idempotent: concurrent first calls may
 * race to create two keys, but at-most-once isn't required for correctness
 * — both rows would have valid material; the first one wins on subsequent
 * lookups.
 */
export async function getActiveSigningKey(db: DatabaseAdapter): Promise<ActiveSigningKey> {
  const existing = await db.findOne<SigningKeyRecord>({
    model: 'oauth_signing_key',
    where: [{ field: 'rotatedAt', operator: 'isNull', value: null }],
  });
  if (existing)
    return hydrate(existing);

  // No active key — generate a fresh RS256 keypair and persist.
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  publicJwk.kid = kid;
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';
  privateJwk.kid = kid;
  privateJwk.alg = 'RS256';

  await db.create<SigningKeyRecord>({
    model: 'oauth_signing_key',
    data: {
      kid,
      alg: 'RS256',
      publicJwk: JSON.stringify(publicJwk),
      privateJwk: JSON.stringify(privateJwk),
      rotatedAt: null,
    },
  });

  return {
    kid,
    alg: 'RS256',
    privateKey: privateKey as SigningKey,
    publicJwk: publicJwk as ActiveSigningKey['publicJwk'],
  };
}

/**
 * Return every signing key fortress will accept on token verification —
 * the active key plus any rotated keys still inside the grace window.
 *
 * The result is the JWKS body verbatim (`{ keys: [...] }`) for cache-able
 * shipping at `/oauth/.well-known/jwks.json`.
 */
export async function listJwks(db: DatabaseAdapter, graceSeconds = 3600): Promise<{ keys: JWK[] }> {
  // Fortress's adapter doesn't have a native "fetch all" — emulate via a
  // wide query and sort. Currently we only mint one key, so this stays
  // tiny.
  const all = await db.findMany<SigningKeyRecord>({
    model: 'oauth_signing_key',
    where: [],
  });
  const cutoff = Date.now() - Math.max(0, graceSeconds) * 1000;
  return {
    keys: all
      .filter(row => row.rotatedAt === null || new Date(row.rotatedAt).getTime() > cutoff)
      // Sort active first, then most-recently-rotated.
      .sort((a, b) => {
        if (a.rotatedAt === null && b.rotatedAt !== null)
          return -1;
        if (a.rotatedAt !== null && b.rotatedAt === null)
          return 1;
        return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      })
      .map(row => JSON.parse(row.publicJwk) as JWK),
  };
}

/** Rotate the active key and prune keys outside the verification grace window. */
export async function rotateSigningKey(db: DatabaseAdapter, graceSeconds = 3600): Promise<ActiveSigningKey> {
  return db.transaction(async (tx) => {
    if (tx.dialect === 'pg' && tx.rawQuery)
      await tx.rawQuery('SELECT pg_advisory_xact_lock(hashtext(?))', ['fortress-oauth-signing-key']);

    const now = new Date();
    const active = await tx.findOne<SigningKeyRecord>({
      model: 'oauth_signing_key',
      where: [{ field: 'rotatedAt', operator: 'isNull', value: null }],
    });
    if (active) {
      await tx.update({
        model: 'oauth_signing_key',
        where: [{ field: 'id', operator: '=', value: active.id }],
        data: { rotatedAt: now },
      });
    }

    const cutoff = new Date(now.getTime() - Math.max(0, graceSeconds) * 1000);
    const expired = await tx.findMany<SigningKeyRecord>({
      model: 'oauth_signing_key',
      where: [{ field: 'rotatedAt', operator: 'lt', value: cutoff }],
    });
    for (const key of expired) {
      await tx.delete({
        model: 'oauth_signing_key',
        where: [{ field: 'id', operator: '=', value: key.id }],
      });
    }

    return getActiveSigningKey(tx);
  });
}

async function hydrate(record: SigningKeyRecord): Promise<ActiveSigningKey> {
  const publicJwk = JSON.parse(record.publicJwk) as ActiveSigningKey['publicJwk'];
  const privateJwk = JSON.parse(record.privateJwk) as JWK;
  const privateKey = await importJWK(privateJwk, 'RS256');
  return {
    kid: record.kid,
    alg: 'RS256',
    privateKey: privateKey as SigningKey,
    publicJwk,
  };
}
