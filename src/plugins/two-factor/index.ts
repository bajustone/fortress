/**
 * Two-factor authentication plugin for fortress.
 *
 * Adds TOTP enrolment and verification, hashed backup codes, and trusted
 * device enrolment so users can opt out of 2FA prompts on familiar devices.
 * Exposes setup, verify, and disable methods on the fortress instance.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressPlugin } from '../../core/plugin';
import type { AuthResult, FortressUser, RequestMeta } from '../../core/types';
import { generateRefreshToken, hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';
import { definePlugin } from '../../core/plugin';

export interface TwoFactorConfig {
  /**
   * 32-byte AES-256-GCM key used to encrypt TOTP seeds at rest. Accepts
   * base64/base64url, 64-character hex, or exactly 32 UTF-8 bytes. Keep this
   * key stable and outside the database; changing it requires re-enrolment.
   */
  secretEncryptionKey: string;
  totp?: {
    /** Issuer name shown in authenticator apps (default: 'Fortress') */
    issuer?: string;
    /** TOTP period in seconds (default: 30) */
    period?: number;
    /** Number of digits (default: 6) */
    digits?: number;
  };
  backupCodes?: {
    /** Number of backup codes to generate (default: 10) */
    count?: number;
  };
  /** Days to trust a device after explicit remember-device opt-in (default: 30) */
  trustedDeviceDays?: number;
  /** Maximum rejected continuation proofs before invalidation (default: 5). */
  maxAttempts?: number;
  /** Minimum delay between rejected proofs for an account (default: 1 second). */
  failedAttemptCooldownSeconds?: number;
}

interface TwoFactorSecretRecord {
  id: string;
  userId: string;
  secret: string;
  isEnabled: boolean;
  createdAt: Date;
  lastUsedCounter: number | null;
}

interface BackupCodeRecord {
  id: string;
  userId: string;
  codeHash: string;
  isUsed: boolean;
}

interface TrustedDeviceRecord {
  id: string;
  userId: string;
  /** Hash of the server-issued secret; the raw secret is never persisted. */
  deviceHash: string;
  expiresAt: Date;
  lastUsedAt: Date;
}

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();
const HEX_32_BYTE_KEY = /^[0-9a-f]{64}$/i;

function decodeEncryptionKey(value: string): Uint8Array {
  const trimmed = value.trim();
  if (HEX_32_BYTE_KEY.test(trimmed))
    return new Uint8Array(trimmed.match(/.{2}/g)!.map(byte => Number.parseInt(byte, 16)));
  try {
    const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const raw = atob(padded);
    const decoded = Uint8Array.from(raw, char => char.charCodeAt(0));
    if (decoded.length === 32)
      return decoded;
  }
  catch {
    // Fall through to exact-length UTF-8 key material.
  }
  return ENCODER.encode(value);
}

function base64UrlEncode(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
  return Uint8Array.from(raw, char => char.charCodeAt(0));
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

async function encryptSecret(keyPromise: Promise<CryptoKey>, secret: string, userId: string): Promise<string> {
  const key = await keyPromise;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: ENCODER.encode(userId) },
    key,
    ENCODER.encode(secret),
  ));
  return `v1.${base64UrlEncode(iv)}.${base64UrlEncode(ciphertext)}`;
}

async function decryptSecret(keyPromise: Promise<CryptoKey>, encrypted: string, userId: string): Promise<string> {
  const [version, encodedIv, encodedCiphertext] = encrypted.split('.');
  if (version !== 'v1' || !encodedIv || !encodedCiphertext)
    throw Errors.unauthorized('Two-factor enrolment uses an unsupported secret format; re-enrolment is required');
  try {
    const key = await keyPromise;
    const iv = base64UrlDecode(encodedIv);
    const ciphertext = base64UrlDecode(encodedCiphertext);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: ENCODER.encode(userId) },
      key,
      toArrayBuffer(ciphertext),
    );
    return DECODER.decode(plaintext);
  }
  catch {
    throw Errors.unauthorized('Unable to decrypt two-factor secret');
  }
}

// --- TOTP Implementation (RFC 6238 / RFC 4226) ---

function generateSecret(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

function base32Encode(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let result = '';

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 31];
  }

  return result;
}

const BASE32_PADDING = /=+$/;

function base32Decode(encoded: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleanInput = encoded.replace(BASE32_PADDING, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of cleanInput) {
    const idx = alphabet.indexOf(char);
    if (idx === -1)
      continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xFF);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

/**
 * Generate a TOTP code from a base32 secret. Re-exported from this module
 * for testing — normal callers should use the plugin methods instead.
 */
async function generateTOTPForCounter(secret: string, digits: number, counter: number): Promise<string> {
  const counterBytes = new ArrayBuffer(8);
  const view = new DataView(counterBytes);
  view.setBigUint64(0, BigInt(counter));

  const keyBytes = base32Decode(secret);
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );

  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = hmac.at(-1)! & 0x0F;
  const code = (
    ((hmac[offset] & 0x7F) << 24)
    | ((hmac[offset + 1] & 0xFF) << 16)
    | ((hmac[offset + 2] & 0xFF) << 8)
    | (hmac[offset + 3] & 0xFF)
  ) % (10 ** digits);

  return String(code).padStart(digits, '0');
}

async function generateTOTP(secret: string, period: number, digits: number, timeOffset = 0): Promise<string> {
  const counter = Math.floor((Date.now() / 1000 + timeOffset) / period);
  return generateTOTPForCounter(secret, digits, counter);
}

/**
 * Verify a TOTP code against a base32 secret, allowing ±1 time window for
 * clock drift. Re-exported from this module for testing — normal callers
 * should use the plugin methods instead.
 */
async function verifyTOTPWithCounter(secret: string, code: string, period: number, digits: number): Promise<number | null> {
  const currentCounter = Math.floor(Date.now() / 1000 / period);
  // Check current and adjacent time windows (±1) to handle clock drift
  for (const counter of [currentCounter, currentCounter - 1, currentCounter + 1]) {
    const expected = await generateTOTPForCounter(secret, digits, counter);
    if (expected === code)
      return counter;
  }
  return null;
}

async function verifyTOTP(secret: string, code: string, period: number, digits: number): Promise<boolean> {
  return (await verifyTOTPWithCounter(secret, code, period, digits)) !== null;
}

function buildOtpauthUrl(secret: string, issuer: string, email: string, period: number, digits: number): string {
  const label = `${issuer}:${email}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(digits),
    period: String(period),
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

async function generateBackupCodes(count: number): Promise<{ raw: string[]; hashes: string[] }> {
  const raw: string[] = [];
  const hashes: string[] = [];

  for (let i = 0; i < count; i++) {
    // Recovery credentials need offline-strength entropy even when endpoint
    // throttling is misconfigured. 16 random bytes = 128 bits.
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    const code = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    raw.push(code);
    hashes.push(await hashToken(code));
  }

  return { raw, hashes };
}

export interface TwoFactorMethods {
  enable: (userId: string) => Promise<{ secret: string; otpauthUrl: string; backupCodes: string[] }>;
  confirmSetup: (userId: string, code: string, meta?: RequestMeta) => Promise<{ verified: true; trustedDeviceToken?: string }>;
  verify: (continuationToken: string, code: string, meta?: RequestMeta) => Promise<AuthResult>;
  disable: (userId: string) => Promise<void>;
}
/**
 * Two-factor authentication plugin factory. Returns a {@link FortressPlugin}
 * that adds TOTP enrolment and verification, hashed backup codes, and
 * trusted-device opt-out for the sign-in flow.
 */
// eslint-disable-next-line ts/explicit-function-return-type -- definePlugin preserves the exact public contract
export function twoFactor(config: TwoFactorConfig) {
  if (!config?.secretEncryptionKey)
    throw Errors.badRequest('twoFactor requires secretEncryptionKey');
  const keyBytes = decodeEncryptionKey(config.secretEncryptionKey);
  if (keyBytes.length !== 32)
    throw Errors.badRequest('twoFactor secretEncryptionKey must decode to exactly 32 bytes for AES-256-GCM');
  const keyBuffer = keyBytes.buffer.slice(keyBytes.byteOffset, keyBytes.byteOffset + keyBytes.byteLength) as ArrayBuffer;
  const encryptionKey = crypto.subtle.importKey('raw', keyBuffer, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const issuer = config.totp?.issuer ?? 'Fortress';
  const period = config.totp?.period ?? 30;
  const digits = config.totp?.digits ?? 6;
  const backupCodeCount = config.backupCodes?.count ?? 10;
  const trustedDeviceDays = config.trustedDeviceDays ?? 30;
  const maxAttempts = config.maxAttempts ?? 5;
  const failedAttemptCooldownSeconds = config.failedAttemptCooldownSeconds ?? 1;

  async function verifyCode(
    db: DatabaseAdapter,
    userId: string,
    code: string,
    meta?: RequestMeta,
  ): Promise<string | undefined> {
    const secretRecord = await db.findOne<TwoFactorSecretRecord>({
      model: 'two_factor_secret',
      where: [{ field: 'userId', operator: '=', value: userId }],
    });
    if (!secretRecord)
      throw Errors.badRequest('Two-factor authentication is not set up');

    const secret = await decryptSecret(encryptionKey, secretRecord.secret, userId);
    const matchedCounter = await verifyTOTPWithCounter(secret, code, period, digits);
    if (matchedCounter !== null) {
      const previousCounter = secretRecord.lastUsedCounter;
      if (previousCounter !== null && matchedCounter <= previousCounter)
        throw Errors.unauthorized('Two-factor code has already been used');

      const claimed = await db.update<TwoFactorSecretRecord>({
        model: 'two_factor_secret',
        where: [
          { field: 'id', operator: '=', value: secretRecord.id },
          previousCounter === null
            ? { field: 'lastUsedCounter', operator: 'isNull', value: null }
            : { field: 'lastUsedCounter', operator: '=', value: previousCounter },
        ],
        data: { isEnabled: true, lastUsedCounter: matchedCounter },
      });
      if (!claimed)
        throw Errors.unauthorized('Two-factor code has already been used');

      if (meta?.rememberDevice) {
        const trusted = await generateRefreshToken();
        const expiresAt = new Date(Date.now() + trustedDeviceDays * 24 * 60 * 60 * 1000);
        await db.create({
          model: 'trusted_device',
          data: { userId, deviceHash: trusted.hash, expiresAt, lastUsedAt: new Date() },
        });
        return trusted.raw;
      }
      return undefined;
    }

    const backupCodes = await db.findMany<BackupCodeRecord>({
      model: 'backup_code',
      where: [
        { field: 'userId', operator: '=', value: userId },
        { field: 'isUsed', operator: '=', value: false },
      ],
    });
    const codeHash = await hashToken(code);
    const matchingCode = backupCodes.find(backupCode => backupCode.codeHash === codeHash);
    if (!matchingCode)
      throw Errors.unauthorized('Invalid two-factor code');

    const claimed = await db.update({
      model: 'backup_code',
      where: [
        { field: 'id', operator: '=', value: matchingCode.id },
        { field: 'isUsed', operator: '=', value: false },
      ],
      data: { isUsed: true },
    });
    if (!claimed)
      throw Errors.unauthorized('Invalid two-factor code');

    if (!secretRecord.isEnabled) {
      await db.update({
        model: 'two_factor_secret',
        where: [{ field: 'id', operator: '=', value: secretRecord.id }],
        data: { isEnabled: true },
      });
    }
    if (meta?.rememberDevice) {
      const trusted = await generateRefreshToken();
      const expiresAt = new Date(Date.now() + trustedDeviceDays * 24 * 60 * 60 * 1000);
      await db.create({
        model: 'trusted_device',
        data: { userId, deviceHash: trusted.hash, expiresAt, lastUsedAt: new Date() },
      });
      return trusted.raw;
    }
    return undefined;
  }

  return definePlugin({
    name: 'two-factor',

    models: [
      {
        name: 'two_factor_secret',
        fields: {
          id: { type: 'number', required: true },
          userId: { type: 'number', required: true, unique: true, references: { model: 'user', field: 'id' } },
          secret: { type: 'string', required: true },
          isEnabled: { type: 'boolean', required: true },
          lastUsedCounter: { type: 'number' },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        name: 'backup_code',
        fields: {
          id: { type: 'number', required: true },
          userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
          codeHash: { type: 'string', required: true },
          isUsed: { type: 'boolean', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        name: 'trusted_device',
        fields: {
          id: { type: 'number', required: true },
          userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
          deviceHash: { type: 'string', required: true },
          expiresAt: { type: 'date', required: true },
          lastUsedAt: { type: 'date', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
    ],

    hooks: {
      postAuthGate: {
        reason: 'two-factor',
        maxAttempts,
        cooldownSeconds: failedAttemptCooldownSeconds,
        async evaluate(ctx) {
          const secret = await ctx.db.findOne<TwoFactorSecretRecord>({
            model: 'two_factor_secret',
            where: [
              { field: 'userId', operator: '=', value: ctx.user.id },
              { field: 'isEnabled', operator: '=', value: true },
            ],
          });
          if (!secret)
            return;

          if (ctx.meta?.trustedDeviceToken) {
            const deviceHash = await hashToken(ctx.meta.trustedDeviceToken);
            const trusted = await ctx.db.findOne<TrustedDeviceRecord>({
              model: 'trusted_device',
              where: [
                { field: 'userId', operator: '=', value: ctx.user.id },
                { field: 'deviceHash', operator: '=', value: deviceHash },
              ],
            });
            if (trusted && trusted.expiresAt > new Date()) {
              await ctx.db.update({
                model: 'trusted_device',
                where: [{ field: 'id', operator: '=', value: trusted.id }],
                data: { lastUsedAt: new Date() },
              });
              return;
            }
          }

          return { pluginData: { requires2FA: true } };
        },
        async verify(ctx, completion) {
          if (typeof completion !== 'string')
            throw Errors.unauthorized('Invalid two-factor code');
          const trustedDeviceToken = await verifyCode(ctx.db, ctx.user.id, completion, ctx.meta);
          return trustedDeviceToken ? { trustedDeviceToken } : undefined;
        },
      },
    },

    methods: (ctx) => {
      // Auth service reference for issuing tokens after 2FA verification
      // We need access to signToken and refresh token creation — reuse the fortress instance
      return {
        async enable(userId: string): Promise<{
          secret: string;
          otpauthUrl: string;
          backupCodes: string[];
        }> {
          const user = await ctx.db.findOne<FortressUser>({
            model: 'user',
            where: [{ field: 'id', operator: '=', value: userId }],
          });

          if (!user)
            throw Errors.notFound('User not found');

          // Check if already has a secret
          const existing = await ctx.db.findOne<TwoFactorSecretRecord>({
            model: 'two_factor_secret',
            where: [{ field: 'userId', operator: '=', value: userId }],
          });

          if (existing?.isEnabled)
            throw Errors.badRequest('Two-factor authentication is already enabled');

          // Remove any previous unenabled setup
          if (existing) {
            await ctx.db.delete({
              model: 'two_factor_secret',
              where: [{ field: 'userId', operator: '=', value: userId }],
            });
            await ctx.db.delete({
              model: 'backup_code',
              where: [{ field: 'userId', operator: '=', value: userId }],
            });
          }

          const secret = generateSecret();
          const otpauthUrl = buildOtpauthUrl(secret, issuer, user.email, period, digits);

          // Generate backup codes
          const { raw: backupCodesRaw, hashes } = await generateBackupCodes(backupCodeCount);

          // Store only an authenticated ciphertext; the raw TOTP seed is
          // returned once for authenticator enrolment and never persisted.
          const encryptedSecret = await encryptSecret(encryptionKey, secret, userId);
          await ctx.db.create({
            model: 'two_factor_secret',
            data: { userId, secret: encryptedSecret, isEnabled: false, lastUsedCounter: null },
          });

          // Store backup code hashes
          for (const hash of hashes) {
            await ctx.db.create({
              model: 'backup_code',
              data: { userId, codeHash: hash, isUsed: false },
            });
          }

          return { secret, otpauthUrl, backupCodes: backupCodesRaw };
        },

        async confirmSetup(userId: string, code: string, meta?: RequestMeta): Promise<{ verified: true; trustedDeviceToken?: string }> {
          const trustedDeviceToken = await verifyCode(ctx.db, userId, code, meta);
          return { verified: true, ...(trustedDeviceToken ? { trustedDeviceToken } : {}) };
        },

        async verify(continuationToken: string, code: string, meta?: RequestMeta): Promise<AuthResult> {
          if (!ctx.auth)
            throw Errors.badRequest('Auth service is unavailable');
          return ctx.auth.completePendingAuth(continuationToken, code, meta);
        },

        async disable(userId: string): Promise<void> {
          await ctx.db.delete({
            model: 'two_factor_secret',
            where: [{ field: 'userId', operator: '=', value: userId }],
          });
          await ctx.db.delete({
            model: 'backup_code',
            where: [{ field: 'userId', operator: '=', value: userId }],
          });
          await ctx.db.delete({
            model: 'trusted_device',
            where: [{ field: 'userId', operator: '=', value: userId }],
          });
        },
      };
    },
  } satisfies FortressPlugin<'two-factor', TwoFactorMethods>);
}

// Export TOTP utilities for testing
export { generateTOTP, verifyTOTP };
