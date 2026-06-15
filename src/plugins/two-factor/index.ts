/**
 * Two-factor authentication plugin for fortress.
 *
 * Adds TOTP enrolment and verification, hashed backup codes, and trusted
 * device enrolment so users can opt out of 2FA prompts on familiar devices.
 * Exposes setup, verify, and disable methods on the fortress instance.
 *
 * @module
 */

import type { FortressPlugin } from '../../core/plugin';
import type { FortressUser, RequestMeta } from '../../core/types';
import { hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';

export interface TwoFactorConfig {
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
  /** Days to trust a device after successful 2FA (default: 30) */
  trustedDeviceDays?: number;
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
  deviceHash: string;
  expiresAt: Date;
  lastUsedAt: Date;
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
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    const code = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    raw.push(code);
    hashes.push(await hashToken(code));
  }

  return { raw, hashes };
}

export interface TwoFactorMethods {
  enable: (userId: string) => Promise<{ secret: string; otpauthUrl: string; backupCodes: string[] }>;
  verify: (userId: string, code: string, meta?: RequestMeta) => Promise<{ verified: boolean }>;
  disable: (userId: string) => Promise<void>;
}
/**
 * Two-factor authentication plugin factory. Returns a {@link FortressPlugin}
 * that adds TOTP enrolment and verification, hashed backup codes, and
 * trusted-device opt-out for the sign-in flow.
 */
export function twoFactor(config: TwoFactorConfig = {}): FortressPlugin & { readonly name: 'two-factor' } {
  const issuer = config.totp?.issuer ?? 'Fortress';
  const period = config.totp?.period ?? 30;
  const digits = config.totp?.digits ?? 6;
  const backupCodeCount = config.backupCodes?.count ?? 10;
  const trustedDeviceDays = config.trustedDeviceDays ?? 30;

  return {
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
      async afterLogin(ctx, result) {
        if (!result.user)
          return result;

        const secret = await ctx.db.findOne<TwoFactorSecretRecord>({
          model: 'two_factor_secret',
          where: [
            { field: 'userId', operator: '=', value: result.user.id },
            { field: 'isEnabled', operator: '=', value: true },
          ],
        });

        if (!secret)
          return result;

        // Check trusted device
        if (ctx.meta?.userAgent) {
          const deviceHash = await hashToken(`${result.user.id}:${ctx.meta.userAgent}`);
          const trusted = await ctx.db.findOne<TrustedDeviceRecord>({
            model: 'trusted_device',
            where: [
              { field: 'userId', operator: '=', value: result.user.id },
              { field: 'deviceHash', operator: '=', value: deviceHash },
            ],
          });

          if (trusted && trusted.expiresAt > new Date()) {
            // Device is trusted — update lastUsedAt and allow login
            await ctx.db.update({
              model: 'trusted_device',
              where: [{ field: 'id', operator: '=', value: trusted.id }],
              data: { lastUsedAt: new Date() },
            });
            return result;
          }
        }

        // 2FA required — return partial response without tokens
        return {
          status: 'pending' as const,
          user: result.user,
          accessToken: null,
          refreshToken: null,
          pluginData: { requires2FA: true },
        };
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

          // Store secret (not yet enabled — enable after first verify)
          await ctx.db.create({
            model: 'two_factor_secret',
            data: { userId, secret, isEnabled: false, lastUsedCounter: null },
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

        async verify(userId: string, code: string, meta?: RequestMeta): Promise<{ verified: boolean }> {
          const secretRecord = await ctx.db.findOne<TwoFactorSecretRecord>({
            model: 'two_factor_secret',
            where: [{ field: 'userId', operator: '=', value: userId }],
          });

          if (!secretRecord)
            throw Errors.badRequest('Two-factor authentication is not set up');

          // Try TOTP verification. A valid counter can be used only once;
          // the conditional update makes replay rejection atomic.
          const matchedCounter = await verifyTOTPWithCounter(secretRecord.secret, code, period, digits);

          if (matchedCounter !== null) {
            const previousCounter = secretRecord.lastUsedCounter;
            if (previousCounter !== null && matchedCounter <= previousCounter)
              throw Errors.unauthorized('Two-factor code has already been used');

            const claimed = await ctx.db.update<TwoFactorSecretRecord>({
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

            // Trust this device if meta is provided
            if (meta?.userAgent) {
              const deviceHash = await hashToken(`${userId}:${meta.userAgent}`);
              const expiresAt = new Date(Date.now() + trustedDeviceDays * 24 * 60 * 60 * 1000);

              // Remove existing trust for this device
              await ctx.db.delete({
                model: 'trusted_device',
                where: [
                  { field: 'userId', operator: '=', value: userId },
                  { field: 'deviceHash', operator: '=', value: deviceHash },
                ],
              });

              await ctx.db.create({
                model: 'trusted_device',
                data: {
                  userId,
                  deviceHash,
                  expiresAt,
                  lastUsedAt: new Date(),
                },
              });
            }

            return { verified: true };
          }

          // Try backup code
          const backupCodes = await ctx.db.findMany<BackupCodeRecord>({
            model: 'backup_code',
            where: [
              { field: 'userId', operator: '=', value: userId },
              { field: 'isUsed', operator: '=', value: false },
            ],
          });

          const codeHash = await hashToken(code);
          const matchingCode = backupCodes.find(bc => bc.codeHash === codeHash);

          if (matchingCode) {
            await ctx.db.update({
              model: 'backup_code',
              where: [{ field: 'id', operator: '=', value: matchingCode.id }],
              data: { isUsed: true },
            });

            // Enable 2FA on first successful verification
            if (!secretRecord.isEnabled) {
              await ctx.db.update({
                model: 'two_factor_secret',
                where: [{ field: 'id', operator: '=', value: secretRecord.id }],
                data: { isEnabled: true },
              });
            }

            return { verified: true };
          }

          throw Errors.unauthorized('Invalid two-factor code');
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
  };
}

// Export TOTP utilities for testing
export { generateTOTP, verifyTOTP };
