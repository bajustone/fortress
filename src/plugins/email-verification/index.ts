/**
 * Email verification plugin for fortress.
 *
 * Issues hashed, time-limited verification tokens, exposes
 * `requestVerification` and `verifyEmail` methods on the fortress instance,
 * and adds the corresponding HTTP routes when mounted via a framework adapter.
 *
 * @module
 */

import type { FortressPlugin } from '../../core/plugin';
import type { FortressUser } from '../../core/types';
import { generateRefreshToken, hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';

export interface EmailVerificationConfig {
  /** Token expiry in seconds (default: 86400 = 24h) */
  tokenExpirySeconds?: number;
  /** Block login for unverified users (default: true) */
  requireVerification?: boolean;
  /** Called when a verification token is created */
  onSendVerification?: (email: string, token: string, userId: string) => Promise<void>;
}

interface VerificationTokenRecord {
  id: string;
  userId: string;
  token: string;
  email: string;
  expiresAt: Date;
  usedAt: Date | null;
}

export interface EmailVerificationMethods {
  sendVerification: (userId: string, email?: string) => Promise<{ token: string }>;
  verify: (rawToken: string) => Promise<{ userId: string; email: string }>;
}
/**
 * Email verification plugin factory. Returns a {@link FortressPlugin} that
 * issues hashed verification tokens, exposes `requestVerification` /
 * `verifyEmail` methods, and (when mounted) the corresponding HTTP routes.
 */
export function emailVerification(config: EmailVerificationConfig = {}): FortressPlugin & { readonly name: 'email-verification' } {
  const tokenExpirySeconds = config.tokenExpirySeconds ?? 86400;
  const requireVerification = config.requireVerification ?? true;

  return {
    name: 'email-verification',

    models: [{
      name: 'email_verification_token',
      fields: {
        id: { type: 'number', required: true },
        userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
        token: { type: 'string', required: true },
        email: { type: 'string', required: true },
        expiresAt: { type: 'date', required: true },
        usedAt: { type: 'date' },
        createdAt: { type: 'date', required: true },
      },
    }],

    hooks: {
      async beforeLogin(ctx) {
        if (!requireVerification)
          return;

        // Look up user by the login identifier
        const user = await ctx.db.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'email', operator: '=', value: ctx.email }],
        });

        if (!user)
          return; // Let auth-service handle "user not found"

        // Fast path: check emailVerified field on user
        if (user.emailVerified)
          return;

        // Fallback: check verification tokens (for users verified before emailVerified field existed)
        const tokens = await ctx.db.findMany<VerificationTokenRecord>({
          model: 'email_verification_token',
          where: [{ field: 'userId', operator: '=', value: user.id }],
        });

        const isVerified = tokens.some(t => t.usedAt !== null);

        if (!isVerified) {
          return {
            stop: true as const,
            response: { error: 'EMAIL_NOT_VERIFIED', message: 'Please verify your email before logging in' },
          };
        }

        return undefined;
      },

      async afterRegister(ctx, user) {
        const { raw, hash } = await generateRefreshToken();
        const expiresAt = new Date(Date.now() + tokenExpirySeconds * 1000);

        await ctx.db.create({
          model: 'email_verification_token',
          data: {
            userId: user.id,
            token: hash,
            email: user.email,
            expiresAt,
            usedAt: null,
          },
        });

        if (config.onSendVerification) {
          await config.onSendVerification(user.email, raw, user.id);
        }
      },
    },

    methods: ctx => ({
      async sendVerification(userId: string, email?: string): Promise<{ token: string }> {
        const user = await ctx.db.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: userId }],
        });

        if (!user)
          throw Errors.notFound('User not found');

        const targetEmail = email ?? user.email;
        const { raw, hash } = await generateRefreshToken();
        const expiresAt = new Date(Date.now() + tokenExpirySeconds * 1000);

        await ctx.db.create({
          model: 'email_verification_token',
          data: {
            userId,
            token: hash,
            email: targetEmail,
            expiresAt,
            usedAt: null,
          },
        });

        if (config.onSendVerification) {
          await config.onSendVerification(targetEmail, raw, userId);
        }

        return { token: raw };
      },

      async verify(rawToken: string): Promise<{ userId: string; email: string }> {
        const hash = await hashToken(rawToken);

        const record = await ctx.db.findOne<VerificationTokenRecord>({
          model: 'email_verification_token',
          where: [{ field: 'token', operator: '=', value: hash }],
        });

        if (!record)
          throw Errors.notFound('Invalid verification token');

        if (record.usedAt)
          throw Errors.badRequest('Token already used');

        if (record.expiresAt < new Date())
          throw Errors.badRequest('Verification token expired');

        await ctx.db.update({
          model: 'email_verification_token',
          where: [{ field: 'id', operator: '=', value: record.id }],
          data: { usedAt: new Date() },
        });

        // Mark user as email-verified
        await ctx.db.update({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: record.userId }],
          data: { emailVerified: true },
        });

        return { userId: record.userId, email: record.email };
      },
    }),
  };
}
