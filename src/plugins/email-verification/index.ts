/**
 * Email verification plugin for fortress.
 *
 * Issues hashed, time-limited verification tokens, exposes
 * `requestVerification` and `verifyEmail` methods on the fortress instance,
 * and adds the corresponding HTTP routes when mounted via a framework adapter.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressPlugin } from '../../core/plugin';
import type { AuthResult, FortressUser, RequestMeta } from '../../core/types';
import { generateRefreshToken, hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';
import { definePlugin } from '../../core/plugin';

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
  sendVerification: (userId: string, email?: string) => Promise<{ sent: true }>;
  verify: (rawToken: string) => Promise<{ userId: string; email: string }>;
  completeVerification: (
    continuationToken: string,
    verificationToken: string,
    meta?: RequestMeta,
  ) => Promise<AuthResult>;
}
/**
 * Email verification plugin factory. Returns a {@link FortressPlugin} that
 * issues hashed verification tokens, exposes `requestVerification` /
 * `verifyEmail` methods, and (when mounted) the corresponding HTTP routes.
 */
export function emailVerification(config: EmailVerificationConfig = {}): FortressPlugin<'email-verification', EmailVerificationMethods, undefined> {
  const tokenExpirySeconds = config.tokenExpirySeconds ?? 86400;
  const requireVerification = config.requireVerification ?? true;

  async function consumeVerificationToken(
    db: DatabaseAdapter,
    rawToken: string,
    expectedUserId?: string,
  ): Promise<VerificationTokenRecord> {
    const hash = await hashToken(rawToken);
    const usedAt = new Date();
    const record = await db.update<VerificationTokenRecord>({
      model: 'email_verification_token',
      where: [
        { field: 'token', operator: '=', value: hash },
        { field: 'usedAt', operator: 'isNull', value: null },
        { field: 'expiresAt', operator: 'gt', value: usedAt },
        ...(expectedUserId ? [{ field: 'userId', operator: '=' as const, value: expectedUserId }] : []),
      ],
      data: { usedAt },
    });
    if (!record)
      throw Errors.notFound('Invalid or expired verification token');

    await db.update({
      model: 'user',
      where: [{ field: 'id', operator: '=', value: record.userId }],
      data: { email: record.email, emailVerified: true },
    });
    return record;
  }

  return definePlugin({
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
      postAuthGate: {
        reason: 'email-verification',
        async evaluate(ctx) {
          if (!requireVerification || ctx.user.emailVerified)
            return;

          const tokens = await ctx.db.findMany<VerificationTokenRecord>({
            model: 'email_verification_token',
            where: [{ field: 'userId', operator: '=', value: ctx.user.id }],
          });
          return tokens.some(token => token.usedAt !== null)
            ? undefined
            : { pluginData: { requiresEmailVerification: true } };
        },
        async verify(ctx, completion) {
          if (typeof completion !== 'string')
            throw Errors.unauthorized('Invalid verification token');
          await consumeVerificationToken(ctx.db, completion, ctx.user.id);
        },
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
      async sendVerification(userId: string, email?: string): Promise<{ sent: true }> {
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

        // Raw verification credentials are delivered only through the callback;
        // returning them to the caller defeats out-of-band verification.
        return { sent: true };
      },

      async verify(rawToken: string): Promise<{ userId: string; email: string }> {
        const record = await ctx.db.transaction(tx => consumeVerificationToken(tx, rawToken));
        return { userId: record.userId, email: record.email };
      },

      async completeVerification(
        continuationToken: string,
        verificationToken: string,
        meta?: RequestMeta,
      ): Promise<AuthResult> {
        if (!ctx.auth)
          throw Errors.badRequest('Auth service is unavailable');
        return ctx.auth.completePendingAuth(continuationToken, verificationToken, meta);
      },
    }),
  } satisfies FortressPlugin<'email-verification', EmailVerificationMethods>);
}
