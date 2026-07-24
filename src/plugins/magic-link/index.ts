/**
 * Passwordless magic-link plugin for fortress.
 *
 * Issues short-lived hashed tokens delivered out-of-band (typically by email)
 * and exchanges a valid token for a fortress access/refresh token pair.
 * Useful as a passwordless sign-in flow or as a recovery mechanism.
 *
 * @module
 */

import type { FortressPlugin } from '../../core/plugin';
import type { AuthResult, FortressUser, RequestMeta } from '../../core/types';
import { generateRefreshToken, hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';
import { definePlugin } from '../../core/plugin';

export interface MagicLinkConfig {
  /** Token expiry in seconds. Default: 600 (10 minutes). */
  tokenExpirySeconds?: number;
  /** Called when a magic link token is created -- send the link to the user */
  onSendMagicLink?: (email: string, token: string) => Promise<void>;
}

export interface MagicLinkMethods {
  sendMagicLink: (email: string) => Promise<{ sent: true }>;
  verify: (rawToken: string, meta?: RequestMeta) => Promise<AuthResult>;
}

interface MagicLinkTokenRecord {
  id: string;
  email: string;
  token: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

/**
 * Magic link plugin factory. Returns a {@link FortressPlugin} that issues
 * short-lived hashed tokens for passwordless sign-in. Tokens are typically
 * delivered out-of-band (email) and exchanged for fortress access/refresh
 * tokens via the verify endpoint.
 */
export function magicLink(config: MagicLinkConfig = {}): FortressPlugin<'magic-link', MagicLinkMethods, undefined> {
  const tokenExpirySeconds = config.tokenExpirySeconds ?? 600;

  return definePlugin({
    name: 'magic-link',

    models: [{
      name: 'magic_link_token',
      fields: {
        id: { type: 'number', required: true },
        email: { type: 'string', required: true },
        token: { type: 'string', required: true },
        expiresAt: { type: 'date', required: true },
        usedAt: { type: 'date' },
        createdAt: { type: 'date', required: true },
      },
    }],

    methods: ctx => ({
      async sendMagicLink(email: string): Promise<{ sent: true }> {
        const { raw, hash } = await generateRefreshToken();
        const expiresAt = new Date(Date.now() + tokenExpirySeconds * 1000);

        await ctx.db.create({
          model: 'magic_link_token',
          data: {
            email,
            token: hash,
            expiresAt,
            usedAt: null,
          },
        });

        if (config.onSendMagicLink) {
          await config.onSendMagicLink(email, raw);
        }

        return { sent: true };
      },

      async verify(rawToken: string, meta?: RequestMeta): Promise<AuthResult> {
        const hash = await hashToken(rawToken);
        const usedAt = new Date();
        const record = await ctx.db.transaction(tx => tx.update<MagicLinkTokenRecord>({
          model: 'magic_link_token',
          where: [
            { field: 'token', operator: '=', value: hash },
            { field: 'usedAt', operator: 'isNull', value: null },
            { field: 'expiresAt', operator: 'gt', value: usedAt },
          ],
          data: { usedAt },
        }));
        if (!record)
          throw Errors.notFound('Invalid or expired magic link token');

        // Find or create user by email (JIT provisioning)
        let user = await ctx.db.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'email', operator: '=', value: record.email }],
        });

        if (!user) {
          user = await ctx.auth!.createUser({
            email: record.email,
            name: record.email.split('@')[0],
          }) as FortressUser;
        }

        // Possession of the single-use link proves control of this address.
        // Mark both JIT-created and existing matching accounts verified before
        // running post-auth gates, otherwise email-verification blocks the
        // very login that established ownership.
        if (!user.emailVerified) {
          await ctx.db.update({
            model: 'user',
            where: [{ field: 'id', operator: '=', value: user.id }],
            data: { emailVerified: true },
          });
        }

        if (!ctx.auth)
          throw Errors.badRequest('Auth service is unavailable');
        return ctx.auth.completePluginAuth(user.id, 'magic-link', meta);
      },
    }),
  } satisfies FortressPlugin<'magic-link', MagicLinkMethods>);
}
