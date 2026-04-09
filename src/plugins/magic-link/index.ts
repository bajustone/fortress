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
import type { FortressUser } from '../../core/types';
import { generateRefreshToken, hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';

export interface MagicLinkConfig {
  /** Token expiry in seconds. Default: 600 (10 minutes). */
  tokenExpirySeconds?: number;
  /** Called when a magic link token is created -- send the link to the user */
  onSendMagicLink?: (email: string, token: string) => Promise<void>;
}

interface MagicLinkTokenRecord {
  id: number;
  email: string;
  token: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export function magicLink(config: MagicLinkConfig = {}): FortressPlugin {
  const tokenExpirySeconds = config.tokenExpirySeconds ?? 600;

  return {
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

      async verifyMagicLink(rawToken: string): Promise<{ userId: number; email: string; accessToken: string }> {
        const hash = await hashToken(rawToken);

        const record = await ctx.db.findOne<MagicLinkTokenRecord>({
          model: 'magic_link_token',
          where: [{ field: 'token', operator: '=', value: hash }],
        });

        if (!record) {
          throw Errors.notFound('Invalid magic link token');
        }

        if (record.usedAt) {
          throw Errors.badRequest('Magic link token already used');
        }

        if (record.expiresAt < new Date()) {
          throw Errors.badRequest('Magic link token expired');
        }

        // Mark token as used
        await ctx.db.update({
          model: 'magic_link_token',
          where: [{ field: 'id', operator: '=', value: record.id }],
          data: { usedAt: new Date() },
        });

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

        // Issue access token via the auth service
        const accessToken = await ctx.auth!.signToken({
          sub: user.id,
          name: user.name,
          groups: [],
          iss: 'fortress',
        }) as string;

        return { userId: user.id, email: record.email, accessToken };
      },
    }),
  };
}
