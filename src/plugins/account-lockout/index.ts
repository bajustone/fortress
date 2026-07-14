/**
 * Account lockout plugin for fortress.
 *
 * Tracks failed sign-in attempts per identifier and applies a progressive
 * lockout (each successive lockout extends the cooldown). Hooks into the
 * sign-in flow to reject attempts during a lockout window.
 *
 * @module
 */

import type { FortressPlugin } from '../../core/plugin';
import { Errors } from '../../core/errors';

export interface AccountLockoutConfig {
  /** Max failed attempts before lockout. Default: 5. */
  maxFailedAttempts?: number;
  /** Initial lockout duration in seconds. Default: 900 (15 minutes). */
  lockoutDurationSeconds?: number;
  /** Double lockout duration on repeated lockouts. Default: true. */
  escalation?: boolean;
  /** Maximum lockout duration in seconds. Default: 3600 (1 hour). */
  maxLockoutSeconds?: number;
}

export interface LockoutStatus {
  identifier: string;
  failedAttempts: number;
  lockoutCount: number;
  lockedUntil: Date | null;
  lastFailedAt: Date | null;
  isLocked: boolean;
}

interface LockoutRecord {
  id: string;
  identifier: string;
  failedAttempts: number;
  lastFailedAt: Date | null;
  lockedUntil: Date | null;
  lockoutCount: number;
  createdAt: Date;
}

/**
 * Account lockout plugin factory. Returns a {@link FortressPlugin} that
 * tracks failed sign-in attempts per identifier and applies a progressive
 * lockout (each successive lockout extends the cooldown window).
 */
export function accountLockout(config: AccountLockoutConfig = {}): FortressPlugin {
  const maxFailedAttempts = config.maxFailedAttempts ?? 5;
  const lockoutDurationSeconds = config.lockoutDurationSeconds ?? 900;
  const escalation = config.escalation ?? true;
  const maxLockoutSeconds = config.maxLockoutSeconds ?? 3600;

  function normalizeIdentifier(identifier: string): string {
    return identifier.trim().normalize('NFC').toLowerCase();
  }

  function calculateLockoutDuration(lockoutCount: number): number {
    if (!escalation) {
      return lockoutDurationSeconds;
    }
    const duration = lockoutDurationSeconds * (2 ** lockoutCount);
    return Math.min(duration, maxLockoutSeconds);
  }

  return {
    name: 'account-lockout',

    models: [{
      name: 'account_lockout',
      fields: {
        id: { type: 'number', required: true },
        identifier: { type: 'string', required: true, unique: true },
        failedAttempts: { type: 'number', required: true },
        lastFailedAt: { type: 'date' },
        lockedUntil: { type: 'date' },
        lockoutCount: { type: 'number', required: true },
        createdAt: { type: 'date', required: true },
      },
    }],

    hooks: {
      async beforeLogin(ctx) {
        const identifier = normalizeIdentifier(ctx.email);

        const record = await ctx.db.findOne<LockoutRecord>({
          model: 'account_lockout',
          where: [{ field: 'identifier', operator: '=', value: identifier }],
        });

        if (!record) {
          return undefined;
        }

        const now = new Date();
        if (record.lockedUntil && record.lockedUntil > now) {
          throw Errors.unauthorized('Account temporarily locked. Try again later.');
        }

        if (record.lockedUntil && record.lockedUntil <= now) {
          await ctx.db.update({
            model: 'account_lockout',
            where: [{ field: 'id', operator: '=', value: record.id }],
            data: { failedAttempts: 0, lockedUntil: null, lastFailedAt: null },
          });
        }

        return undefined;
      },

      async onLoginFailure(ctx) {
        if (ctx.error.message.includes('temporarily locked'))
          return;
        const identifier = normalizeIdentifier(ctx.identifier);

        // Compare-and-swap retry loop. DatabaseAdapter has no arithmetic
        // update expression, so we make the read-then-write safe by including
        // the observed counters in the UPDATE predicate. A concurrent failure
        // that wins the race changes those counters and makes our update
        // return null; we then re-read and retry instead of losing a count.
        for (let attempt = 0; attempt < 5; attempt++) {
          const now = new Date();
          let record = await ctx.db.findOne<LockoutRecord>({
            model: 'account_lockout',
            where: [{ field: 'identifier', operator: '=', value: identifier }],
          });

          if (!record) {
            const newFailedAttempts = 1;
            const updateData: Record<string, unknown> = {
              identifier,
              failedAttempts: newFailedAttempts,
              lastFailedAt: now,
              lockedUntil: null,
              lockoutCount: 0,
            };
            if (newFailedAttempts >= maxFailedAttempts) {
              updateData.lockedUntil = new Date(now.getTime() + calculateLockoutDuration(0) * 1000);
              updateData.lockoutCount = 1;
            }
            try {
              await ctx.db.create<LockoutRecord>({ model: 'account_lockout', data: updateData });
              return;
            }
            catch {
              continue;
            }
          }

          const expired = record.lockedUntil !== null && record.lockedUntil <= now;
          const observedFailedAttempts = record.failedAttempts;
          const observedLockoutCount = record.lockoutCount;
          if (expired) {
            record = { ...record, failedAttempts: 0, lockedUntil: null, lastFailedAt: null };
          }

          const newFailedAttempts = record.failedAttempts + 1;
          const updateData: Record<string, unknown> = {
            failedAttempts: newFailedAttempts,
            lastFailedAt: now,
            lockedUntil: expired ? null : record.lockedUntil,
          };

          if (newFailedAttempts >= maxFailedAttempts) {
            const duration = calculateLockoutDuration(record.lockoutCount);
            updateData.lockedUntil = new Date(now.getTime() + duration * 1000);
            updateData.lockoutCount = record.lockoutCount + 1;
          }
          else if (expired) {
            updateData.lockoutCount = record.lockoutCount;
          }

          const updated = await ctx.db.update<LockoutRecord>({
            model: 'account_lockout',
            where: [
              { field: 'id', operator: '=', value: record.id },
              { field: 'failedAttempts', operator: '=', value: observedFailedAttempts },
              { field: 'lockoutCount', operator: '=', value: observedLockoutCount },
            ],
            data: updateData,
          });
          if (updated)
            return;
        }
      },

      async afterLogin(ctx, result) {
        const identifier = normalizeIdentifier(ctx.identifier ?? result.user.email);

        const record = await ctx.db.findOne<LockoutRecord>({
          model: 'account_lockout',
          where: [{ field: 'identifier', operator: '=', value: identifier }],
        });

        if (record && record.failedAttempts > 0) {
          await ctx.db.update({
            model: 'account_lockout',
            where: [{ field: 'id', operator: '=', value: record.id }],
            data: {
              failedAttempts: 0,
              lockedUntil: null,
            },
          });
        }

        return result;
      },
    },

    methods: ctx => ({
      async getLockoutStatus(identifier: string): Promise<LockoutStatus> {
        const normalized = normalizeIdentifier(identifier);
        const record = await ctx.db.findOne<LockoutRecord>({
          model: 'account_lockout',
          where: [{ field: 'identifier', operator: '=', value: normalized }],
        });

        if (!record) {
          return {
            identifier: normalized,
            failedAttempts: 0,
            lockoutCount: 0,
            lockedUntil: null,
            lastFailedAt: null,
            isLocked: false,
          };
        }

        const isLocked = record.lockedUntil !== null
          && record.lockedUntil > new Date();

        return {
          identifier: record.identifier,
          failedAttempts: record.failedAttempts,
          lockoutCount: record.lockoutCount,
          lockedUntil: record.lockedUntil,
          lastFailedAt: record.lastFailedAt,
          isLocked,
        };
      },

      async resetLockout(identifier: string): Promise<void> {
        const normalized = normalizeIdentifier(identifier);
        const record = await ctx.db.findOne<LockoutRecord>({
          model: 'account_lockout',
          where: [{ field: 'identifier', operator: '=', value: normalized }],
        });

        if (!record) {
          return;
        }

        await ctx.db.update({
          model: 'account_lockout',
          where: [{ field: 'id', operator: '=', value: record.id }],
          data: {
            failedAttempts: 0,
            lockedUntil: null,
            lockoutCount: 0,
            lastFailedAt: null,
          },
        });
      },
    }),
  };
}
