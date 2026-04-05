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
  lockedUntil: string | null;
  lastFailedAt: string | null;
  isLocked: boolean;
}

interface LockoutRecord {
  id: number;
  identifier: string;
  failedAttempts: number;
  lastFailedAt: string | null;
  lockedUntil: string | null;
  lockoutCount: number;
  createdAt: string;
}

export function accountLockout(config: AccountLockoutConfig = {}): FortressPlugin {
  const maxFailedAttempts = config.maxFailedAttempts ?? 5;
  const lockoutDurationSeconds = config.lockoutDurationSeconds ?? 900;
  const escalation = config.escalation ?? true;
  const maxLockoutSeconds = config.maxLockoutSeconds ?? 3600;

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
        const identifier = ctx.email;

        const record = await ctx.db.findOne<LockoutRecord>({
          model: 'account_lockout',
          where: [{ field: 'identifier', operator: '=', value: identifier }],
        });

        if (!record) {
          return undefined;
        }

        if (record.lockedUntil && new Date(record.lockedUntil) > new Date()) {
          throw Errors.unauthorized('Account temporarily locked. Try again later.');
        }

        return undefined;
      },

      async onLoginFailure(ctx) {
        const identifier = ctx.identifier;
        const now = new Date();

        let record = await ctx.db.findOne<LockoutRecord>({
          model: 'account_lockout',
          where: [{ field: 'identifier', operator: '=', value: identifier }],
        });

        if (!record) {
          record = await ctx.db.create<LockoutRecord>({
            model: 'account_lockout',
            data: {
              identifier,
              failedAttempts: 0,
              lastFailedAt: null,
              lockedUntil: null,
              lockoutCount: 0,
            },
          });
        }

        const newFailedAttempts = record.failedAttempts + 1;
        const updateData: Record<string, unknown> = {
          failedAttempts: newFailedAttempts,
          lastFailedAt: now.toISOString(),
        };

        if (newFailedAttempts >= maxFailedAttempts) {
          const duration = calculateLockoutDuration(record.lockoutCount);
          const lockedUntil = new Date(now.getTime() + duration * 1000);
          updateData.lockedUntil = lockedUntil.toISOString();
          updateData.lockoutCount = record.lockoutCount + 1;
        }

        await ctx.db.update({
          model: 'account_lockout',
          where: [{ field: 'id', operator: '=', value: record.id }],
          data: updateData,
        });
      },

      async afterLogin(ctx, result) {
        const identifier = result.user.email;

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
        const record = await ctx.db.findOne<LockoutRecord>({
          model: 'account_lockout',
          where: [{ field: 'identifier', operator: '=', value: identifier }],
        });

        if (!record) {
          return {
            identifier,
            failedAttempts: 0,
            lockoutCount: 0,
            lockedUntil: null,
            lastFailedAt: null,
            isLocked: false,
          };
        }

        const isLocked = record.lockedUntil !== null
          && new Date(record.lockedUntil) > new Date();

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
        const record = await ctx.db.findOne<LockoutRecord>({
          model: 'account_lockout',
          where: [{ field: 'identifier', operator: '=', value: identifier }],
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
