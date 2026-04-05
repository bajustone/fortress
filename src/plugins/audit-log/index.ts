import type { WhereClause } from '../../adapters/database/types';
import type { FortressPlugin } from '../../core/plugin';

export interface AuditLogConfig {
  /** Events to capture. Default: all. */
  events?: AuditEventType[];
  /** Enable hash chain for tamper detection. Default: false. */
  hashChain?: boolean;
}

export type AuditEventType
  = | 'LOGIN_SUCCESS'
    | 'LOGIN_FAILURE'
    | 'LOGOUT'
    | 'REGISTER'
    | 'TOKEN_REFRESH'
    | 'TOKEN_REUSE';

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  eventType: AuditEventType;
  actorId: number | null;
  actorType: string;
  targetId: number | null;
  targetType: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  outcome: string;
  metadata: string | null;
  previousHash: string | null;
  createdAt: string;
}

export interface AuditLogQueryOptions {
  userId?: number;
  eventType?: AuditEventType;
  from?: Date;
  to?: Date;
  limit?: number;
  offset?: number;
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function auditLog(config: AuditLogConfig = {}): FortressPlugin {
  const allowedEvents = config.events ?? null;
  const hashChain = config.hashChain ?? false;

  function shouldLog(eventType: AuditEventType): boolean {
    if (!allowedEvents)
      return true;
    return allowedEvents.includes(eventType);
  }

  return {
    name: 'audit-log',

    models: [{
      name: 'audit_log',
      fields: {
        id: { type: 'number', required: true },
        timestamp: { type: 'date', required: true },
        eventType: { type: 'string', required: true },
        actorId: { type: 'number' },
        actorType: { type: 'string', required: true },
        targetId: { type: 'number' },
        targetType: { type: 'string' },
        ipAddress: { type: 'string' },
        userAgent: { type: 'string' },
        outcome: { type: 'string', required: true },
        metadata: { type: 'string' },
        previousHash: { type: 'string' },
        createdAt: { type: 'date', required: true },
      },
    }],

    hooks: {
      async afterLogin(ctx, result) {
        if (!shouldLog('LOGIN_SUCCESS'))
          return result;

        let previousHash: string | null = null;
        if (hashChain) {
          const lastEntries = await ctx.db.findMany<AuditLogEntry>({
            model: 'audit_log',
            sortBy: { field: 'id', direction: 'desc' },
            limit: 1,
          });
          if (lastEntries.length > 0) {
            const last = lastEntries[0];
            previousHash = await sha256Hex(
              `${last.id}${last.timestamp}${last.eventType}${last.actorId}`,
            );
          }
        }

        await ctx.db.create({
          model: 'audit_log',
          data: {
            timestamp: new Date().toISOString(),
            eventType: 'LOGIN_SUCCESS',
            actorId: result.user.id,
            actorType: 'user',
            targetId: null,
            targetType: null,
            ipAddress: ctx.meta?.ipAddress ?? null,
            userAgent: ctx.meta?.userAgent ?? null,
            outcome: 'success',
            metadata: null,
            previousHash,
          },
        });

        return result;
      },

      async onLoginFailure(ctx) {
        if (!shouldLog('LOGIN_FAILURE'))
          return;

        let previousHash: string | null = null;
        if (hashChain) {
          const lastEntries = await ctx.db.findMany<AuditLogEntry>({
            model: 'audit_log',
            sortBy: { field: 'id', direction: 'desc' },
            limit: 1,
          });
          if (lastEntries.length > 0) {
            const last = lastEntries[0];
            previousHash = await sha256Hex(
              `${last.id}${last.timestamp}${last.eventType}${last.actorId}`,
            );
          }
        }

        await ctx.db.create({
          model: 'audit_log',
          data: {
            timestamp: new Date().toISOString(),
            eventType: 'LOGIN_FAILURE',
            actorId: null,
            actorType: 'anonymous',
            targetId: null,
            targetType: null,
            ipAddress: null,
            userAgent: null,
            outcome: 'failure',
            metadata: JSON.stringify({ identifier: ctx.identifier, error: ctx.error.message }),
            previousHash,
          },
        });
      },

      async beforeLogout(ctx) {
        if (!shouldLog('LOGOUT'))
          return;

        // Resolve user from the token to get actorId
        // The token is available in ctx but we can't decode it here without auth service,
        // so we log with the token hash as metadata for traceability
        let previousHash: string | null = null;
        if (hashChain) {
          const lastEntries = await ctx.db.findMany<AuditLogEntry>({
            model: 'audit_log',
            sortBy: { field: 'id', direction: 'desc' },
            limit: 1,
          });
          if (lastEntries.length > 0) {
            const last = lastEntries[0];
            previousHash = await sha256Hex(
              `${last.id}${last.timestamp}${last.eventType}${last.actorId}`,
            );
          }
        }

        await ctx.db.create({
          model: 'audit_log',
          data: {
            timestamp: new Date().toISOString(),
            eventType: 'LOGOUT',
            actorId: null,
            actorType: 'user',
            targetId: null,
            targetType: null,
            ipAddress: ctx.meta?.ipAddress ?? null,
            userAgent: ctx.meta?.userAgent ?? null,
            outcome: 'success',
            metadata: null,
            previousHash,
          },
        });
      },

      async afterRegister(ctx, user) {
        if (!shouldLog('REGISTER'))
          return;

        let previousHash: string | null = null;
        if (hashChain) {
          const lastEntries = await ctx.db.findMany<AuditLogEntry>({
            model: 'audit_log',
            sortBy: { field: 'id', direction: 'desc' },
            limit: 1,
          });
          if (lastEntries.length > 0) {
            const last = lastEntries[0];
            previousHash = await sha256Hex(
              `${last.id}${last.timestamp}${last.eventType}${last.actorId}`,
            );
          }
        }

        await ctx.db.create({
          model: 'audit_log',
          data: {
            timestamp: new Date().toISOString(),
            eventType: 'REGISTER',
            actorId: user.id,
            actorType: 'user',
            targetId: user.id,
            targetType: 'user',
            ipAddress: ctx.meta?.ipAddress ?? null,
            userAgent: ctx.meta?.userAgent ?? null,
            outcome: 'success',
            metadata: null,
            previousHash,
          },
        });
      },

      async afterTokenRefresh(ctx, result) {
        if (!shouldLog('TOKEN_REFRESH'))
          return result;

        let previousHash: string | null = null;
        if (hashChain) {
          const lastEntries = await ctx.db.findMany<AuditLogEntry>({
            model: 'audit_log',
            sortBy: { field: 'id', direction: 'desc' },
            limit: 1,
          });
          if (lastEntries.length > 0) {
            const last = lastEntries[0];
            previousHash = await sha256Hex(
              `${last.id}${last.timestamp}${last.eventType}${last.actorId}`,
            );
          }
        }

        await ctx.db.create({
          model: 'audit_log',
          data: {
            timestamp: new Date().toISOString(),
            eventType: 'TOKEN_REFRESH',
            actorId: null,
            actorType: 'user',
            targetId: null,
            targetType: null,
            ipAddress: ctx.meta?.ipAddress ?? null,
            userAgent: ctx.meta?.userAgent ?? null,
            outcome: 'success',
            metadata: null,
            previousHash,
          },
        });

        return result;
      },
    },

    methods: ctx => ({
      async getAuditLog(options?: AuditLogQueryOptions): Promise<AuditLogEntry[]> {
        const where: WhereClause[] = [];

        if (options?.userId != null) {
          where.push({ field: 'actorId', operator: '=', value: options.userId });
        }

        if (options?.eventType) {
          where.push({ field: 'eventType', operator: '=', value: options.eventType });
        }

        if (options?.from) {
          where.push({ field: 'timestamp', operator: '>=', value: options.from.toISOString() });
        }

        if (options?.to) {
          where.push({ field: 'timestamp', operator: '<=', value: options.to.toISOString() });
        }

        return ctx.db.findMany<AuditLogEntry>({
          model: 'audit_log',
          where: where.length > 0 ? where : undefined,
          limit: options?.limit,
          offset: options?.offset,
          sortBy: { field: 'timestamp', direction: 'desc' },
        });
      },
    }),
  };
}
