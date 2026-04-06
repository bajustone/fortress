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
    | 'TOKEN_REUSE'
    | 'ROLE_CREATED'
    | 'ROLE_DELETED'
    | 'ROLE_BOUND'
    | 'ROLE_UNBOUND'
    | 'PERMISSION_CHANGED'
    | 'GROUP_CREATED'
    | 'GROUP_MEMBER_ADDED'
    | 'GROUP_MEMBER_REMOVED';

export interface AuditLogEntry {
  id: number;
  timestamp: Date;
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
  createdAt: Date;
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

export interface CustomAuditEvent {
  eventType: string;
  actorId?: number | null;
  actorType?: string;
  targetId?: number | null;
  targetType?: string | null;
  outcome?: string;
  metadata?: Record<string, unknown> | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

export interface ChainVerificationResult {
  valid: boolean;
  totalEntries: number;
  brokenLinks: { entryId: number; expected: string; actual: string | null }[];
}

export interface AuditLogMethods {
  getAuditLog: (options?: AuditLogQueryOptions) => Promise<AuditLogEntry[]>;
  logCustomEvent: (event: CustomAuditEvent) => Promise<void>;
  verifyChain: () => Promise<ChainVerificationResult>;
}
export function auditLog(config: AuditLogConfig = {}): FortressPlugin & { readonly name: 'audit-log' } {
  const allowedEvents = config.events ?? null;
  const hashChain = config.hashChain ?? false;

  function shouldLog(eventType: AuditEventType): boolean {
    if (!allowedEvents)
      return true;
    return allowedEvents.includes(eventType);
  }

  async function getLastHash(db: import('../../adapters/database').DatabaseAdapter): Promise<string | null> {
    if (!hashChain)
      return null;
    const lastEntries = await db.findMany<AuditLogEntry>({
      model: 'audit_log',
      sortBy: { field: 'id', direction: 'desc' },
      limit: 1,
    });
    if (lastEntries.length === 0)
      return null;
    const last = lastEntries[0];
    return sha256Hex(`${last.id}${last.timestamp}${last.eventType}${last.actorId}`);
  }

  async function writeEntry(
    db: import('../../adapters/database').DatabaseAdapter,
    entry: Omit<AuditLogEntry, 'id' | 'createdAt' | 'previousHash'>,
  ): Promise<void> {
    const previousHash = await getLastHash(db);
    await db.create({
      model: 'audit_log',
      data: { ...entry, previousHash },
    });
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

        await writeEntry(ctx.db, {
          timestamp: new Date(),
          eventType: 'LOGIN_SUCCESS',
          actorId: result.user.id,
          actorType: 'user',
          targetId: null,
          targetType: null,
          ipAddress: ctx.meta?.ipAddress ?? null,
          userAgent: ctx.meta?.userAgent ?? null,
          outcome: 'success',
          metadata: null,
        });

        return result;
      },

      async onLoginFailure(ctx) {
        if (!shouldLog('LOGIN_FAILURE'))
          return;

        await writeEntry(ctx.db, {
          timestamp: new Date(),
          eventType: 'LOGIN_FAILURE',
          actorId: null,
          actorType: 'anonymous',
          targetId: null,
          targetType: null,
          ipAddress: null,
          userAgent: null,
          outcome: 'failure',
          metadata: JSON.stringify({ identifier: ctx.identifier, error: ctx.error.message }),
        });
      },

      async beforeLogout(ctx) {
        if (!shouldLog('LOGOUT'))
          return;

        await writeEntry(ctx.db, {
          timestamp: new Date(),
          eventType: 'LOGOUT',
          actorId: null,
          actorType: 'user',
          targetId: null,
          targetType: null,
          ipAddress: ctx.meta?.ipAddress ?? null,
          userAgent: ctx.meta?.userAgent ?? null,
          outcome: 'success',
          metadata: null,
        });
      },

      async afterRegister(ctx, user) {
        if (!shouldLog('REGISTER'))
          return;

        await writeEntry(ctx.db, {
          timestamp: new Date(),
          eventType: 'REGISTER',
          actorId: user.id,
          actorType: 'user',
          targetId: user.id,
          targetType: 'user',
          ipAddress: ctx.meta?.ipAddress ?? null,
          userAgent: ctx.meta?.userAgent ?? null,
          outcome: 'success',
          metadata: null,
        });
      },

      async afterTokenRefresh(ctx, result) {
        if (!shouldLog('TOKEN_REFRESH'))
          return result;

        await writeEntry(ctx.db, {
          timestamp: new Date(),
          eventType: 'TOKEN_REFRESH',
          actorId: null,
          actorType: 'user',
          targetId: null,
          targetType: null,
          ipAddress: ctx.meta?.ipAddress ?? null,
          userAgent: ctx.meta?.userAgent ?? null,
          outcome: 'success',
          metadata: null,
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
          where.push({ field: 'timestamp', operator: '>=', value: options.from });
        }

        if (options?.to) {
          where.push({ field: 'timestamp', operator: '<=', value: options.to });
        }

        return ctx.db.findMany<AuditLogEntry>({
          model: 'audit_log',
          where: where.length > 0 ? where : undefined,
          limit: options?.limit,
          offset: options?.offset,
          sortBy: { field: 'timestamp', direction: 'desc' },
        });
      },

      async logCustomEvent(event: CustomAuditEvent): Promise<void> {
        const eventType = event.eventType as AuditEventType;
        if (allowedEvents && !allowedEvents.includes(eventType))
          return;

        await writeEntry(ctx.db, {
          timestamp: new Date(),
          eventType,
          actorId: event.actorId ?? null,
          actorType: event.actorType ?? 'system',
          targetId: event.targetId ?? null,
          targetType: event.targetType ?? null,
          ipAddress: event.ipAddress ?? null,
          userAgent: event.userAgent ?? null,
          outcome: event.outcome ?? 'success',
          metadata: event.metadata ? JSON.stringify(event.metadata) : null,
        });
      },

      async verifyChain(): Promise<ChainVerificationResult> {
        const entries = await ctx.db.findMany<AuditLogEntry>({
          model: 'audit_log',
          sortBy: { field: 'id', direction: 'asc' },
        });

        const brokenLinks: ChainVerificationResult['brokenLinks'] = [];

        for (let i = 1; i < entries.length; i++) {
          const prev = entries[i - 1];
          const current = entries[i];

          const expectedHash = await sha256Hex(
            `${prev.id}${prev.timestamp}${prev.eventType}${prev.actorId}`,
          );

          if (current.previousHash !== expectedHash) {
            brokenLinks.push({
              entryId: current.id,
              expected: expectedHash,
              actual: current.previousHash,
            });
          }
        }

        return {
          valid: brokenLinks.length === 0,
          totalEntries: entries.length,
          brokenLinks,
        };
      },
    }),
  };
}
