/**
 * Append-only audit log plugin for fortress.
 *
 * Captures auth and IAM lifecycle events into the `fortress_audit_log` table
 * with a tamper-evident hash chain (each entry links to the previous entry's
 * hash). Configurable event filtering and a query API for compliance reads.
 *
 * @module
 */

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
    | 'LOGIN_PENDING'
    | 'MFA_VERIFY_SUCCESS'
    | 'MFA_VERIFY_FAILURE'
    | 'LOGOUT'
    | 'REGISTER'
    | 'TOKEN_REFRESH'
    | 'TOKEN_REUSE'
    | 'ROLE_CREATED'
    | 'ROLE_DELETED'
    | 'ROLE_UPDATED'
    | 'ROLE_BOUND'
    | 'ROLE_UNBOUND'
    | 'ROLE_PERMISSION_ADDED'
    | 'ROLE_PERMISSION_REMOVED'
    | 'PERMISSION_CHANGED'
    | 'PERMISSION_CREATED'
    | 'PERMISSION_DELETED'
    | 'GROUP_CREATED'
    | 'GROUP_UPDATED'
    | 'GROUP_DELETED'
    | 'GROUP_MEMBER_ADDED'
    | 'GROUP_MEMBER_REMOVED'
    | 'SERVICE_ACCOUNT_CREATED'
    | 'SERVICE_ACCOUNT_UPDATED'
    | 'SERVICE_ACCOUNT_DELETED';

export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  eventType: AuditEventType;
  actorId: string | null;
  actorType: string;
  targetId: string | null;
  targetType: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  outcome: string;
  metadata: string | null;
  previousHash: string | null;
  createdAt: Date;
}

export interface AuditLogQueryOptions {
  userId?: string;
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

// Synchronous SQLite drivers can deadlock the event loop while waiting on a
// second connection's writer lock. The local queue avoids that; the database
// transaction/advisory lock remains authoritative across processes.
let auditWriteChain: Promise<void> = Promise.resolve();

export interface CustomAuditEvent {
  eventType: string;
  actorId?: string | null;
  actorType?: string;
  targetId?: string | null;
  targetType?: string | null;
  outcome?: string;
  metadata?: Record<string, unknown> | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

export interface ChainVerificationResult {
  valid: boolean;
  totalEntries: number;
  brokenLinks: { entryId: string; expected: string; actual: string | null }[];
}

/** Serialization formats supported by {@link AuditLogMethods.exportEntries}. */
export type AuditLogExportFormat = 'json' | 'csv';

export interface AuditLogMethods {
  getAuditLog: (options?: AuditLogQueryOptions) => Promise<AuditLogEntry[]>;
  logCustomEvent: (event: CustomAuditEvent) => Promise<void>;
  verifyChain: () => Promise<ChainVerificationResult>;
  exportEntries: (format?: AuditLogExportFormat, options?: AuditLogQueryOptions) => Promise<string>;
}

/** Stable column order for the CSV export. */
const AUDIT_EXPORT_COLUMNS = [
  'id',
  'timestamp',
  'eventType',
  'actorId',
  'actorType',
  'targetId',
  'targetType',
  'ipAddress',
  'userAgent',
  'outcome',
  'metadata',
  'previousHash',
  'createdAt',
] as const;

// RFC 4180: a cell must be quoted when it contains a comma, quote, or newline.
const CSV_SPECIAL_RE = /[",\n\r]/;
const CSV_FORMULA_PREFIX_RE = /^[=+\-@\t\r]/;

function toCsvCell(value: unknown): string {
  if (value == null)
    return '';
  const raw = value instanceof Date ? value.toISOString() : String(value);
  // Spreadsheet applications execute cells beginning with these characters.
  // A leading apostrophe forces literal display without changing RFC 4180.
  const str = CSV_FORMULA_PREFIX_RE.test(raw) ? `'${raw}` : raw;
  // Quote and escape embedded quotes by doubling them.
  if (CSV_SPECIAL_RE.test(str))
    return `"${str.replace(/"/g, '""')}"`;
  return str;
}

function entriesToCsv(entries: AuditLogEntry[]): string {
  const header = AUDIT_EXPORT_COLUMNS.join(',');
  const rows = entries.map((entry) => {
    const record = entry as unknown as Record<string, unknown>;
    return AUDIT_EXPORT_COLUMNS.map(column => toCsvCell(record[column])).join(',');
  });
  return [header, ...rows].join('\n');
}

async function computeEntryHash(entry: AuditLogEntry): Promise<string> {
  const values = AUDIT_EXPORT_COLUMNS.map((column) => {
    const value = entry[column];
    return value instanceof Date ? value.toISOString() : value;
  });
  return sha256Hex(JSON.stringify(values));
}

interface ChainState {
  tail: AuditLogEntry | null;
  brokenLinks: ChainVerificationResult['brokenLinks'];
}

async function inspectChain(entries: AuditLogEntry[]): Promise<ChainState> {
  if (entries.length === 0)
    return { tail: null, brokenLinks: [] };

  const hashes = new Map<string, AuditLogEntry>();
  const duplicateHashes = new Set<string>();
  for (const entry of entries) {
    const hash = await computeEntryHash(entry);
    if (hashes.has(hash))
      duplicateHashes.add(hash);
    hashes.set(hash, entry);
  }

  const brokenLinks: ChainVerificationResult['brokenLinks'] = [];
  const roots = entries.filter(entry => entry.previousHash == null);
  for (const entry of entries) {
    if (entry.previousHash != null && !hashes.has(entry.previousHash)) {
      brokenLinks.push({
        entryId: entry.id,
        expected: 'hash of an existing predecessor',
        actual: entry.previousHash,
      });
    }
  }
  for (const hash of duplicateHashes) {
    brokenLinks.push({
      entryId: hashes.get(hash)!.id,
      expected: 'unique entry hash',
      actual: hash,
    });
  }
  if (roots.length !== 1) {
    for (const root of roots.slice(1)) {
      brokenLinks.push({
        entryId: root.id,
        expected: 'exactly one chain root',
        actual: null,
      });
    }
    if (roots.length === 0) {
      brokenLinks.push({
        entryId: entries[0].id,
        expected: 'one entry with previousHash=null',
        actual: entries[0].previousHash,
      });
    }
  }

  const byPreviousHash = new Map<string, AuditLogEntry[]>();
  for (const entry of entries) {
    if (entry.previousHash == null)
      continue;
    const successors = byPreviousHash.get(entry.previousHash) ?? [];
    successors.push(entry);
    byPreviousHash.set(entry.previousHash, successors);
  }

  const visited = new Set<AuditLogEntry>();
  let current = roots.length === 1 ? roots[0] : null;
  let tail: AuditLogEntry | null = null;
  while (current && !visited.has(current)) {
    visited.add(current);
    tail = current;
    const hash = await computeEntryHash(current);
    const successors = byPreviousHash.get(hash) ?? [];
    if (successors.length > 1) {
      for (const successor of successors.slice(1)) {
        brokenLinks.push({
          entryId: successor.id,
          expected: 'a predecessor with only one successor',
          actual: successor.previousHash,
        });
      }
    }
    current = successors.length === 1 ? successors[0] : null;
  }
  for (const entry of entries) {
    if (!visited.has(entry)) {
      brokenLinks.push({
        entryId: entry.id,
        expected: 'entry reachable from the chain root',
        actual: entry.previousHash,
      });
    }
  }

  return { tail, brokenLinks };
}

async function queryAuditLog(
  db: import('../../adapters/database').DatabaseAdapter,
  options?: AuditLogQueryOptions,
): Promise<AuditLogEntry[]> {
  const where: WhereClause[] = [];

  if (options?.userId != null)
    where.push({ field: 'actorId', operator: '=', value: options.userId });
  if (options?.eventType)
    where.push({ field: 'eventType', operator: '=', value: options.eventType });
  if (options?.from)
    where.push({ field: 'timestamp', operator: '>=', value: options.from });
  if (options?.to)
    where.push({ field: 'timestamp', operator: '<=', value: options.to });

  return db.findMany<AuditLogEntry>({
    model: 'audit_log',
    where: where.length > 0 ? where : undefined,
    limit: options?.limit,
    offset: options?.offset,
    sortBy: { field: 'timestamp', direction: 'desc' },
  });
}
/**
 * Audit log plugin factory. Returns a {@link FortressPlugin} that records
 * auth and IAM lifecycle events into an append-only table with a
 * tamper-evident hash chain, plus a query API for compliance reads.
 */
export function auditLog(config: AuditLogConfig = {}): FortressPlugin & { readonly name: 'audit-log' } {
  const allowedEvents = config.events ?? null;
  const hashChain = config.hashChain ?? false;

  function shouldLog(eventType: AuditEventType): boolean {
    if (!allowedEvents)
      return true;
    return allowedEvents.includes(eventType);
  }

  async function writeEntry(
    db: import('../../adapters/database').DatabaseAdapter,
    entry: Omit<AuditLogEntry, 'id' | 'createdAt' | 'previousHash'>,
  ): Promise<void> {
    if (!hashChain) {
      await db.create({ model: 'audit_log', data: { ...entry, previousHash: null } });
      return;
    }

    const run = (): Promise<void> => db.transaction(async (tx) => {
      if (tx.dialect === 'pg' && tx.rawQuery)
        await tx.rawQuery('SELECT pg_advisory_xact_lock(117993, 1)');
      const entries = await tx.findMany<AuditLogEntry>({ model: 'audit_log' });
      const state = await inspectChain(entries);
      if (state.brokenLinks.length > 0)
        throw new Error('Cannot append to an invalid audit hash chain');
      const previousHash = state.tail ? await computeEntryHash(state.tail) : null;
      await tx.create({ model: 'audit_log', data: { ...entry, previousHash } });
    });
    const write = auditWriteChain.then(run, run);
    auditWriteChain = write.then(() => undefined, () => undefined);
    await write;
  }

  return {
    name: 'audit-log',

    models: [{
      name: 'audit_log',
      fields: {
        id: { type: 'string', required: true },
        timestamp: { type: 'date', required: true },
        eventType: { type: 'string', required: true },
        actorId: { type: 'string' },
        actorType: { type: 'string', required: true },
        targetId: { type: 'string' },
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
        return queryAuditLog(ctx.db, options);
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

      async exportEntries(
        format: AuditLogExportFormat = 'json',
        options?: AuditLogQueryOptions,
      ): Promise<string> {
        const entries = await queryAuditLog(ctx.db, options);
        if (format === 'csv')
          return entriesToCsv(entries);
        return JSON.stringify(entries, null, 2);
      },

      async verifyChain(): Promise<ChainVerificationResult> {
        const entries = await ctx.db.findMany<AuditLogEntry>({ model: 'audit_log' });
        const { brokenLinks } = await inspectChain(entries);
        return {
          valid: brokenLinks.length === 0,
          totalEntries: entries.length,
          brokenLinks,
        };
      },
    }),
  };
}
