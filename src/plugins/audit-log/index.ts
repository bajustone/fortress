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
import { definePlugin } from '../../core/plugin';

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
// second write on the same adapter. Queue those transactions per adapter, not
// process-wide. PostgreSQL relies solely on its transaction-scoped advisory
// lock, so unrelated databases and PG transactions never share this queue.
const auditWriteChains = new WeakMap<object, Promise<void>>();

function withAuditChainLock<T>(
  db: import('../../adapters/database').DatabaseAdapter,
  fn: (tx: import('../../adapters/database').DatabaseAdapter) => Promise<T>,
): Promise<T> {
  const run = (): Promise<T> => db.transaction(async (tx) => {
    if (tx.dialect === 'pg') {
      if (!tx.rawQuery)
        throw new Error('PostgreSQL audit hash chains require rawQuery advisory-lock support');
      await tx.rawQuery('SELECT pg_advisory_xact_lock(117993, 1)');
    }
    return fn(tx);
  });

  if (db.dialect === 'pg')
    return run();

  const previous = auditWriteChains.get(db) ?? Promise.resolve();
  const result = previous.then(run, run);
  auditWriteChains.set(db, result.then(() => undefined, () => undefined));
  return result;
}

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
  /** Transactionally convert an unchained legacy log into a hash chain. */
  rebaselineChain: () => Promise<ChainVerificationResult>;
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

interface AuditChainAnchor {
  id: string;
  lastHash: string | null;
  entryCount: number;
  updatedAt: Date;
}

interface ChainState {
  tail: AuditLogEntry | null;
  brokenLinks: ChainVerificationResult['brokenLinks'];
}

async function inspectChain(
  entries: AuditLogEntry[],
  anchor: AuditChainAnchor | null,
): Promise<ChainState> {
  if (entries.length === 0) {
    const brokenLinks: ChainVerificationResult['brokenLinks'] = [];
    if (!anchor) {
      brokenLinks.push({
        entryId: 'anchor',
        expected: 'persistent zero-entry audit-chain anchor',
        actual: null,
      });
    }
    else if (anchor.entryCount !== 0 || anchor.lastHash !== null) {
      brokenLinks.push({
        entryId: 'anchor',
        expected: 'entry_count=0 and last_hash=null',
        actual: `${anchor.entryCount}:${anchor.lastHash ?? 'null'}`,
      });
    }
    return { tail: null, brokenLinks };
  }

  const [firstEntry] = entries;
  if (firstEntry === undefined)
    throw new Error('Audit chain invariant violated: non-empty entry list has no first entry');

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
    const entry = hashes.get(hash);
    if (entry === undefined)
      throw new Error(`Audit chain invariant violated: duplicate hash '${hash}' has no entry`);
    brokenLinks.push({
      entryId: entry.id,
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
        entryId: firstEntry.id,
        expected: 'one entry with previousHash=null',
        actual: firstEntry.previousHash,
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
  let current: AuditLogEntry | null = null;
  if (roots.length === 1) {
    const [root] = roots;
    if (root === undefined)
      throw new Error('Audit chain invariant violated: sole root is absent');
    current = root;
  }
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
    if (successors.length === 1) {
      const [successor] = successors;
      if (successor === undefined)
        throw new Error('Audit chain invariant violated: sole successor is absent');
      current = successor;
    }
    else {
      current = null;
    }
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

  // A broken chain can have no reachable tail; retain the established first
  // entry fallback, now explicitly proven above, for an actionable report.
  const anchorEntry = tail === null ? firstEntry : tail;
  if (!anchor) {
    brokenLinks.push({
      entryId: anchorEntry.id,
      expected: 'persisted terminal audit-chain anchor',
      actual: null,
    });
  }
  else {
    if (anchor.entryCount !== entries.length) {
      brokenLinks.push({
        entryId: anchorEntry.id,
        expected: `anchor entry count ${anchor.entryCount}`,
        actual: String(entries.length),
      });
    }
    if (tail) {
      const tailHash = await computeEntryHash(tail);
      if (anchor.lastHash !== tailHash) {
        brokenLinks.push({
          entryId: tail.id,
          expected: anchor.lastHash ?? 'non-null terminal hash',
          actual: tailHash,
        });
      }
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
export function auditLog(config: AuditLogConfig = {}): FortressPlugin<'audit-log', AuditLogMethods, undefined> {
  const allowedEvents = config.events ?? null;
  const hashChain = config.hashChain ?? false;

  function shouldLog(eventType: AuditEventType): boolean {
    if (!allowedEvents)
      return true;
    return allowedEvents.includes(eventType);
  }

  async function readChainAnchor(
    db: import('../../adapters/database').DatabaseAdapter,
  ): Promise<AuditChainAnchor | null> {
    return db.findOne<AuditChainAnchor>({
      model: 'audit_chain_state',
      where: [{ field: 'id', operator: '=', value: '1' }],
    });
  }

  async function writeEntry(
    db: import('../../adapters/database').DatabaseAdapter,
    entry: Omit<AuditLogEntry, 'id' | 'createdAt' | 'previousHash'>,
  ): Promise<void> {
    if (!hashChain) {
      await db.create({ model: 'audit_log', data: { ...entry, previousHash: null } });
      return;
    }

    await withAuditChainLock(db, async (tx) => {
      const anchor = await readChainAnchor(tx);
      if (
        !anchor
        || !Number.isInteger(anchor.entryCount)
        || anchor.entryCount < 0
        || (anchor.entryCount === 0) !== (anchor.lastHash === null)
      ) {
        throw new Error('Cannot append without a valid audit hash-chain anchor');
      }

      if (anchor.entryCount === 0) {
        const existing = await tx.findMany<Pick<AuditLogEntry, 'id'>>({
          model: 'audit_log',
          limit: 1,
        });
        if (existing.length > 0) {
          throw new Error(
            'Cannot append to an unchained legacy audit log; call rebaselineChain() first',
          );
        }
      }

      const created = await tx.create<AuditLogEntry>({
        model: 'audit_log',
        data: { ...entry, previousHash: anchor.lastHash },
      });
      const lastHash = await computeEntryHash(created);
      const updated = await tx.update({
        model: 'audit_chain_state',
        where: [{ field: 'id', operator: '=', value: anchor.id }],
        data: { lastHash, entryCount: anchor.entryCount + 1, updatedAt: new Date() },
      });
      if (!updated)
        throw new Error('Audit hash-chain anchor disappeared during append');
    });
  }

  async function writeAuthEntry(
    db: import('../../adapters/database').DatabaseAdapter,
    entry: Omit<AuditLogEntry, 'id' | 'createdAt' | 'previousHash'>,
    logger: import('../../core/observability/logger').FortressLogger | undefined,
  ): Promise<void> {
    try {
      await writeEntry(db, entry);
    }
    catch (error) {
      // Auth state may already be committed when after-hooks run. Audit
      // availability must not turn a successful auth operation into a reported
      // failure; explicit logCustomEvent calls still surface write failures.
      try {
        logger?.error({ plugin: 'audit-log', error }, 'audit log write failed');
      }
      catch {
        // A custom observability sink must never alter an already-completed
        // authentication operation.
      }
    }
  }

  return definePlugin({
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
    }, {
      name: 'audit_chain_state',
      fields: {
        id: { type: 'string', required: true },
        lastHash: { type: 'string' },
        entryCount: { type: 'number', required: true },
        updatedAt: { type: 'date', required: true },
      },
    }],

    hooks: {
      async afterLogin(ctx, result) {
        if (!shouldLog('LOGIN_SUCCESS'))
          return result;

        await writeAuthEntry(ctx.db, {
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
        }, ctx.config.logger);

        return result;
      },

      async onLoginFailure(ctx) {
        if (!shouldLog('LOGIN_FAILURE'))
          return;

        await writeAuthEntry(ctx.db, {
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
        }, ctx.config.logger);
      },

      async beforeLogout(ctx) {
        if (!shouldLog('LOGOUT'))
          return;

        await writeAuthEntry(ctx.db, {
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
        }, ctx.config.logger);
      },

      async afterRegister(ctx, user) {
        if (!shouldLog('REGISTER'))
          return;

        await writeAuthEntry(ctx.db, {
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
        }, ctx.config.logger);
      },

      async afterTokenRefresh(ctx, result) {
        if (!shouldLog('TOKEN_REFRESH'))
          return result;

        await writeAuthEntry(ctx.db, {
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
        }, ctx.config.logger);

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

      async rebaselineChain(): Promise<ChainVerificationResult> {
        if (!hashChain)
          throw new Error('Enable hashChain before rebaselining the audit log');

        return withAuditChainLock(ctx.db, async (tx) => {
          const anchor = await readChainAnchor(tx);
          if (!anchor)
            throw new Error('Cannot rebaseline without the persistent audit hash-chain anchor');
          if (anchor.entryCount !== 0 || anchor.lastHash !== null) {
            throw new Error('Cannot rebaseline an audit hash chain that has already been initialized');
          }

          const entries = await tx.findMany<AuditLogEntry>({ model: 'audit_log' });
          if (entries.some(entry => entry.previousHash !== null)) {
            throw new Error('Cannot rebaseline a partially or previously chained audit log');
          }
          entries.sort((left, right) => {
            const timeDifference = left.createdAt.getTime() - right.createdAt.getTime();
            if (timeDifference !== 0)
              return timeDifference;
            return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
          });

          let previousHash: string | null = null;
          const rebaselined: AuditLogEntry[] = [];
          for (const entry of entries) {
            const updated = await tx.update<AuditLogEntry>({
              model: 'audit_log',
              where: [{ field: 'id', operator: '=', value: entry.id }],
              data: { previousHash },
            });
            if (!updated)
              throw new Error(`Audit entry ${entry.id} disappeared during rebaseline`);
            rebaselined.push(updated);
            previousHash = await computeEntryHash(updated);
          }

          const updatedAt = new Date();
          const updatedAnchor = await tx.update<AuditChainAnchor>({
            model: 'audit_chain_state',
            where: [{ field: 'id', operator: '=', value: anchor.id }],
            data: { lastHash: previousHash, entryCount: entries.length, updatedAt },
          });
          if (!updatedAnchor)
            throw new Error('Audit hash-chain anchor disappeared during rebaseline');

          const { brokenLinks } = await inspectChain(rebaselined, updatedAnchor);
          if (brokenLinks.length > 0)
            throw new Error('Rebaselined audit hash chain failed verification');
          return { valid: true, totalEntries: entries.length, brokenLinks: [] };
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
        return withAuditChainLock(ctx.db, async (tx) => {
          const entries = await tx.findMany<AuditLogEntry>({ model: 'audit_log' });
          const anchor = await readChainAnchor(tx);
          const { brokenLinks } = await inspectChain(entries, anchor);
          return {
            valid: brokenLinks.length === 0,
            totalEntries: entries.length,
            brokenLinks,
          };
        });
      },
    }),
  } satisfies FortressPlugin<'audit-log', AuditLogMethods>);
}
