/**
 * Regression tests for finding #16: standalone (non-transaction) SQLite ops
 * must serialize on the same async chain as `transaction()`, so a plain write
 * issued while a transaction is mid-BEGIN…COMMIT on the single shared
 * connection can never interleave into that open transaction and be swept away
 * by its ROLLBACK.
 */

import type { DatabaseAdapter } from '../adapters/database';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../testing';

/** Build a `create()` argument for a user row keyed by email. */
function newUser(email: string): { model: string; data: Record<string, unknown> } {
  return { model: 'user', data: { email, name: email, passwordHash: 'h', isActive: true } };
}

async function findUser(db: DatabaseAdapter, email: string): Promise<unknown> {
  return db.findOne({ model: 'user', where: [{ field: 'email', operator: '=', value: email }] });
}

describe('sqlite non-transactional op serialization (#16)', () => {
  let db: DatabaseAdapter;

  beforeEach(() => {
    db = createTestAdapter();
  });

  it('does not sweep a concurrent standalone write into an aborting transaction ROLLBACK', async () => {
    // The transaction writes a row, awaits, then aborts. A standalone write is
    // fired WHILE the transaction is open. Without serialization the standalone
    // INSERT runs on the same connection inside the open transaction and gets
    // rolled back.
    const txPromise = db.transaction(async (tx) => {
      await tx.create(newUser('tx@example.com'));
      await new Promise(resolve => setTimeout(resolve, 40));
      throw new Error('forced abort');
    }).catch((err: unknown) => err);

    // Wait until the transaction has actually opened (its BEGIN IMMEDIATE
    // microtask + first insert have run) before firing the standalone. Firing
    // it on the same tick would let better-sqlite3's synchronous INSERT
    // autocommit BEFORE the deferred BEGIN, so it could never be swept and the
    // test would pass even without the fix (a tautology).
    await new Promise(resolve => setTimeout(resolve, 10));

    const standalone = db.create(newUser('standalone@example.com'));

    await Promise.all([txPromise, standalone]);

    // The transaction's own row was rolled back…
    expect(await findUser(db, 'tx@example.com')).toBeNull();
    // …but the concurrent standalone write survived (it was serialized, not
    // captured by the ROLLBACK).
    expect(await findUser(db, 'standalone@example.com')).not.toBeNull();
  });

  it('commits a concurrent standalone write alongside a committing transaction', async () => {
    const txPromise = db.transaction(async (tx) => {
      await tx.create(newUser('tx-ok@example.com'));
      await new Promise(resolve => setTimeout(resolve, 40));
    });

    // Fire the standalone while the transaction is open (see the abort test).
    await new Promise(resolve => setTimeout(resolve, 10));
    const standalone = db.create(newUser('standalone-ok@example.com'));

    await Promise.all([txPromise, standalone]);

    expect(await findUser(db, 'tx-ok@example.com')).not.toBeNull();
    expect(await findUser(db, 'standalone-ok@example.com')).not.toBeNull();
  });

  it('runs ops inside a transaction callback without deadlocking and commits them atomically', async () => {
    await db.transaction(async (tx) => {
      await tx.create(newUser('nested-a@example.com'));
      await tx.create(newUser('nested-b@example.com'));
      // A read inside the callback must also run directly on the open tx, not
      // queue behind it (which would deadlock).
      const seen = await tx.findOne({ model: 'user', where: [{ field: 'email', operator: '=', value: 'nested-a@example.com' }] });
      expect(seen).not.toBeNull();
    });

    expect(await findUser(db, 'nested-a@example.com')).not.toBeNull();
    expect(await findUser(db, 'nested-b@example.com')).not.toBeNull();
  });

  it('rolls back every op issued inside an aborting transaction callback', async () => {
    await db.transaction(async (tx) => {
      await tx.create(newUser('rollback-a@example.com'));
      await tx.create(newUser('rollback-b@example.com'));
      throw new Error('boom');
    }).catch(() => undefined);

    expect(await findUser(db, 'rollback-a@example.com')).toBeNull();
    expect(await findUser(db, 'rollback-b@example.com')).toBeNull();
  });

  it('serializes many concurrent standalone writes without deadlock or loss', async () => {
    await Promise.all(
      Array.from({ length: 12 }, (_, i) => db.create(newUser(`bulk-${i}@example.com`))),
    );

    expect(await db.count({ model: 'user' })).toBe(12);
  });
});
