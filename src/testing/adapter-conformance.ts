/**
 * Adapter conformance suite — run it against any {@link DatabaseAdapter}
 * implementation to verify the contract fortress relies on.
 *
 * The suite is runner-neutral: it declares cases through a {@link ConformanceRunner}
 * you supply and reports failures by throwing, so it carries no test-framework
 * or assertion-library dependency and can run under Vitest, Jest, or
 * `node:test`.
 *
 * @example
 * ```ts
 * import { runAdapterTests } from '@bajustone/fortress/testing';
 * import { beforeEach, describe, it } from 'vitest';
 *
 * runAdapterTests(() => createMyAdapter(), { describe, it, beforeEach });
 * ```
 *
 * @module
 */

import type { DatabaseAdapter } from '../adapters/database';

/**
 * The subset of a test framework the conformance suite needs. Vitest, Jest,
 * and `node:test` all satisfy this with their global `describe`/`it`/`beforeEach`.
 */
export interface ConformanceRunner {
  describe: (name: string, definition: () => void) => void;
  it: (name: string, execute: () => void | Promise<void>) => void;
  beforeEach: (execute: () => void | Promise<void>) => void;
}

/** Narrows a created record to a string id, throwing if the adapter returned another type. */
export function assertStringId(record: { id: unknown }): asserts record is { id: string } {
  if (typeof record.id !== 'string')
    throw new TypeError(`DatabaseAdapter.create() returned a non-string id (${typeof record.id})`);
}

function isRecordLike(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function describeValue(value: unknown): string {
  if (value instanceof Date)
    return value.toISOString();
  if (value instanceof Error)
    return `${value.name}: ${value.message}`;
  if (typeof value === 'object' && value !== null) {
    try {
      return JSON.stringify(value) ?? String(value);
    }
    catch {
      return String(value);
    }
  }
  return typeof value === 'string' ? JSON.stringify(value) : String(value);
}

function suffix(context?: string): string {
  return context === undefined ? '' : ` (${context})`;
}

function fail(message: string): never {
  throw new Error(`Adapter conformance failure: ${message}`);
}

function deepEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right))
    return true;
  if (left instanceof Date && right instanceof Date)
    return left.getTime() === right.getTime();
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length
      && left.every((item, index) => deepEqual(item, right[index]));
  }
  if (isRecordLike(left) && isRecordLike(right)) {
    const leftKeys = Object.keys(left);
    return leftKeys.length === Object.keys(right).length
      && leftKeys.every(key => Object.hasOwn(right, key) && deepEqual(left[key], right[key]));
  }
  return false;
}

/** Recursive subset comparison, matching the semantics the suite previously relied on. */
function matchesSubset(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    return Array.isArray(actual)
      && actual.length === expected.length
      && expected.every((item, index) => matchesSubset(actual[index], item));
  }
  if (isRecordLike(expected)) {
    return isRecordLike(actual)
      && Object.keys(expected).every(key => matchesSubset(actual[key], expected[key]));
  }
  return deepEqual(actual, expected);
}

function assertSame(actual: unknown, expected: unknown, context?: string): void {
  if (!Object.is(actual, expected))
    fail(`expected ${describeValue(expected)} but received ${describeValue(actual)}${suffix(context)}`);
}

function assertDeepEqual(actual: unknown, expected: unknown, context?: string): void {
  if (!deepEqual(actual, expected))
    fail(`expected ${describeValue(expected)} but received ${describeValue(actual)}${suffix(context)}`);
}

function assertSubset(actual: unknown, expected: Record<string, unknown>, context?: string): void {
  if (!matchesSubset(actual, expected))
    fail(`expected ${describeValue(actual)} to match ${describeValue(expected)}${suffix(context)}`);
}

function assertLength(value: unknown, expected: number, context?: string): void {
  if (!Array.isArray(value))
    fail(`expected an array of length ${expected} but received ${describeValue(value)}${suffix(context)}`);
  if (value.length !== expected)
    fail(`expected length ${expected} but received ${value.length}${suffix(context)}`);
}

function assertNull(value: unknown, context?: string): void {
  if (value !== null)
    fail(`expected null but received ${describeValue(value)}${suffix(context)}`);
}

function assertNotNull<T>(value: T, context?: string): asserts value is Exclude<T, null> {
  if (value === null)
    fail(`expected a value but received null${suffix(context)}`);
}

function assertDefined(value: unknown, context?: string): void {
  if (value === undefined)
    fail(`expected a defined value but received undefined${suffix(context)}`);
}

interface RejectionExpectation {
  /** Substring (string) or pattern (RegExp) the rejection message must match. */
  message?: string | RegExp;
  /** Properties the rejection must carry, compared as a recursive subset. */
  subset?: Record<string, unknown>;
}

async function assertRejects(
  operation: Promise<unknown>,
  expectation: RejectionExpectation = {},
  context?: string,
): Promise<void> {
  let rejection: unknown;
  let rejected = false;
  try {
    await operation;
  }
  catch (error) {
    rejected = true;
    rejection = error;
  }

  if (!rejected)
    fail(`expected the operation to reject${suffix(context)}`);

  if (expectation.message !== undefined) {
    const message = rejection instanceof Error ? rejection.message : String(rejection);
    const matched = typeof expectation.message === 'string'
      ? message.includes(expectation.message)
      : expectation.message.test(message);
    if (!matched)
      fail(`expected rejection message to match ${String(expectation.message)} but received ${describeValue(message)}${suffix(context)}`);
  }

  if (expectation.subset !== undefined && !matchesSubset(rejection, expectation.subset))
    fail(`expected rejection ${describeValue(rejection)} to match ${describeValue(expectation.subset)}${suffix(context)}`);
}

/**
 * Declare the adapter conformance suite against `createAdapter`, using the
 * supplied test runner. A fresh adapter is created before every case.
 */
export function runAdapterTests(createAdapter: () => DatabaseAdapter, runner: ConformanceRunner): void {
  const { beforeEach, describe, it } = runner;
  let db: DatabaseAdapter;

  beforeEach(() => {
    db = createAdapter();
  });

  describe('create', () => {
    it('creates a record and returns it with an id', async () => {
      const user = await db.create<{ id: string; email: string; name: string }>({
        model: 'user',
        data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true },
      });

      assertDefined(user.id, 'created id');
      assertStringId(user);
      assertSame(user.email, 'alice@test.com');
      assertSame(user.name, 'Alice');
    });
  });

  describe('findOne', () => {
    it('returns a matching record', async () => {
      await db.create({ model: 'user', data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true } });

      const found = await db.findOne<{ email: string }>({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'alice@test.com' }],
      });

      assertNotNull(found);
      assertSame(found.email, 'alice@test.com');
    });

    it('returns null when no match', async () => {
      const found = await db.findOne({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'nobody@test.com' }],
      });

      assertNull(found);
    });
  });

  describe('findMany', () => {
    it('returns all matching records', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });

      const users = await db.findMany<{ email: string }>({ model: 'user' });
      assertLength(users, 2);
    });

    it('returns empty array when no matches', async () => {
      const users = await db.findMany({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'nobody@test.com' }],
      });

      assertDeepEqual(users, []);
    });

    it('respects limit', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'c@test.com', name: 'C', passwordHash: 'h', isActive: true } });

      const users = await db.findMany({ model: 'user', limit: 2 });
      assertLength(users, 2);
    });

    it('supports offset', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'c@test.com', name: 'C', passwordHash: 'h', isActive: true } });

      const users = await db.findMany({ model: 'user', limit: 10, offset: 2 });
      assertLength(users, 1);
    });
  });

  describe('update', () => {
    it('updates matching records and returns the updated row', async () => {
      const user = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true },
      });

      const updated = await db.update<{ id: string; name: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
        data: { name: 'Alice Updated' },
      });
      assertSubset(updated, { id: user.id, name: 'Alice Updated' });

      const found = await db.findOne<{ name: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });

      assertNotNull(found);
      assertSame(found.name, 'Alice Updated');
    });

    it('returns null when no row matches', async () => {
      assertNull(await db.update({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'missing@test.com' }],
        data: { name: 'Nobody' },
      }));
    });

    it('updates every matching row while returning one updated row', async () => {
      await db.create({ model: 'user', data: { email: 'multi-a@test.com', name: 'A', passwordHash: 'shared', isActive: true } });
      await db.create({ model: 'user', data: { email: 'multi-b@test.com', name: 'B', passwordHash: 'shared', isActive: true } });
      const updated = await db.update<{ isActive: boolean }>({
        model: 'user',
        where: [{ field: 'passwordHash', operator: '=', value: 'shared' }],
        data: { isActive: false },
      });
      assertSame(updated?.isActive, false);
      assertSame(await db.count({
        model: 'user',
        where: [{ field: 'isActive', operator: '=', value: false }],
      }), 2);
    });

    it('round-trips boolean values on create, update, and read', async () => {
      const user = await db.create<{ id: string; isActive: boolean }>({
        model: 'user',
        data: { email: 'boolean@test.com', name: 'Boolean', passwordHash: 'h', isActive: false },
      });
      assertSame(user.isActive, false);
      const updated = await db.update<{ isActive: boolean }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
        data: { isActive: true },
      });
      assertSame(updated?.isActive, true);
      assertSubset(await db.findOne<{ isActive: boolean }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      }), { isActive: true });
    });
  });

  describe('delete', () => {
    it('removes matching records', async () => {
      const user = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true },
      });

      await db.delete({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });

      const found = await db.findOne({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });

      assertNull(found);
    });

    it('removes every matching row', async () => {
      await db.create({ model: 'user', data: { email: 'delete-a@test.com', name: 'A', passwordHash: 'delete-shared', isActive: true } });
      await db.create({ model: 'user', data: { email: 'delete-b@test.com', name: 'B', passwordHash: 'delete-shared', isActive: true } });
      await db.delete({
        model: 'user',
        where: [{ field: 'passwordHash', operator: '=', value: 'delete-shared' }],
      });
      assertSame(await db.count({ model: 'user' }), 0);
    });

    it('is a no-op when no match', async () => {
      // Should not throw
      await db.delete({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: 99999 }],
      });
    });
  });

  describe('count', () => {
    it('counts all records', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });

      assertSame(await db.count({ model: 'user' }), 2);
    });

    it('counts with filter', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });

      assertSame(await db.count({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'a@test.com' }],
      }), 1);
    });

    it('returns 0 for no matches', async () => {
      assertSame(await db.count({ model: 'user' }), 0);
    });
  });

  describe('rawQuery placeholder contract', () => {
    it('accepts canonical ? placeholders on every dialect', async () => {
      if (!db.rawQuery)
        return;
      const rows = await db.rawQuery<{ value: number | string }>('SELECT ? AS value', [42]);
      assertSame(Number(rows[0]?.value), 42);
    });
  });

  describe('transaction', () => {
    it('commits on success', async () => {
      await db.transaction(async (tx) => {
        await tx.create({ model: 'user', data: { email: 'tx@test.com', name: 'TX', passwordHash: 'h', isActive: true } });
      });

      const found = await db.findOne<{ email: string }>({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'tx@test.com' }],
      });

      assertNotNull(found);
    });

    it('rolls back on error', async () => {
      await assertRejects(
        db.transaction(async (tx) => {
          await tx.create({ model: 'user', data: { email: 'rollback@test.com', name: 'RB', passwordHash: 'h', isActive: true } });
          throw new Error('forced rollback');
        }),
        { message: 'forced rollback' },
      );

      const found = await db.findOne({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'rollback@test.com' }],
      });

      assertNull(found);
    });
  });

  describe('operators', () => {
    it('supports != operator', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });

      const users = await db.findMany<{ email: string }>({
        model: 'user',
        where: [{ field: 'email', operator: '!=', value: 'a@test.com' }],
      });

      assertLength(users, 1);
      assertSame(users[0]?.email, 'b@test.com');
    });

    it('supports in operator', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'c@test.com', name: 'C', passwordHash: 'h', isActive: true } });

      const users = await db.findMany<{ email: string }>({
        model: 'user',
        where: [{ field: 'email', operator: 'in', value: ['a@test.com', 'c@test.com'] }],
      });

      assertLength(users, 2);
    });

    it('supports gt, lt, gte, and lte operators', async () => {
      const dates = [
        new Date('2020-01-01T00:00:00.000Z'),
        new Date('2021-01-01T00:00:00.000Z'),
        new Date('2022-01-01T00:00:00.000Z'),
      ];
      for (const [index, createdAt] of dates.entries()) {
        await db.create({
          model: 'user',
          data: { email: `date-${index}@test.com`, name: String(index), passwordHash: 'h', isActive: true, createdAt, updatedAt: createdAt },
        });
      }
      const cases = [
        ['gt', dates[1], 1],
        ['lt', dates[1], 1],
        ['gte', dates[1], 2],
        ['lte', dates[1], 2],
      ] as const;
      for (const [operator, value, expected] of cases) {
        const rows = await db.findMany({
          model: 'user',
          where: [{ field: 'createdAt', operator, value }],
        });
        assertLength(rows, expected, operator);
      }
    });

    it('supports isNull independently of the supplied value', async () => {
      await db.create({ model: 'user', data: { email: 'null@test.com', name: 'Null', passwordHash: null, isActive: true } });
      await db.create({ model: 'user', data: { email: 'not-null@test.com', name: 'Not null', passwordHash: 'h', isActive: true } });
      const rows = await db.findMany<{ email: string }>({
        model: 'user',
        where: [{ field: 'passwordHash', operator: 'isNull', value: false }],
      });
      assertDeepEqual(rows.map(row => row.email), ['null@test.com']);
    });

    it('throws for an unknown operator', async () => {
      await assertRejects(db.findMany({
        model: 'user',
        where: [{ field: 'email', operator: 'definitely-unsupported', value: 'x' }],
      }));
    });
  });

  describe('sortBy', () => {
    it('sorts ascending and descending by the requested field', async () => {
      for (const name of ['Charlie', 'Alice', 'Bob']) {
        await db.create({
          model: 'user',
          data: { email: `${name.toLowerCase()}@test.com`, name, passwordHash: 'h', isActive: true },
        });
      }
      const ascending = await db.findMany<{ name: string }>({
        model: 'user',
        sortBy: { field: 'name', direction: 'asc' },
      });
      const descending = await db.findMany<{ name: string }>({
        model: 'user',
        sortBy: { field: 'name', direction: 'desc' },
      });
      assertDeepEqual(ascending.map(row => row.name), ['Alice', 'Bob', 'Charlie']);
      assertDeepEqual(descending.map(row => row.name), ['Charlie', 'Bob', 'Alice']);
    });
  });

  describe('empty where clause is rejected on mutations', () => {
    // A frozen contract guarantee: update/delete/findOne with an empty where
    // must throw rather than silently match every row (a full-table wipe
    // footgun). Unfiltered reads (findMany/count) remain legal.
    it('update throws on an empty where', async () => {
      await assertRejects(db.update({ model: 'user', where: [], data: { name: 'x' } }));
    });

    it('delete throws on an empty where', async () => {
      await assertRejects(db.delete({ model: 'user', where: [] }));
    });

    it('findOne throws on an empty where', async () => {
      await assertRejects(db.findOne({ model: 'user', where: [] }));
    });

    it('findMany still allows an unfiltered read', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      const users = await db.findMany({ model: 'user', where: [] });
      assertLength(users, 1);
    });
  });

  describe('constraint violations map to typed errors', () => {
    it('maps a unique violation to a 409 CONFLICT', async () => {
      await db.create({ model: 'user', data: { email: 'dupe@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await assertRejects(
        db.create({ model: 'user', data: { email: 'dupe@test.com', name: 'B', passwordHash: 'h', isActive: true } }),
        { subset: { code: 'CONFLICT', statusCode: 409 } },
      );
    });
  });
}
