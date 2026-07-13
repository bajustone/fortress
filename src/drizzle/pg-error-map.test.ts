import { describe, expect, it } from 'vitest';
import { FortressError } from '../core/errors';
import { findSqlstate, rethrowDbError } from './pg-error-map';

describe('findSqlstate', () => {
  it('returns the code from the top-level error', () => {
    expect(findSqlstate({ code: '23505' })).toBe('23505');
  });

  it('walks the cause chain to find the SQLSTATE', () => {
    const err = new Error('drizzle wrapper');
    (err as any).cause = new Error('postgres-js wrapper');
    ((err as any).cause as any).cause = { code: '40P01', message: 'deadlock' };
    expect(findSqlstate(err)).toBe('40P01');
  });

  it('only recognizes the 5-char alnum SQLSTATE shape', () => {
    expect(findSqlstate({ code: 'CONFLICT' })).toBeNull();
    expect(findSqlstate({ code: 'abc12' })).toBeNull(); // lowercase not allowed
    expect(findSqlstate({ code: 12345 })).toBeNull(); // number not allowed
    expect(findSqlstate(null)).toBeNull();
    expect(findSqlstate(undefined)).toBeNull();
    expect(findSqlstate('not an object')).toBeNull();
  });

  it('gives up after a fixed depth', () => {
    // Build a chain longer than MAX_CAUSE_DEPTH (6)
    let leaf: any = { code: '23505' };
    for (let i = 0; i < 10; i++)
      leaf = { cause: leaf };
    expect(findSqlstate(leaf)).toBeNull();
  });
});

describe('rethrowDbError', () => {
  it('passes a non-constraint sqlite error through untouched', () => {
    // A pg SQLSTATE is not a SQLite constraint code, so under the sqlite
    // dialect it is not recognized and the original is re-thrown.
    const original = { code: '23505', message: 'unique violation' };
    expect(() => rethrowDbError(original, 'sqlite')).toThrow();
    try {
      rethrowDbError(original, 'sqlite');
    }
    catch (err) {
      expect(err).toBe(original);
    }
  });

  it('maps a sqlite UNIQUE violation to CONFLICT/409 (by code)', () => {
    try {
      rethrowDbError({ code: 'SQLITE_CONSTRAINT_UNIQUE', message: 'UNIQUE constraint failed: user.email' }, 'sqlite');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect(err).toBeInstanceOf(FortressError);
      expect((err as FortressError).code).toBe('CONFLICT');
      expect((err as FortressError).statusCode).toBe(409);
    }
  });

  it('maps a sqlite UNIQUE violation to CONFLICT by message alone', () => {
    // Older drivers set only the message, not a SQLITE_CONSTRAINT_* code.
    try {
      rethrowDbError(new Error('UNIQUE constraint failed: social_account.provider'), 'sqlite');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('CONFLICT');
    }
  });

  it('maps sqlite PRIMARYKEY to CONFLICT and FOREIGNKEY to UNPROCESSABLE_ENTITY', () => {
    try {
      rethrowDbError({ code: 'SQLITE_CONSTRAINT_PRIMARYKEY' }, 'sqlite');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('CONFLICT');
    }
    try {
      rethrowDbError({ code: 'SQLITE_CONSTRAINT_FOREIGNKEY' }, 'sqlite');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('UNPROCESSABLE_ENTITY');
      expect((err as FortressError).statusCode).toBe(422);
    }
  });

  it('walks the cause chain for a wrapped sqlite constraint error', () => {
    const driver = new Error('UNIQUE constraint failed: user.email');
    (driver as any).code = 'SQLITE_CONSTRAINT_UNIQUE';
    const wrapper = new Error('DrizzleQueryError');
    (wrapper as any).cause = driver;
    try {
      rethrowDbError(wrapper, 'sqlite');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('CONFLICT');
    }
  });

  it('passes through unrecognized SQLSTATEs on pg', () => {
    const original = { code: 'P0001', message: 'raise exception' };
    try {
      rethrowDbError(original, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect(err).toBe(original);
    }
  });

  it('maps 23505 (unique_violation) to CONFLICT/409', () => {
    try {
      rethrowDbError({ code: '23505' }, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect(err).toBeInstanceOf(FortressError);
      expect((err as FortressError).code).toBe('CONFLICT');
      expect((err as FortressError).statusCode).toBe(409);
    }
  });

  it('maps 23503 (foreign_key_violation) to UNPROCESSABLE_ENTITY/422', () => {
    try {
      rethrowDbError({ code: '23503' }, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect(err).toBeInstanceOf(FortressError);
      expect((err as FortressError).code).toBe('UNPROCESSABLE_ENTITY');
      expect((err as FortressError).statusCode).toBe(422);
    }
  });

  it('maps 23502 (not_null_violation) to BAD_REQUEST/400', () => {
    try {
      rethrowDbError({ code: '23502' }, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('BAD_REQUEST');
      expect((err as FortressError).statusCode).toBe(400);
    }
  });

  it('maps 23514 (check_violation) to UNPROCESSABLE_ENTITY/422', () => {
    try {
      rethrowDbError({ code: '23514' }, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('UNPROCESSABLE_ENTITY');
      expect((err as FortressError).statusCode).toBe(422);
    }
  });

  it('maps 40001 (serialization_failure) to CONFLICT/409', () => {
    try {
      rethrowDbError({ code: '40001' }, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('CONFLICT');
      expect((err as FortressError).statusCode).toBe(409);
    }
  });

  it('maps 40P01 (deadlock_detected) to CONFLICT/409', () => {
    try {
      rethrowDbError({ code: '40P01' }, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('CONFLICT');
      expect((err as FortressError).statusCode).toBe(409);
    }
  });

  it('maps 57014 (query_canceled) to SERVICE_UNAVAILABLE/503', () => {
    try {
      rethrowDbError({ code: '57014' }, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('SERVICE_UNAVAILABLE');
      expect((err as FortressError).statusCode).toBe(503);
    }
  });

  it('preserves the original error as cause on the FortressError', () => {
    const original = new Error('postgres: duplicate key value');
    (original as any).code = '23505';
    try {
      rethrowDbError(original, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).cause).toBe(original);
    }
  });

  it('walks cause chain to find SQLSTATE on wrapped drizzle errors', () => {
    const driver = { code: '23505', message: 'duplicate key' };
    const wrapper = new Error('DrizzleQueryError');
    (wrapper as any).cause = driver;
    try {
      rethrowDbError(wrapper, 'pg');
      throw new Error('should have thrown');
    }
    catch (err) {
      expect((err as FortressError).code).toBe('CONFLICT');
    }
  });
});
