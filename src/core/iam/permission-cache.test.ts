import type { Permission } from '../types';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPermissionCache, subjectCacheKey } from './permission-cache';

function perm(id: number, resource = 'post', action = 'read'): Permission {
  return { id, resource, action, effect: 'ALLOW' };
}

function userKey(id: number): string {
  return subjectCacheKey({ type: 'USER', id });
}

describe('permissionCache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns undefined on cache miss', () => {
    const cache = createPermissionCache(30_000, 100);
    expect(cache.get(userKey(1))).toBeUndefined();
  });

  it('returns cached permissions on hit', () => {
    const cache = createPermissionCache(30_000, 100);
    const perms = [perm(1), perm(2, 'user', 'write')];
    cache.set(userKey(1), perms);
    expect(cache.get(userKey(1))).toEqual(perms);
  });

  it('expires entries after TTL', () => {
    const cache = createPermissionCache(5_000, 100);
    cache.set(userKey(1), [perm(1)]);
    expect(cache.get(userKey(1))).toBeDefined();

    vi.advanceTimersByTime(5_001);
    expect(cache.get(userKey(1))).toBeUndefined();
  });

  it('invalidate removes a specific subject', () => {
    const cache = createPermissionCache(30_000, 100);
    cache.set(userKey(1), [perm(1)]);
    cache.set(userKey(2), [perm(2)]);

    cache.invalidate(userKey(1));
    expect(cache.get(userKey(1))).toBeUndefined();
    expect(cache.get(userKey(2))).toBeDefined();
  });

  it('invalidateAll clears everything', () => {
    const cache = createPermissionCache(30_000, 100);
    cache.set(userKey(1), [perm(1)]);
    cache.set(userKey(2), [perm(2)]);

    cache.invalidateAll();
    expect(cache.get(userKey(1))).toBeUndefined();
    expect(cache.get(userKey(2))).toBeUndefined();
  });

  it('evicts oldest entry when at capacity', () => {
    const cache = createPermissionCache(30_000, 2);
    cache.set(userKey(1), [perm(1)]);
    cache.set(userKey(2), [perm(2)]);
    cache.set(userKey(3), [perm(3)]); // should evict user 1

    expect(cache.get(userKey(1))).toBeUndefined();
    expect(cache.get(userKey(2))).toBeDefined();
    expect(cache.get(userKey(3))).toBeDefined();
  });

  it('does not evict when updating existing entry', () => {
    const cache = createPermissionCache(30_000, 2);
    cache.set(userKey(1), [perm(1)]);
    cache.set(userKey(2), [perm(2)]);
    cache.set(userKey(1), [perm(1), perm(3)]); // update, not new entry

    expect(cache.get(userKey(1))).toHaveLength(2);
    expect(cache.get(userKey(2))).toBeDefined();
  });

  it('user and service account with the same numeric id do not collide', () => {
    const cache = createPermissionCache(30_000, 100);
    cache.set(subjectCacheKey({ type: 'USER', id: 42 }), [perm(1)]);
    cache.set(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id: 42 }), [perm(2, 'deploy', 'run')]);

    const userPerms = cache.get(subjectCacheKey({ type: 'USER', id: 42 }));
    const saPerms = cache.get(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id: 42 }));
    expect(userPerms).toHaveLength(1);
    expect(userPerms![0].id).toBe(1);
    expect(saPerms).toHaveLength(1);
    expect(saPerms![0].resource).toBe('deploy');
  });

  describe('generation (F5 TOCTOU guard)', () => {
    it('starts at 0 and increments on invalidate and invalidateAll', () => {
      const cache = createPermissionCache(30_000, 100);
      expect(cache.generation()).toBe(0);

      cache.invalidate(userKey(1));
      expect(cache.generation()).toBe(1);

      cache.invalidateAll();
      expect(cache.generation()).toBe(2);
    });

    it('lets a read-through detect that an invalidation raced its load', () => {
      const cache = createPermissionCache(30_000, 100);
      // Mirrors the checkPermission read-through ordering:
      const gen = cache.generation(); // captured before the (awaited) DB load
      cache.invalidate(userKey(1)); // a revocation fires mid-load
      // Guard: the load is now stale, so the caller must NOT write it back.
      expect(cache.generation() !== gen).toBe(true);
    });

    it('does not bump generation on get or set (only revocations advance it)', () => {
      const cache = createPermissionCache(30_000, 100);
      cache.set(userKey(1), [perm(1)]);
      cache.get(userKey(1));
      expect(cache.generation()).toBe(0);
    });
  });
});
