import type { Permission, Subject } from '../types';

interface CacheEntry {
  permissions: Permission[];
  expiresAt: number;
}

/**
 * Build a stable cache key for a subject. The `${type}:${id}` form partitions
 * users from service accounts (and any future subject types) so a USER and a
 * SERVICE_ACCOUNT with the same numeric id never collide.
 */
export function subjectCacheKey(subject: Subject): string {
  return `${subject.type}:${subject.id}`;
}

export interface PermissionCache {
  get: (key: string) => Permission[] | undefined;
  set: (key: string, permissions: Permission[]) => void;
  invalidate: (key: string) => void;
  invalidateAll: () => void;
  /**
   * Monotonic counter bumped on every `invalidate`/`invalidateAll`. Callers
   * doing a read-through (miss → load from DB → set) capture this before the
   * load and skip the `set` if it advanced, closing the TOCTOU window where a
   * revocation that fires mid-load would otherwise be clobbered by a stale
   * write and keep a revoked subject authorized until the entry expires.
   */
  generation: () => number;
}

export function createPermissionCache(ttlMs: number, maxEntries: number): PermissionCache {
  const store = new Map<string, CacheEntry>();
  let generation = 0;

  return {
    get(key: string): Permission[] | undefined {
      const entry = store.get(key);
      if (!entry)
        return undefined;
      if (Date.now() > entry.expiresAt) {
        store.delete(key);
        return undefined;
      }
      return entry.permissions;
    },

    set(key: string, permissions: Permission[]): void {
      // Evict oldest entry if at capacity
      if (store.size >= maxEntries && !store.has(key)) {
        const oldest = store.keys().next().value;
        if (oldest !== undefined)
          store.delete(oldest);
      }
      store.set(key, { permissions, expiresAt: Date.now() + ttlMs });
    },

    invalidate(key: string): void {
      store.delete(key);
      generation++;
    },

    invalidateAll(): void {
      store.clear();
      generation++;
    },

    generation(): number {
      return generation;
    },
  };
}
