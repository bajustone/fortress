import type { Permission } from '../types';

interface CacheEntry {
  permissions: Permission[];
  expiresAt: number;
}

export interface PermissionCache {
  get: (userId: number) => Permission[] | undefined;
  set: (userId: number, permissions: Permission[]) => void;
  invalidate: (userId: number) => void;
  invalidateAll: () => void;
}

export function createPermissionCache(ttlMs: number, maxEntries: number): PermissionCache {
  const store = new Map<number, CacheEntry>();

  return {
    get(userId: number): Permission[] | undefined {
      const entry = store.get(userId);
      if (!entry)
        return undefined;
      if (Date.now() > entry.expiresAt) {
        store.delete(userId);
        return undefined;
      }
      return entry.permissions;
    },

    set(userId: number, permissions: Permission[]): void {
      // Evict oldest entry if at capacity
      if (store.size >= maxEntries && !store.has(userId)) {
        const oldest = store.keys().next().value;
        if (oldest !== undefined)
          store.delete(oldest);
      }
      store.set(userId, { permissions, expiresAt: Date.now() + ttlMs });
    },

    invalidate(userId: number): void {
      store.delete(userId);
    },

    invalidateAll(): void {
      store.clear();
    },
  };
}
