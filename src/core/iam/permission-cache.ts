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
  generation: (key: string) => string;
  /** Returns false when invalidation occurred after the caller's read began. */
  set: (key: string, permissions: Permission[], expectedGeneration?: string) => boolean;
  invalidate: (key: string) => void;
  invalidateAll: () => void;
}

export function createPermissionCache(ttlMs: number, maxEntries: number): PermissionCache {
  const store = new Map<string, CacheEntry>();
  let generationCounter = 0;
  // A single monotonic generation avoids unbounded per-subject metadata.
  // Per-key invalidation may conservatively reject unrelated in-flight writes,
  // while leaving their already-cached entries intact.
  const generation = (_key: string): string => String(generationCounter);

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

    generation,

    set(key: string, permissions: Permission[], expectedGeneration?: string): boolean {
      if (expectedGeneration !== undefined && expectedGeneration !== generation(key))
        return false;
      // Evict oldest entry if at capacity
      if (store.size >= maxEntries && !store.has(key)) {
        const oldest = store.keys().next().value;
        if (oldest !== undefined)
          store.delete(oldest);
      }
      store.set(key, { permissions, expiresAt: Date.now() + ttlMs });
      return true;
    },

    invalidate(key: string): void {
      store.delete(key);
      generationCounter++;
    },

    invalidateAll(): void {
      store.clear();
      generationCounter++;
    },
  };
}
