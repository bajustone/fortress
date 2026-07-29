export interface RateLimitStore {
  /** Increment the counter for a key within a sliding window. Returns current count and reset time. */
  increment: (key: string, windowMs: number) => Promise<{ count: number; resetAt: number }>;
  /** Get the current counter for the most recently used window. */
  get: (key: string) => Promise<{ count: number; resetAt: number } | null>;
}

interface WindowRecord {
  /** Retained for the largest window ever used by this key. */
  timestamps: number[];
  maxWindowMs: number;
  lastWindowMs: number;
}

function oldestActiveTimestamp(timestamps: readonly number[]): number {
  const [oldest] = timestamps;
  if (oldest === undefined)
    throw new Error('Rate-limit store invariant violated: active window has no oldest timestamp');
  return oldest;
}

/** In-memory sliding-window store with per-key retention. */
export function createMemoryStore(): RateLimitStore {
  const store = new Map<string, WindowRecord>();

  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, record] of store) {
      const timestamps = record.timestamps.filter(timestamp => now - timestamp < record.maxWindowMs);
      if (timestamps.length === 0)
        store.delete(key);
      else
        store.set(key, { ...record, timestamps });
    }
  }, 60_000);

  if (typeof cleanupInterval === 'object' && 'unref' in cleanupInterval)
    (cleanupInterval as { unref: () => void }).unref();

  return {
    async increment(key: string, windowMs: number): Promise<{ count: number; resetAt: number }> {
      const now = Date.now();
      const existing = store.get(key);
      const maxWindowMs = Math.max(existing?.maxWindowMs ?? 0, windowMs);
      const retained = (existing?.timestamps ?? [])
        .filter(timestamp => timestamp > now - maxWindowMs);
      retained.push(now);
      store.set(key, { timestamps: retained, maxWindowMs, lastWindowMs: windowMs });

      const active = retained.filter(timestamp => timestamp > now - windowMs);
      return { count: active.length, resetAt: oldestActiveTimestamp(active) + windowMs };
    },

    async get(key: string): Promise<{ count: number; resetAt: number } | null> {
      const record = store.get(key);
      if (!record)
        return null;
      const now = Date.now();
      const active = record.timestamps.filter(timestamp => timestamp > now - record.lastWindowMs);
      if (active.length === 0)
        return null;
      return {
        count: active.length,
        resetAt: oldestActiveTimestamp(active) + record.lastWindowMs,
      };
    },
  };
}
