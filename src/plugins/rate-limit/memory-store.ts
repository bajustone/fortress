export interface RateLimitStore {
  /** Increment the counter for a key within a sliding window. Returns current count and reset time. */
  increment: (key: string, windowMs: number) => Promise<{ count: number; resetAt: number }>;
  /** Get the current counter for a key. Returns null if no record exists. */
  get: (key: string) => Promise<{ count: number; resetAt: number } | null>;
}

/**
 * In-memory sliding window rate limit store.
 * Stores timestamps of each request per key and prunes expired entries.
 */
export function createMemoryStore(): RateLimitStore {
  const store = new Map<string, number[]>();

  // Prune expired entries every 60 seconds
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, timestamps] of store) {
      // Keep only entries that could still be within any reasonable window (max 1 hour)
      const filtered = timestamps.filter(t => now - t < 3_600_000);
      if (filtered.length === 0) {
        store.delete(key);
      }
      else {
        store.set(key, filtered);
      }
    }
  }, 60_000);

  // Allow the process to exit even if the interval is active (Node/Bun)
  if (typeof cleanupInterval === 'object' && 'unref' in cleanupInterval) {
    (cleanupInterval as { unref: () => void }).unref();
  }

  return {
    async increment(key: string, windowMs: number): Promise<{ count: number; resetAt: number }> {
      const now = Date.now();
      const windowStart = now - windowMs;

      const existing = store.get(key) ?? [];
      const filtered = existing.filter(t => t > windowStart);
      filtered.push(now);
      store.set(key, filtered);

      // resetAt = when the oldest entry in the window will expire
      const resetAt = filtered[0] + windowMs;

      return { count: filtered.length, resetAt };
    },

    async get(key: string): Promise<{ count: number; resetAt: number } | null> {
      const timestamps = store.get(key);
      if (!timestamps || timestamps.length === 0)
        return null;

      // We don't know the window here, so return the count as-is
      // The caller knows the window and can filter
      return { count: timestamps.length, resetAt: timestamps[0] };
    },
  };
}
