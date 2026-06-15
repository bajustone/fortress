/**
 * Login timing-oracle regression test.
 *
 * Background: an earlier implementation used a hard-coded malformed Argon2 PHC
 * string as the dummy hash for the "user not found / no password" branch in
 * `login()`. `hash-wasm`'s parser threw before running the KDF, so that branch
 * completed in ~0.3ms while a real password verify took ~50-200ms. The gap
 * allowed user enumeration over the network.
 *
 * This test asserts the two branches are within the same order of magnitude
 * so the dummy hash continues to be a *real* Argon2 hash (i.e. the verify
 * actually runs the KDF). It is intentionally generous: Argon2 timings vary
 * across runtimes, but a malformed dummy regresses by ~100x which this
 * threshold catches reliably without false positives.
 */

import type { Fortress } from '../fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'login-timing-test-secret-32chars!!';
const PASSWORD = 'password-123';
const EMAIL = 'timing@example.com';

let fortress: Fortress;

async function timeFailedLogin(identifier: string): Promise<number> {
  const start = performance.now();
  try {
    await fortress.auth.login(identifier, 'definitely-not-the-password');
  }
  catch {
    /* expected */
  }
  return performance.now() - start;
}

async function median(samples: number[]): Promise<number> {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

describe('login timing-oracle defense', () => {
  beforeEach(async () => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
    await fortress.auth.createUser({
      email: EMAIL,
      name: 'Timing User',
      password: PASSWORD,
    });
    // Warm the lazy dummy hash so the *first* miss isn't unfairly slow.
    await timeFailedLogin('missing@example.com');
  });

  it('user-not-found branch takes a real Argon2-verify amount of time', async () => {
    const N = 5;
    const missSamples: number[] = [];
    const hitSamples: number[] = [];
    for (let i = 0; i < N; i++) {
      missSamples.push(await timeFailedLogin(`ghost-${i}@example.com`));
      hitSamples.push(await timeFailedLogin(EMAIL));
    }

    const missMedian = await median(missSamples);
    const hitMedian = await median(hitSamples);

    // Both branches should perform a real Argon2 verify. We require the miss
    // branch to be at least ~30% of the hit branch's wall-clock time. The
    // malformed-dummy regression produced a ~300x gap, so this catches it
    // with comfortable margin while tolerating GC / jitter noise.
    expect(missMedian).toBeGreaterThan(hitMedian * 0.3);
  });
});
