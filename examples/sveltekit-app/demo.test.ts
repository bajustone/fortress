import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { demoSeedPromise, fortress } from './src/lib/server/fortress';

const readme = readFileSync(new URL('./README.md', import.meta.url), 'utf8');
const documentedPassword = readme.match(/`alice@example\.com` \/ `([^`]+)`/)?.[1];

describe('svelteKit demo configuration', () => {
  it('creates and authenticates the documented demo user', async () => {
    await demoSeedPromise;

    if (!documentedPassword)
      throw new Error('SvelteKit README must document the seeded demo credentials');
    const result = await fortress.auth.login('alice@example.com', documentedPassword);

    expect(result.user.email).toBe('alice@example.com');
  });

  it('opts out of secure cookies explicitly for local HTTP', () => {
    expect(fortress.cookies.secure).toBe(false);
    expect(fortress.cookies.accessName).toBe('fortress_access');
  });
});
