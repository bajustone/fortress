import { afterEach, describe, expect, it } from 'vitest';
import { loadPolicy, parsePolicyDocument, resolvePolicyPath } from './loader';

const tempDirs: string[] = [];
const sparseArray: unknown[] = [];
sparseArray.length = 1;

afterEach(async () => {
  const { rm } = await import('node:fs/promises');
  await Promise.all(tempDirs.splice(0).map(dir => rm(dir, { recursive: true, force: true })));
});

describe('policy loader', () => {
  it('loads an env-specific file asynchronously and validates it', async () => {
    const { mkdtemp, writeFile } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const cwd = await mkdtemp(join(tmpdir(), 'fortress-policy-'));
    tempDirs.push(cwd);
    await writeFile(join(cwd, 'fortress.policy.json'), JSON.stringify({ groups: [{ name: 'base' }] }));
    await writeFile(join(cwd, 'fortress.policy.production.json'), JSON.stringify({
      roles: [{ name: 'reader', permissions: [{ resource: 'article', action: 'read' }] }],
    }));

    expect(await resolvePolicyPath({ cwd, env: 'production' }))
      .toBe(join(cwd, 'fortress.policy.production.json'));
    const { policy } = await loadPolicy({ cwd, env: 'production' });
    expect(requireAt(requireValue(policy.roles, 'policy roles'), 0, 'reader policy role').name).toBe('reader');
  });

  it('allows annotations and deduplicates equivalent ALLOW permissions', () => {
    const policy = parsePolicyDocument({
      $comment: 'documented annotation',
      roles: [{
        name: 'reader',
        permissions: [
          { resource: 'article', action: 'read' },
          { resource: 'article', action: 'read', effect: 'ALLOW' },
        ],
      }],
    });
    expect(requireAt(requireValue(policy.roles, 'policy roles'), 0, 'reader policy role').permissions).toEqual([
      { resource: 'article', action: 'read' },
    ]);
  });

  it.each([
    [null, 'must be an object'],
    [[], 'must be an object'],
    [{ groups: sparseArray }, 'dense array of objects'],
    [{ unknown: [] }, 'Unknown policy field'],
    [{ $comment: 1 }, '$comment must be a string'],
    [{ $schema: false }, '$schema must be a string'],
    [{ roles: [{ name: 'x' }] }, 'permissions must be an array'],
    [{ roles: [{ name: 'x', permissions: [{ resource: 'r', action: 'a', effect: 'MAYBE' }] }] }, 'effect must be ALLOW or DENY'],
    [{ groups: [{ name: 'x' }, { name: 'x' }] }, 'duplicate name'],
    [{ serviceAccounts: [{ name: 'bot', roles: 'reader' }] }, 'roles must be an array'],
    [{ roles: [{ name: 'x', permissions: [{ resource: 'r', action: 'a', effectt: 'DENY' }] }] }, 'Unknown field'],
    [{ groups: [{ name: 'x', descriptino: 'typo' }] }, 'Unknown field'],
  ])('rejects malformed policy documents', (value, message) => {
    expect(() => parsePolicyDocument(value)).toThrow(message);
  });
});
function requireValue<T>(value: T | undefined, description: string): T {
  if (value === undefined)
    throw new Error(`Expected ${description}`);
  return value;
}

function requireAt<T>(values: readonly T[], index: number, description: string): T {
  return requireValue(values[index], description);
}
