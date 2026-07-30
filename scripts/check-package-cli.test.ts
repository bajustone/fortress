import { describe, expect, it } from 'vitest';
import { normalizePackManifest } from './publication-files.mjs';

// Recorded from a real `npm pack . --json` of this package. npm 11 wraps the
// manifest in an array; npm 12 keys it by package name.
function manifest(): Record<string, unknown> {
  return {
    id: '@bajustone/fortress@2.0.0',
    name: '@bajustone/fortress',
    version: '2.0.0',
    size: 1401821,
    unpackedSize: 6104711,
    shasum: 'b27eda05e599e757871e19301482a3f30c2ad068',
    integrity: 'sha512-qKAxJc6Wv1ZOFhRbyg0LLmgWBGKC/+ecFxjXRs9d6V73plPyGZcMGrQe4lrBfBEaRa/bDw3vdvrfwh+fjn3o9A==',
    filename: 'bajustone-fortress-2.0.0.tgz',
    files: [
      { path: 'CHANGELOG.md', size: 115153, mode: 420 },
      { path: 'dist/index.d.cts', size: 58368, mode: 420 },
    ],
    entryCount: 385,
    bundled: [],
  };
}

const npm11 = (): unknown => [manifest()];
const npm12 = (): unknown => ({ '@bajustone/fortress': manifest() });

describe('normalizePackManifest', () => {
  it('reads the npm 11 array shape', () => {
    expect(normalizePackManifest(npm11())).toEqual(manifest());
  });

  it('reads the npm 12 package-name-keyed shape', () => {
    expect(normalizePackManifest(npm12())).toEqual(manifest());
  });

  it('resolves both shapes to the same manifest', () => {
    expect(normalizePackManifest(npm11())).toEqual(normalizePackManifest(npm12()));
  });

  it('rejects a result that does not describe exactly one package', () => {
    expect(() => normalizePackManifest([])).toThrow('returned 0 manifests');
    expect(() => normalizePackManifest({})).toThrow('returned 0 manifests');
    expect(() => normalizePackManifest([manifest(), manifest()])).toThrow('returned 2 manifests');
    expect(() => normalizePackManifest({
      '@bajustone/fortress': manifest(),
      '@bajustone/other': manifest(),
    })).toThrow('returned 2 manifests');
  });

  it('rejects output that is not a manifest container', () => {
    for (const value of [null, undefined, 'bajustone-fortress-2.0.0.tgz', 42, true])
      expect(() => normalizePackManifest(value)).toThrow('neither a manifest array nor a keyed manifest object');
  });

  it('rejects a manifest reached only through the prototype chain', () => {
    const inherited = Object.create({ '@bajustone/fortress': manifest() });
    expect(() => normalizePackManifest(inherited))
      .toThrow('neither a manifest array nor a keyed manifest object');
  });

  it('rejects a manifest smuggled under a __proto__ key', () => {
    const poisoned: unknown = JSON.parse(`{"__proto__": ${JSON.stringify(manifest())}}`);
    expect(() => normalizePackManifest(poisoned)).toThrow('describes package "@bajustone/fortress"');
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
  });

  it('rejects a keyed manifest whose key contradicts the packed package', () => {
    expect(() => normalizePackManifest({ '@bajustone/other': manifest() }))
      .toThrow('describes package "@bajustone/fortress"');
  });

  it('rejects manifests missing the fields the publication policy reads', () => {
    expect(() => normalizePackManifest([{ ...manifest(), name: '' }])).toThrow('has no package name');
    expect(() => normalizePackManifest([{ ...manifest(), name: 7 }])).toThrow('has no package name');
    expect(() => normalizePackManifest([{ ...manifest(), filename: '' }])).toThrow('has no tarball filename');
    expect(() => normalizePackManifest([{ ...manifest(), filename: null }])).toThrow('has no tarball filename');
    expect(() => normalizePackManifest([{ ...manifest(), files: undefined }])).toThrow('has no file list');
    expect(() => normalizePackManifest([{ ...manifest(), files: 'CHANGELOG.md' }])).toThrow('has no file list');
  });

  it('rejects a file list entry without a usable path', () => {
    for (const file of [{ size: 1 }, { path: '' }, { path: 12 }, 'CHANGELOG.md', null]) {
      expect(() => normalizePackManifest([{ ...manifest(), files: [file] }]))
        .toThrow('lists a file without a path');
    }
  });

  it('rejects a non-object manifest inside a valid container', () => {
    expect(() => normalizePackManifest([null])).toThrow('is not an object manifest');
    expect(() => normalizePackManifest({ '@bajustone/fortress': 'tarball' }))
      .toThrow('is not an object manifest');
  });
});
