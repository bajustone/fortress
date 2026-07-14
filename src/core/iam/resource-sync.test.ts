import { describe, expect, it } from 'vitest';

import { generateResourceTypes, parseResourceFile } from './resource-sync';

describe('parseResourceFile', () => {
  it('accepts the canonical map shape and deduplicates actions', () => {
    expect(parseResourceFile({
      $schema: 'ignored annotation',
      resources: { article: { actions: ['read', 'read'], description: 'Articles' } },
    })).toEqual({
      resources: { article: { actions: ['read'], description: 'Articles' } },
    });
  });

  it.each([
    [null, 'must be an object'],
    [{ resources: [] }, 'legacy resources array'],
    [{ resources: { article: { actions: 'read' } } }, 'actions must be an array'],
    [{ resources: { article: { actions: ['read', 1] } } }, 'actions must be an array'],
    [{ resources: { article: { actions: [], description: 1 } } }, 'description must be a string'],
    [JSON.parse('{"resources":{"__proto__":{"actions":["read"]}}}'), 'reserved or empty'],
  ])('rejects malformed resource documents', (value, message) => {
    expect(() => parseResourceFile(value)).toThrow(message);
  });
});

describe('generateResourceTypes', () => {
  it('generates TypeScript types from resource definitions', () => {
    const types = generateResourceTypes({
      resources: {
        user: { actions: ['create', 'read', 'update', 'delete'] },
        post: { actions: ['create', 'read', 'publish'] },
      },
    });

    expect(types).toContain('"user"');
    expect(types).toContain('"post"');
    expect(types).toContain('"create" | "read" | "update" | "delete"');
    expect(types).toContain('"create" | "read" | "publish"');
    expect(types).toContain('FortressResource');
    expect(types).toContain('FortressAction');
  });

  it('handles empty resources', () => {
    const types = generateResourceTypes({ resources: {} });
    expect(types).toContain('never');
  });

  it('escapes resource/action literals and handles empty action sets', () => {
    const types = generateResourceTypes({
      resources: {
        'blog-post': { actions: [] },
        'quoted': { actions: ['read\'quote'] },
      },
    });
    expect(types).toContain('R extends "blog-post" ? never');
    expect(types).toContain('"read\'quote"');
  });

  it('handles single resource', () => {
    const types = generateResourceTypes({
      resources: {
        invoice: { actions: ['create', 'void'] },
      },
    });

    expect(types).toContain('"invoice"');
    expect(types).toContain('"create" | "void"');
  });
});
