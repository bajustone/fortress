/* eslint-disable no-template-curly-in-string -- tests use ${variable} syntax intentionally */
import type { Permission } from '../types';

import { describe, expect, it } from 'vitest';
import { evaluateConditions, evaluatePermissions } from './permission-evaluator';

function perm(overrides: Partial<Permission> = {}): Permission {
  return {
    id: 1,
    resource: 'post',
    action: 'update',
    effect: 'ALLOW',
    ...overrides,
  };
}

describe('evaluatePermissions', () => {
  describe('allow-only mode', () => {
    it('returns false when no permissions match', () => {
      const result = evaluatePermissions(
        [perm({ resource: 'user', action: 'read' })],
        'post',
        'update',
        'allow-only',
      );
      expect(result).toBe(false);
    });

    it('returns true when an ALLOW permission matches', () => {
      const result = evaluatePermissions(
        [perm()],
        'post',
        'update',
        'allow-only',
      );
      expect(result).toBe(true);
    });

    it('returns false when empty permissions', () => {
      expect(evaluatePermissions([], 'post', 'update', 'allow-only')).toBe(false);
    });

    it('ignores DENY permissions in allow-only mode', () => {
      const result = evaluatePermissions(
        [perm({ effect: 'DENY' }), perm({ id: 2, effect: 'ALLOW' })],
        'post',
        'update',
        'allow-only',
      );
      expect(result).toBe(true);
    });
  });

  describe('deny-overrides mode', () => {
    it('denies if any DENY matches even with ALLOW present', () => {
      const result = evaluatePermissions(
        [perm({ effect: 'ALLOW' }), perm({ id: 2, effect: 'DENY' })],
        'post',
        'update',
        'deny-overrides',
      );
      expect(result).toBe(false);
    });

    it('allows if only ALLOW matches', () => {
      const result = evaluatePermissions(
        [perm({ effect: 'ALLOW' })],
        'post',
        'update',
        'deny-overrides',
      );
      expect(result).toBe(true);
    });

    it('denies if no matching permissions', () => {
      expect(evaluatePermissions([], 'post', 'update', 'deny-overrides')).toBe(false);
    });
  });

  describe('with conditions', () => {
    it('allows when condition is met', () => {
      const result = evaluatePermissions(
        [perm({
          conditions: [{ field: 'resource.ownerId', operator: 'eq', value: '42' }],
        })],
        'post',
        'update',
        'allow-only',
        { resource: { ownerId: 42 } },
      );
      expect(result).toBe(true);
    });

    it('denies when condition is not met', () => {
      const result = evaluatePermissions(
        [perm({
          conditions: [{ field: 'resource.ownerId', operator: 'eq', value: '42' }],
        })],
        'post',
        'update',
        'allow-only',
        { resource: { ownerId: 99 } },
      );
      expect(result).toBe(false);
    });

    it('denies when no context provided but conditions exist', () => {
      const result = evaluatePermissions(
        [perm({
          conditions: [{ field: 'resource.ownerId', operator: 'eq', value: '42' }],
        })],
        'post',
        'update',
        'allow-only',
      );
      expect(result).toBe(false);
    });

    it('supports ${user.id} variable in conditions', () => {
      const result = evaluatePermissions(
        [perm({
          conditions: [{ field: 'resource.ownerId', operator: 'eq', value: '${user.id}' }],
        })],
        'post',
        'update',
        'allow-only',
        { resource: { ownerId: 42 }, user: { id: 42 } },
      );
      expect(result).toBe(true);
    });

    it('${user.id} variable mismatch denies', () => {
      const result = evaluatePermissions(
        [perm({
          conditions: [{ field: 'resource.ownerId', operator: 'eq', value: '${user.id}' }],
        })],
        'post',
        'update',
        'allow-only',
        { resource: { ownerId: 42 }, user: { id: 99 } },
      );
      expect(result).toBe(false);
    });
  });
});

describe('evaluateConditions', () => {
  it('supports neq operator', () => {
    const result = evaluateConditions(
      [{ field: 'resource.status', operator: 'neq', value: 'archived' }],
      { resource: { status: 'published' } },
    );
    expect(result).toBe(true);
  });

  it('supports in operator', () => {
    const result = evaluateConditions(
      [{ field: 'resource.status', operator: 'in', value: ['draft', 'published'] }],
      { resource: { status: 'published' } },
    );
    expect(result).toBe(true);
  });

  it('in operator denies when value not in list', () => {
    const result = evaluateConditions(
      [{ field: 'resource.status', operator: 'in', value: ['draft', 'published'] }],
      { resource: { status: 'archived' } },
    );
    expect(result).toBe(false);
  });

  it('supports startsWith operator', () => {
    const result = evaluateConditions(
      [{ field: 'request.ip', operator: 'startsWith', value: '192.168.' }],
      { request: { ip: '192.168.1.100' } },
    );
    expect(result).toBe(true);
  });

  it('all conditions must be true (AND logic)', () => {
    const result = evaluateConditions(
      [
        { field: 'resource.ownerId', operator: 'eq', value: '${user.id}' },
        { field: 'resource.status', operator: 'neq', value: 'archived' },
      ],
      { resource: { ownerId: 42, status: 'published' }, user: { id: 42 } },
    );
    expect(result).toBe(true);
  });

  it('fails if any condition is false', () => {
    const result = evaluateConditions(
      [
        { field: 'resource.ownerId', operator: 'eq', value: '${user.id}' },
        { field: 'resource.status', operator: 'neq', value: 'archived' },
      ],
      { resource: { ownerId: 42, status: 'archived' }, user: { id: 42 } },
    );
    expect(result).toBe(false);
  });
});
