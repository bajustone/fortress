import type { EndpointDefinition } from '../endpoint';
import { describe, expect, it } from 'vitest';
import { buildRouteTable, matchRoute } from './match';

function ep(method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH', path: string, handler: string): EndpointDefinition {
  return {
    method,
    path,
    handler,
  };
}

describe('matchRoute', () => {
  const table = buildRouteTable([
    ep('GET', '/auth/me', 'me'),
    ep('POST', '/auth/login', 'login'),
    ep('GET', '/iam/roles', 'getRoles'),
    ep('POST', '/iam/roles', 'createRole'),
    ep('DELETE', '/iam/roles/:id', 'deleteRole'),
    ep('GET', '/iam/users/:id/permissions', 'getUserPermissions'),
    ep('DELETE', '/iam/groups/:id/users/:userId', 'removeUserFromGroup'),
  ]);

  it('matches an exact static route', () => {
    const m = matchRoute(table, 'GET', '/auth/me');
    expect(m?.endpoint.handler).toBe('me');
    expect(m?.params).toEqual({});
  });

  it('respects HTTP method', () => {
    expect(matchRoute(table, 'POST', '/auth/me')).toBeNull();
    expect(matchRoute(table, 'GET', '/iam/roles')?.endpoint.handler).toBe('getRoles');
    expect(matchRoute(table, 'POST', '/iam/roles')?.endpoint.handler).toBe('createRole');
  });

  it('extracts a single path param', () => {
    const m = matchRoute(table, 'DELETE', '/iam/roles/42');
    expect(m?.endpoint.handler).toBe('deleteRole');
    expect(m?.params).toEqual({ id: '42' });
  });

  it('extracts multiple path params', () => {
    const m = matchRoute(table, 'DELETE', '/iam/groups/3/users/7');
    expect(m?.endpoint.handler).toBe('removeUserFromGroup');
    expect(m?.params).toEqual({ id: '3', userId: '7' });
  });

  it('returns null when segment counts differ', () => {
    expect(matchRoute(table, 'GET', '/iam/roles/extra')).toBeNull();
  });

  it('returns null when no route matches', () => {
    expect(matchRoute(table, 'GET', '/nope')).toBeNull();
  });

  it('case-insensitive on method', () => {
    expect(matchRoute(table, 'get', '/auth/me')?.endpoint.handler).toBe('me');
  });

  it('url-decodes path param values', () => {
    const m = matchRoute(table, 'GET', '/iam/users/hello%20world/permissions');
    expect(m?.params.id).toBe('hello world');
  });

  it.each([
    [
      [
        ep('GET', '/users/:id', 'param'),
        ep('GET', '/users/me', 'static'),
      ],
      'static',
    ],
    [
      [
        ep('GET', '/users/me', 'static'),
        ep('GET', '/users/:id', 'param'),
      ],
      'static',
    ],
  ] as const)('prefers /users/me over /users/:id regardless of registration order', (routes, handler) => {
    const m = matchRoute(buildRouteTable(routes), 'GET', '/users/me');
    expect(m?.endpoint.handler).toBe(handler);
    expect(m?.params).toEqual({});
  });

  it.each([
    [
      [
        ep('GET', '/users/*', 'wildcard'),
        ep('GET', '/users/:id', 'param'),
        ep('GET', '/users/me', 'static'),
      ],
      'static',
      '/users/me',
      {},
    ],
    [
      [
        ep('GET', '/users/me', 'static'),
        ep('GET', '/users/*', 'wildcard'),
        ep('GET', '/users/:id', 'param'),
      ],
      'param',
      '/users/alice',
      { id: 'alice' },
    ],
    [
      [
        ep('GET', '/accounts/:id', 'param'),
        ep('GET', '/users/me', 'static'),
        ep('GET', '/users/*', 'wildcard'),
      ],
      'wildcard',
      '/users/alice',
      {},
    ],
  ] as const)('uses static, param, then wildcard precedence deterministically', (routes, handler, path, params) => {
    const m = matchRoute(buildRouteTable(routes), 'GET', path);
    expect(m?.endpoint.handler).toBe(handler);
    expect(m?.params).toEqual(params);
  });
});
