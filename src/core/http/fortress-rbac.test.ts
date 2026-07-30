import type { EndpointDefinition } from '../endpoint';
import { describe, expect, it, vi } from 'vitest';
import { enforceFortressPermission } from './fortress-rbac';

function endpoint(security: NonNullable<EndpointDefinition['meta']>['security']): EndpointDefinition {
  return {
    method: 'GET',
    path: '/billing',
    handler: 'billing',
    input: {},
    responses: {},
    meta: {
      summary: 'Billing',
      security,
      permission: { resource: 'billing', action: 'read' },
    },
  };
}

function transportOnlyEndpoint(
  security: NonNullable<EndpointDefinition['meta']>['security'],
): EndpointDefinition {
  return {
    method: 'GET',
    path: '/billing',
    handler: 'billing',
    input: {},
    responses: {},
    meta: { summary: 'Billing', security },
  };
}

describe('enforceFortressPermission', () => {
  it('denies a Basic route that declares no permission', async () => {
    // Fortress has no Basic verifier, so `basic` alone is not proof of
    // authentication. Route assembly rejects this at construction; reaching
    // the enforcer directly must still fail closed rather than pass through.
    const checkPermission = vi.fn(async () => true);

    await expect(enforceFortressPermission(
      transportOnlyEndpoint(['basic']),
      { type: 'USER', id: '1' },
      { checkPermission },
    )).rejects.toMatchObject({ code: 'FORBIDDEN', statusCode: 403 });
    expect(checkPermission).not.toHaveBeenCalled();
  });

  it('denies a permissionless Basic route even with no subject', async () => {
    await expect(enforceFortressPermission(
      transportOnlyEndpoint(['basic']),
      undefined,
      { checkPermission: vi.fn(async () => true) },
    )).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('still passes through a route declaring security:[\'none\']', async () => {
    await expect(enforceFortressPermission(
      transportOnlyEndpoint(['none']),
      undefined,
      { checkPermission: vi.fn(async () => false) },
    )).resolves.toBeUndefined();
  });

  it('enforces permission before basic transport metadata', async () => {
    const checkPermission = vi.fn(async () => false);
    await expect(enforceFortressPermission(
      endpoint(['basic']),
      { type: 'USER', id: '1' },
      { checkPermission },
    )).rejects.toMatchObject({
      code: 'FORBIDDEN',
      statusCode: 403,
      message: 'Insufficient permissions',
      details: { requiredPermission: 'billing:read' },
    });
    expect(checkPermission).toHaveBeenCalledWith(
      { type: 'USER', id: '1' },
      'billing',
      'read',
      undefined,
    );
  });

  it('requires a subject for api-key permission routes', async () => {
    await expect(enforceFortressPermission(
      endpoint(['apiKey']),
      undefined,
      { checkPermission: async () => true },
    )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });
});
