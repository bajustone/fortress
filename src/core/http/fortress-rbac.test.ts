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

describe('enforceFortressPermission', () => {
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
