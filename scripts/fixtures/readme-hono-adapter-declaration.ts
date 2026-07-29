import type { DatabaseAdapter } from '@bajustone/fortress';
import { createFortress } from '@bajustone/fortress';
import {
  createHonoMiddleware,
  createSecurityHeadersMiddleware,
  getSubject,
  mountFortress,
} from '@bajustone/fortress/hono';
import { Hono } from 'hono';

/**
 * Compiles README.md's full Hono adapter block against both public surfaces.
 * Keep the adapter usage below aligned with the documented snippet.
 */
export function honoAdapterQuickstartContract(database: DatabaseAdapter): void {
  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
  });

  const app = new Hono();
  mountFortress(app, fortress, { prefix: '/api' });

  const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
    routeMap: {
      'GET /posts': { resource: 'post', action: 'read' },
      'POST /posts': { resource: 'post', action: 'create' },
    },
    unmappedRoutes: 'deny',
    skipPaths: ['/health'],
  });

  app.onError(errorHandler);
  app.use('/posts/*', authMiddleware, rbacMiddleware);
  app.get('/posts', c => c.json({ subject: getSubject(c) }));
  app.use('*', createSecurityHeadersMiddleware());
}
