import type { DatabaseAdapter } from '@bajustone/fortress';
import type { ExpressMiddleware } from '@bajustone/fortress/express';
import { createFortress } from '@bajustone/fortress';
import {
  createExpressMiddleware,
  getSubject,
  mountFortress,
} from '@bajustone/fortress/express';
import express from 'express';

/**
 * Compiles the README Express quickstart against public source entrypoints and
 * generated package declarations. Keep this aligned with README.md's Express block.
 */
export function express5QuickstartContract(database: DatabaseAdapter): void {
  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
  });

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  mountFortress(app, fortress, { prefix: '/api' });

  const { authMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress, {
    routeMap: { 'GET /posts': { resource: 'post', action: 'read' } },
    unmappedRoutes: 'deny',
  });

  app.use('/posts', authMiddleware, rbacMiddleware);
  app.get('/posts', (req, res) => res.json({ subject: getSubject(req) }));
  app.use(errorHandler);
}

/** Both public surfaces intentionally retain support for lightweight hosts. */
export function lightweightExpressAppContract(database: DatabaseAdapter): void {
  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
  });
  let registeredMiddleware: ExpressMiddleware | undefined;
  const app = {
    use(middleware: ExpressMiddleware): void {
      registeredMiddleware = middleware;
    },
  };

  mountFortress(app, fortress);
  void registeredMiddleware;
}
