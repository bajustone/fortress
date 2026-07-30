import type {
  DatabaseAdapter,
  Subject,
  TokenClaims,
} from '@bajustone/fortress';
import type { ExpressMiddleware } from '@bajustone/fortress/express';
import { createFortress } from '@bajustone/fortress';
import {
  createExpressMiddleware,
  getClaims,
  getDb,
  getSubject,
  getUserId,
  mountFortress,
} from '@bajustone/fortress/express';
import express4 from 'express4';

/**
 * Built-package declaration contract for a real Express 4 application. The
 * fixture-specific tsconfig resolves `express4` to @types/express 4 and gives
 * its nested express-serve-static-core v4 precedence over ambient v5.
 */
export function express4QuickstartContract(database: DatabaseAdapter): express4.Application {
  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
  });

  const app: express4.Application = express4();
  app.use(express4.json());
  app.use(express4.urlencoded({ extended: false }));
  mountFortress(app, fortress, { prefix: '/api' });

  const { authMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress, {
    routeMap: { 'GET /posts': { resource: 'post', action: 'read' } },
    unmappedRoutes: 'deny',
  });
  const authHandler: express4.RequestHandler = authMiddleware;
  const fortressMiddleware: ExpressMiddleware = authMiddleware;

  app.use('/posts', authHandler, rbacMiddleware);
  app.get('/posts', (req: express4.Request, res: express4.Response) => {
    const subject: Subject = getSubject(req);
    const userId: string = getUserId(req);
    const claims: TokenClaims = getClaims(req);
    const requestDatabase: DatabaseAdapter = getDb(req);
    void [userId, claims, requestDatabase];
    return res.status(200).json({ subject });
  });
  app.use(errorHandler);

  // Stable negative sentinels: declaration degradation to `any` makes these
  // directives unused and therefore fails the contract.
  // @ts-expect-error mountFortress requires a host with Express-compatible use()
  mountFortress({}, fortress);
  // @ts-expect-error getSubject requires an Express request shape
  getSubject({ status: 200 });

  void fortressMiddleware;
  return app;
}
