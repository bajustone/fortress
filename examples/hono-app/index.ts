/**
 * Example Hono app using Fortress
 *
 * This serves as both an E2E test and documentation for how to use Fortress.
 *
 * Run: bun run dev
 * Or:  bun run examples/hono-app/index.ts
 */

// TODO: Uncomment and implement once core is built
//
// import { Hono } from 'hono';
// import { createFortress, Errors } from '@bajustone/fortress';
// import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
// import { createHonoMiddleware } from '@bajustone/fortress/hono';
//
// const app = new Hono();
//
// // 1. Create Fortress instance
// const fortress = createFortress({
//   jwt: { secret: 'dev-secret-change-me' },
//   database: createDrizzleAdapter(db),
// });
//
// // 2. Get middleware
// const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
//   routeMap: {
//     'POST /api/users': { resource: 'user', action: 'create' },
//     'GET /api/users': { resource: 'user', action: 'list' },
//     'GET /api/users/:id': { resource: 'user', action: 'read' },
//   },
//   skipPaths: ['/health', '/auth/*'],
// });
//
// // 3. Wire middleware
// app.use('*', errorHandler);
// app.use('/api/*', authMiddleware);
// app.use('/api/*', rbacMiddleware);
//
// // 4. Routes
// app.get('/health', (c) => c.json({ status: 'ok' }));
//
// app.post('/auth/login', async (c) => {
//   const { identifier, password } = await c.req.json();
//   const result = await fortress.auth.login(identifier, password, {
//     ipAddress: c.req.header('x-forwarded-for'),
//     userAgent: c.req.header('user-agent'),
//   });
//   return c.json({ data: result });
// });
//
// app.post('/auth/refresh', async (c) => {
//   const { refreshToken } = await c.req.json();
//   const result = await fortress.auth.refresh(refreshToken);
//   return c.json({ data: result });
// });
//
// app.get('/api/users', async (c) => {
//   return c.json({ data: [] }); // TODO
// });
//
// export default {
//   port: 3000,
//   fetch: app.fetch,
// };

// eslint-disable-next-line no-console
console.log('Example app placeholder — implement once core is built');
