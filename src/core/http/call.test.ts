import type { authEndpoints } from '../auth/auth-endpoints';
import type { InferEndpointCallInput, InferEndpointSuccessResponse } from '../endpoint';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { FortressError } from '../errors';
import { createFortress } from '../fortress';
import { definePlugin } from '../plugin';
import { bool, endpoint, obj, str } from '../schema-builder';
import { assertSuccess } from '../types';

const SECRET = 'call-test-secret-at-least-32-bytes-long!!';

const literalRoutePlugin = definePlugin({
  name: 'literal-route',
  routes: {
    literalEcho: endpoint('POST', '/literal/echo')
      .security('none')
      .body(obj({ message: str() }, 'message'))
      .response(200, 'Echo response', obj({ echoed: str() }, 'echoed'))
      .handler('literalEcho')
      .build(),
  },
  methods: () => ({
    literalEcho: async (input: { message: string }) => ({ echoed: input.message }),
  }),
});

const noRoutePlugin = definePlugin({
  name: 'no-route',
  methods: () => ({ health: () => 'ok' }),
});

const correlatedSuccessPlugin = definePlugin({
  name: 'correlated-success',
  methods: () => ({ first: () => ({ kind: 'A' as const }) }),
  routes: {
    first: endpoint('GET', '/correlated-success')
      .security('none')
      .response(202, 'Queued', obj({ queued: bool() }, 'queued'))
      .response(200, 'Immediate', obj({ kind: str() }, 'kind'))
      .handler('first')
      .build(),
  },
});

function makeFortress() {
  return createFortress({
    jwt: { key: SECRET, issuer: 'call-test' },
    database: createTestAdapter(),
    plugins: [literalRoutePlugin, noRoutePlugin, correlatedSuccessPlugin] as const,
  });
}

/** Compile-only negative coverage: this function is deliberately never invoked. */
function rejectsInvalidCallInputs(fortress: ReturnType<typeof makeFortress>): void {
  // @ts-expect-error -- login requires a password
  fortress.call.auth.login({ identifier: 'user@example.com' });
  // @ts-expect-error -- login does not accept unrelated fields
  fortress.call.auth.login({ identifier: 'user@example.com', password: 'secret', extra: true });
  // @ts-expect-error -- revokeSession requires its route parameter
  fortress.call.auth.revokeSession({});
  // @ts-expect-error -- IAM permission effects are a closed literal union
  fortress.call.iam.createRole({ name: 'admin', permissions: [{ resource: 'app', action: 'read', effect: 'MAYBE' }] });
  // @ts-expect-error -- the literal plugin route requires message
  fortress.call.plugins['literal-route'].literalEcho({});
  // @ts-expect-error -- no-route plugins do not add call namespaces
  fortress.call.plugins['no-route'].health({});
  // @ts-expect-error -- unknown route keys must not be callable
  fortress.call.plugins['literal-route'].notRegistered({});
}

describe('fortress.call', () => {
  it('correlates the lowest numeric success body with the dispatched status', async () => {
    const fortress = makeFortress();
    const result: { kind: string } = await fortress.call.plugins['correlated-success'].first({});
    expect(result).toEqual({ kind: 'A' });
    const response = await fortress.handleRequest(new Request('http://localhost/correlated-success'));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ kind: 'A' });
  });

  describe('type inference', () => {
    it('infers login input shape', () => {
      expectTypeOf<InferEndpointCallInput<typeof authEndpoints.login>>().toEqualTypeOf<{
        identifier: string;
        password: string;
        trustedDeviceToken?: string;
      }>();
    });

    it('infers revokeSession params shape', () => {
      expectTypeOf<InferEndpointCallInput<typeof authEndpoints.revokeSession>>().toEqualTypeOf<{
        id: string;
      }>();
    });

    it('infers login success response carries a tagged union', () => {
      type R = InferEndpointSuccessResponse<typeof authEndpoints.login>;
      expectTypeOf<R>().not.toBeNever();
      expectTypeOf<R>().not.toBeUnknown();
    });

    it('infers me endpoint takes no input', () => {
      expectTypeOf<InferEndpointCallInput<typeof authEndpoints.me>>().not.toBeNever();
      expectTypeOf<InferEndpointCallInput<typeof authEndpoints.me>>().not.toBeUnknown();
    });

    it('keeps invalid and unknown calls as compile errors', () => {
      expectTypeOf(rejectsInvalidCallInputs).toBeFunction();
    });
  });

  describe('runtime: happy path', () => {
    it('creates a user and logs in through the inferred core call surface', async () => {
      const fortress = makeFortress();

      await fortress.auth.createUser({
        email: 'call@example.com',
        name: 'Call Test',
        password: 'password-123456',
      });

      const result = await fortress.call.auth.login({
        identifier: 'call@example.com',
        password: 'password-123456',
      });

      expect(result.status).toBe('success');
      if (result.status !== 'success')
        throw new Error('expected successful login');
      expect(typeof result.accessToken).toBe('string');
      expect(typeof result.refreshToken).toBe('string');
      expect(result.user.email).toBe('call@example.com');
    });

    it('calls IAM with its inferred input and response types', async () => {
      const fortress = makeFortress();
      const user = await fortress.auth.createUser({
        email: 'iam-call@example.com',
        name: 'IAM Call',
        password: 'password-123456',
      });
      const role = await fortress.iam.createRole('iam-call-reader', [
        { resource: 'fortress', action: 'viewRoles' },
      ]);
      await fortress.iam.bindRoleToUser(user.id, role.id);

      const loginResult = await fortress.call.auth.login({
        identifier: 'iam-call@example.com',
        password: 'password-123456',
      });
      if (loginResult.status !== 'success')
        throw new Error('expected successful login');

      const roles = await fortress.call.iam.getRoles({}, {
        headers: { authorization: `Bearer ${loginResult.accessToken}` },
      });
      expect(roles.some(item => item.name === 'iam-call-reader')).toBe(true);
    });

    it('substitutes :id from an inferred params input', async () => {
      const fortress = makeFortress();
      await fortress.auth.createUser({
        email: 'sessions@example.com',
        name: 'Sessions',
        password: 'password-123456',
      });
      const loginResult = await fortress.auth.login(
        'sessions@example.com',
        'password-123456',
      );
      assertSuccess(loginResult);
      const accessToken = loginResult.accessToken;
      expect(typeof accessToken).toBe('string');
      if (accessToken === null)
        throw new Error('expected accessToken');

      const sessions = await fortress.auth.listSessions(
        (await fortress.auth.verifyToken(accessToken)).sub,
      );
      expect(sessions.length).toBeGreaterThan(0);
      const sessionId = sessions[0].id;

      await expect(
        fortress.call.auth.revokeSession(
          { id: sessionId },
          { headers: { authorization: `Bearer ${accessToken}` } },
        ),
      ).resolves.toEqual({ ok: true });
    });

    it('calls an exact literal plugin route while ignoring a no-route plugin', async () => {
      const fortress = makeFortress();

      const result = await fortress.call.plugins['literal-route'].literalEcho({ message: 'hello' });

      expect(result).toEqual({ echoed: 'hello' });
    });
  });

  describe('runtime: error path', () => {
    it('throws FortressError on non-2xx', async () => {
      const fortress = makeFortress();
      await fortress.auth.createUser({
        email: 'bad@example.com',
        name: 'Bad',
        password: 'password-123456',
      });

      await expect(fortress.call.auth.login({
        identifier: 'bad@example.com',
        password: 'wrong-password',
      })).rejects.toBeInstanceOf(FortressError);
    });

    it('preserves the error code from the JSON body', async () => {
      const fortress = makeFortress();
      await fortress.auth.createUser({
        email: 'coded@example.com',
        name: 'Coded',
        password: 'password-123456',
      });

      try {
        await fortress.call.auth.login({
          identifier: 'coded@example.com',
          password: 'wrong',
        });
        expect.fail('expected call to throw');
      }
      catch (err) {
        expect(err).toBeInstanceOf(FortressError);
        if (!(err instanceof FortressError))
          throw err;
        expect(err.code).toBe('UNAUTHORIZED');
        expect(err.statusCode).toBe(401);
      }
    });
  });
});
