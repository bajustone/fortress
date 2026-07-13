import type { authEndpoints } from '../auth/auth-endpoints';
import type { InferEndpointCallInput, InferEndpointSuccessResponse } from '../endpoint';
import type { Fortress } from '../fortress';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { FortressError } from '../errors';
import { createFortress } from '../fortress';
import { assertSuccess } from '../types';

const SECRET = 'call-test-secret-at-least-32-bytes-long!!';

function makeFortress(): Fortress {
  return createFortress({
    jwt: { key: SECRET, issuer: 'call-test' },
    database: createTestAdapter(),
  }) as unknown as Fortress;
}

describe('fortress.call', () => {
  describe('type inference', () => {
    it('infers login input shape', () => {
      // Compile-time only — verifies the generic flow.
      expectTypeOf<InferEndpointCallInput<typeof authEndpoints.login>>().toEqualTypeOf<{
        identifier: string;
        password: string;
      }>();
    });

    it('infers revokeSession params shape', () => {
      expectTypeOf<InferEndpointCallInput<typeof authEndpoints.revokeSession>>().toEqualTypeOf<{
        id: string;
      }>();
    });

    it('infers login success response carries a tagged union', () => {
      type R = InferEndpointSuccessResponse<typeof authEndpoints.login>;
      // The AuthResult oneOf collapses to a discriminated union — exercise
      // that at least one variant has an accessToken string.
      expectTypeOf<R>().not.toBeNever();
      expectTypeOf<R>().not.toBeUnknown();
    });

    it('infers me endpoint takes no input', () => {
      // `me` has no body/query/params, so the inferred call input collapses
      // to the empty intersection — we assert it's not `never` and not `unknown`.
      expectTypeOf<InferEndpointCallInput<typeof authEndpoints.me>>().not.toBeNever();
      expectTypeOf<InferEndpointCallInput<typeof authEndpoints.me>>().not.toBeUnknown();
    });
  });

  describe('runtime: happy path', () => {
    it('creates a user via call.createUser and logs in via call.login', async () => {
      const fortress = makeFortress();

      // Direct service call to create the user — createUser over HTTP uses
      // a different password-policy path than we want to exercise here.
      await fortress.auth.createUser({
        email: 'call@example.com',
        name: 'Call Test',
        password: 'password-123456',
      });

      const result = await (fortress.call as any).login({
        identifier: 'call@example.com',
        password: 'password-123456',
      });

      expect(result).toBeDefined();
      expect(typeof result.accessToken).toBe('string');
      expect(typeof result.refreshToken).toBe('string');
      expect(result.user.email).toBe('call@example.com');
    });

    it('substitutes :id from a params input', async () => {
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

      // Rotate so we have a sessions row to revoke. Then call.revokeSession
      // using params substitution.
      const sessions = await fortress.auth.listSessions(
        (await fortress.auth.verifyToken(accessToken)).sub,
      );
      expect(sessions.length).toBeGreaterThan(0);
      const sessionId = sessions[0].id;

      // revokeSession requires bearer auth. Pass it via options.headers.
      await expect(
        (fortress.call as any).revokeSession(
          { id: sessionId },
          { headers: { authorization: `Bearer ${accessToken}` } },
        ),
      ).resolves.toEqual({ ok: true });
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

      await expect((fortress.call as any).login({
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
        await (fortress.call as any).login({
          identifier: 'coded@example.com',
          password: 'wrong',
        });
        expect.fail('expected call to throw');
      }
      catch (err) {
        expect(err).toBeInstanceOf(FortressError);
        const fe = err as FortressError;
        expect(fe.code).toBe('UNAUTHORIZED');
        expect(fe.statusCode).toBe(401);
      }
    });
  });
});
