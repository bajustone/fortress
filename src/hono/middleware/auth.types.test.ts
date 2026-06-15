/**
 * Type-level tests for the Hono adapter typed helpers (P1-6).
 *
 * Uses `expectTypeOf` for compile-time assertions. The body of every `it`
 * is intentionally type-only and contains no runtime assertions; vitest
 * runs them once just to confirm the file imports cleanly.
 */

import type { Subject, TokenClaims } from '../../core/types';
import type { FortressEnv } from './auth';
import { Hono } from 'hono';
import { describe, expectTypeOf, it } from 'vitest';
import { getClaims, getSubject, getUserId } from './auth';

interface MyEnv {
  Variables: { requestId: string };
  Bindings: { DB: 'pretend-binding' };
}

interface MyCustomClaims {
  tenantId: string;
  tenantCode: string;
}

describe('fortressEnv<TAppEnv> composition', () => {
  it('exposes both host and fortress variables on a composed env', () => {
    // Build a context typed as FortressEnv<MyEnv> and verify the types.
    type Composed = FortressEnv<MyEnv>;
    type Variables = Composed['Variables'];

    expectTypeOf<Variables['fortressSubject']>().toEqualTypeOf<Subject>();
    expectTypeOf<Variables['requestId']>().toEqualTypeOf<string>();
    expectTypeOf<Composed['Bindings']['DB']>().toEqualTypeOf<'pretend-binding'>();
  });

  it('app = new Hono<FortressEnv<MyEnv>>() retains host variables', () => {
    const app = new Hono<FortressEnv<MyEnv>>();
    app.get('/x', (c) => {
      const requestId = c.get('requestId');
      expectTypeOf(requestId).toEqualTypeOf<string>();
      return c.json({ requestId });
    });
  });
});

describe('typed helpers accept any FortressEnv-compatible context', () => {
  it('getSubject works on the default FortressEnv', () => {
    const app = new Hono<FortressEnv>();
    app.get('/x', (c) => {
      const subject = getSubject(c);
      expectTypeOf(subject).toEqualTypeOf<Subject>();
      return c.json({ subject });
    });
  });

  it('getSubject / getUserId work on FortressEnv<MyEnv> without casts', () => {
    const app = new Hono<FortressEnv<MyEnv>>();
    app.get('/y', (c) => {
      const subject = getSubject(c);
      const userId = getUserId(c);
      expectTypeOf(subject).toEqualTypeOf<Subject>();
      expectTypeOf(userId).toEqualTypeOf<string>();
      return c.json({ subject, userId });
    });
  });

  it('getClaims narrows customClaims via the type parameter', () => {
    const app = new Hono<FortressEnv>();
    app.get('/z', (c) => {
      const claims = getClaims<MyCustomClaims>(c);
      expectTypeOf(claims).toEqualTypeOf<TokenClaims & { customClaims?: MyCustomClaims }>();
      if (claims.customClaims) {
        expectTypeOf(claims.customClaims.tenantId).toEqualTypeOf<string>();
        expectTypeOf(claims.customClaims.tenantCode).toEqualTypeOf<string>();
      }
      return c.json({ ok: true });
    });
  });
});

describe('fortressEnv default keeps existing callers working', () => {
  it('hono<FortressEnv> still resolves to a usable env', () => {
    type Variables = FortressEnv['Variables'];
    expectTypeOf<Variables['fortressSubject']>().toEqualTypeOf<Subject>();
    // The unconstrained generic falls back to an empty bindings/extra-vars
    // shape; Hono accepts it as a valid Env and the typed helpers work.
    const app = new Hono<FortressEnv>();
    app.get('/x', (c) => {
      const subject = getSubject(c);
      expectTypeOf(subject).toEqualTypeOf<Subject>();
      return c.json({ subject });
    });
  });
});
