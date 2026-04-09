import { describe, expect, it } from 'vitest';
import { Errors, FortressError } from '../errors';
import { errorToResponse, withCookies } from './error-response';

describe('errorToResponse', () => {
  it('maps a FortressError to its declared status', async () => {
    const res = errorToResponse(Errors.unauthorized('nope'));
    expect(res.status).toBe(401);
    expect(res.headers.get('content-type')).toBe('application/json');
    const body = await res.json() as { code: string; message: string };
    expect(body.code).toBe('UNAUTHORIZED');
    expect(body.message).toBe('nope');
  });

  it('attaches Retry-After for RATE_LIMITED', () => {
    const res = errorToResponse(Errors.rateLimited(42));
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('42');
  });

  it('omits Retry-After for non-rate-limited errors', () => {
    const res = errorToResponse(Errors.forbidden());
    expect(res.headers.get('retry-after')).toBeNull();
  });

  it('returns 500 INTERNAL_ERROR for unknown errors and does not leak the message', async () => {
    const res = errorToResponse(new Error('something private'));
    expect(res.status).toBe(500);
    const body = await res.json() as { code: string; message: string };
    expect(body.code).toBe('INTERNAL_ERROR');
    expect(body.message).toBe('Internal server error');
  });

  it('handles validation errors (issue array)', async () => {
    const err = Errors.validationError([{ message: 'required', path: ['email'] }]);
    expect(err).toBeInstanceOf(FortressError);
    const res = errorToResponse(err);
    expect(res.status).toBe(422);
    const body = await res.json() as { code: string; details: unknown };
    expect(body.code).toBe('VALIDATION_ERROR');
    expect(body.details).toBeDefined();
  });
});

describe('withCookies', () => {
  it('returns the same response when no cookies given', () => {
    const r = new Response('hi', { status: 200 });
    expect(withCookies(r, [])).toBe(r);
  });

  it('appends multiple Set-Cookie headers (not overwriting)', () => {
    const r = new Response('{}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
    const out = withCookies(r, ['a=1; Path=/', 'b=2; Path=/']);
    const setCookies = out.headers.getSetCookie();
    expect(setCookies).toContain('a=1; Path=/');
    expect(setCookies).toContain('b=2; Path=/');
    expect(out.headers.get('content-type')).toBe('application/json');
  });

  it('preserves status and statusText', () => {
    const r = new Response('x', { status: 201, statusText: 'Created' });
    const out = withCookies(r, ['a=1']);
    expect(out.status).toBe(201);
    expect(out.statusText).toBe('Created');
  });
});
