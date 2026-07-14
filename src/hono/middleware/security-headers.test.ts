import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { createSecurityHeadersMiddleware } from './security-headers';

describe('security headers middleware', () => {
  it('sets all default security headers', async () => {
    const app = new Hono();
    app.use('*', createSecurityHeadersMiddleware());
    app.get('/test', c => c.text('ok'));

    const res = await app.request('/test');
    expect(res.status).toBe(200);
    expect(res.headers.get('Strict-Transport-Security')).toBe('max-age=63072000; includeSubDomains');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('Content-Security-Policy')).toBe('default-src \'self\'');
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(res.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none');
  });

  it('sets security headers on error responses', async () => {
    const app = new Hono();
    app.use('*', createSecurityHeadersMiddleware());
    app.get('/error', () => {
      throw new Error('boom');
    });

    const res = await app.request('/error');
    expect(res.status).toBe(500);
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
  });

  it('allows custom CSP', async () => {
    const app = new Hono();
    app.use('*', createSecurityHeadersMiddleware({
      contentSecurityPolicy: 'default-src \'self\'; script-src \'self\' cdn.example.com',
    }));
    app.get('/test', c => c.text('ok'));

    const res = await app.request('/test');
    expect(res.headers.get('Content-Security-Policy')).toBe('default-src \'self\'; script-src \'self\' cdn.example.com');
  });

  it('allows disabling individual headers', async () => {
    const app = new Hono();
    app.use('*', createSecurityHeadersMiddleware({
      frameOptions: false,
      contentSecurityPolicy: false,
      referrerPolicy: false,
    }));
    app.get('/test', c => c.text('ok'));

    const res = await app.request('/test');
    expect(res.headers.get('X-Frame-Options')).toBeNull();
    expect(res.headers.get('Content-Security-Policy')).toBeNull();
    expect(res.headers.get('Referrer-Policy')).toBeNull();
    // Others still present
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('supports HSTS preload', async () => {
    const app = new Hono();
    app.use('*', createSecurityHeadersMiddleware({ hstsPreload: true }));
    app.get('/test', c => c.text('ok'));

    const res = await app.request('/test');
    expect(res.headers.get('Strict-Transport-Security')).toBe('max-age=63072000; includeSubDomains; preload');
  });

  it('disables HSTS when maxAge is 0', async () => {
    const app = new Hono();
    app.use('*', createSecurityHeadersMiddleware({ hstsMaxAge: 0 }));
    app.get('/test', c => c.text('ok'));

    const res = await app.request('/test');
    expect(res.headers.get('Strict-Transport-Security')).toBeNull();
  });

  it('allows SAMEORIGIN for X-Frame-Options', async () => {
    const app = new Hono();
    app.use('*', createSecurityHeadersMiddleware({ frameOptions: 'SAMEORIGIN' }));
    app.get('/test', c => c.text('ok'));

    const res = await app.request('/test');
    expect(res.headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
  });
});
