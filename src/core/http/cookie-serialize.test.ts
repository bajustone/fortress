import { describe, expect, it } from 'vitest';
import { resolveCookieConfig } from '../config';
import {
  clearAuthCookies,
  parseCookieHeader,
  serializeAuthCookies,
  serializeCookie,
} from './cookie-serialize';

describe('resolveCookieConfig', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const setEnv = (val: string | undefined): void => {
    if (val === undefined)
      delete process.env.NODE_ENV;
    else process.env.NODE_ENV = val;
  };

  it('uses __Host- prefix and Secure when NODE_ENV=production', () => {
    setEnv('production');
    const c = resolveCookieConfig();
    expect(c.accessName).toBe('__Host-fortress_access');
    expect(c.refreshName).toBe('__Host-fortress_refresh');
    expect(c.secure).toBe(true);
    expect(c.sameSite).toBe('lax');
    expect(c.path).toBe('/');
    setEnv(originalNodeEnv);
  });

  it('drops __Host- prefix and disables Secure outside production', () => {
    setEnv('development');
    const c = resolveCookieConfig();
    expect(c.accessName).toBe('fortress_access');
    expect(c.refreshName).toBe('fortress_refresh');
    expect(c.secure).toBe(false);
    setEnv(originalNodeEnv);
  });

  it('drops __Host- prefix when a Domain is set even in production', () => {
    setEnv('production');
    const c = resolveCookieConfig({ domain: 'example.com' });
    expect(c.accessName).toBe('fortress_access');
    expect(c.refreshName).toBe('fortress_refresh');
    expect(c.secure).toBe(true);
    expect(c.domain).toBe('example.com');
    setEnv(originalNodeEnv);
  });

  it('drops __Host- prefix when path is not /', () => {
    setEnv('production');
    const c = resolveCookieConfig({ path: '/api' });
    expect(c.accessName).toBe('fortress_access');
    setEnv(originalNodeEnv);
  });

  it('honors caller-provided overrides', () => {
    setEnv('production');
    const c = resolveCookieConfig({
      accessName: 'my_access',
      refreshName: 'my_refresh',
      sameSite: 'strict',
      secure: false,
    });
    expect(c.accessName).toBe('my_access');
    expect(c.refreshName).toBe('my_refresh');
    expect(c.sameSite).toBe('strict');
    expect(c.secure).toBe(false);
    setEnv(originalNodeEnv);
  });
});

describe('serializeCookie', () => {
  it('produces a Set-Cookie value with all attributes', () => {
    const cookies = resolveCookieConfig({ secure: true });
    const out = serializeCookie('test', 'value', cookies, 60);
    expect(out).toContain('test=value');
    expect(out).toContain('Path=/');
    expect(out).toContain('HttpOnly');
    expect(out).toContain('Secure');
    expect(out).toContain('SameSite=Lax');
    expect(out).toContain('Max-Age=60');
    expect(out).toContain('Expires=');
  });

  it('omits Secure when not set', () => {
    const cookies = resolveCookieConfig({ secure: false });
    const out = serializeCookie('test', 'value', cookies);
    expect(out).not.toContain('Secure');
  });

  it('url-encodes the value', () => {
    const cookies = resolveCookieConfig({ secure: false });
    const out = serializeCookie('test', 'a b/c', cookies);
    expect(out).toContain('test=a%20b%2Fc');
  });

  it('omits Max-Age/Expires when no expiry given', () => {
    const cookies = resolveCookieConfig({ secure: false });
    const out = serializeCookie('test', 'value', cookies);
    expect(out).not.toContain('Max-Age');
    expect(out).not.toContain('Expires');
  });
});

describe('serializeAuthCookies', () => {
  it('emits one Set-Cookie value when only accessToken is present', () => {
    const cookies = resolveCookieConfig({ secure: false });
    const out = serializeAuthCookies({ accessToken: 'a' }, cookies);
    expect(out).toHaveLength(1);
    expect(out[0]).toContain('fortress_access=a');
  });

  it('emits two values when refreshToken is also present', () => {
    const cookies = resolveCookieConfig({ secure: false });
    const out = serializeAuthCookies(
      { accessToken: 'a', refreshToken: 'r' },
      cookies,
      { access: 60, refresh: 120 },
    );
    expect(out).toHaveLength(2);
    expect(out[0]).toContain('fortress_access=a');
    expect(out[0]).toContain('Max-Age=60');
    expect(out[1]).toContain('fortress_refresh=r');
    expect(out[1]).toContain('Max-Age=120');
  });

  it('omits the refresh cookie when refreshToken is null', () => {
    const cookies = resolveCookieConfig({ secure: false });
    const out = serializeAuthCookies(
      { accessToken: 'a', refreshToken: null },
      cookies,
    );
    expect(out).toHaveLength(1);
  });
});

describe('clearAuthCookies', () => {
  it('produces immediately-expiring Set-Cookie values for both names', () => {
    const cookies = resolveCookieConfig({ secure: false });
    const out = clearAuthCookies(cookies);
    expect(out).toHaveLength(2);
    expect(out[0]).toContain('fortress_access=');
    expect(out[0]).toContain('Max-Age=0');
    expect(out[1]).toContain('fortress_refresh=');
    expect(out[1]).toContain('Max-Age=0');
  });
});

describe('parseCookieHeader', () => {
  it('returns {} for null/empty', () => {
    expect(parseCookieHeader(null)).toEqual({});
    expect(parseCookieHeader('')).toEqual({});
  });

  it('parses a single cookie', () => {
    expect(parseCookieHeader('a=b')).toEqual({ a: 'b' });
  });

  it('parses multiple cookies', () => {
    expect(parseCookieHeader('a=b; c=d')).toEqual({ a: 'b', c: 'd' });
  });

  it('decodes URL-encoded values', () => {
    expect(parseCookieHeader('a=b%20c')).toEqual({ a: 'b c' });
  });

  it('skips malformed segments', () => {
    expect(parseCookieHeader('a=b; nokey; c=d')).toEqual({ a: 'b', c: 'd' });
  });
});
