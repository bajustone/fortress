import { describe, expect, it } from 'vitest';
import { resolveCookieConfig } from '../config';
import { extractAccessToken, extractRefreshToken } from './token-extraction';

const cookies = resolveCookieConfig({ secure: false }); // dev defaults: fortress_access / fortress_refresh

function req(headers: Record<string, string>): Request {
  return new Request('http://localhost/', { headers });
}

describe('extractAccessToken', () => {
  it('reads the access token from the configured cookie first', () => {
    const r = req({ cookie: 'fortress_access=cookie-token' });
    expect(extractAccessToken(r, cookies)).toBe('cookie-token');
  });

  it('falls back to Authorization: Bearer when no cookie', () => {
    const r = req({ authorization: 'Bearer header-token' });
    expect(extractAccessToken(r, cookies)).toBe('header-token');
  });

  it('prefers Authorization header over cookie (P3.7 — cookie-shadow fix)', () => {
    const r = req({
      cookie: 'fortress_access=cookie-token',
      authorization: 'Bearer header-token',
    });
    expect(extractAccessToken(r, cookies)).toBe('header-token');
  });

  it('returns null when neither source has a token', () => {
    expect(extractAccessToken(req({}), cookies)).toBeNull();
  });

  it('ignores non-Bearer Authorization headers', () => {
    const r = req({ authorization: 'Basic dXNlcjpwYXNz' });
    expect(extractAccessToken(r, cookies)).toBeNull();
  });
});

describe('extractRefreshToken', () => {
  it('reads the refresh token from the cookie jar', () => {
    const r = req({ cookie: 'fortress_refresh=rtoken' });
    expect(extractRefreshToken(r, cookies)).toBe('rtoken');
  });

  it('returns null when no refresh cookie present', () => {
    expect(extractRefreshToken(req({}), cookies)).toBeNull();
  });

  it('does NOT fall back to Authorization header', () => {
    const r = req({ authorization: 'Bearer some-token' });
    expect(extractRefreshToken(r, cookies)).toBeNull();
  });
});
