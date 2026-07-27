import { createFetch } from '@bajustone/fetcher';
import { array, object, string, union } from '@bajustone/fetcher/schema';

/**
 * Deno compile-only coverage for every outbound header shape used by Fortress.
 * Deno 2.6 exposed an ambient RequestInit regression in fetcher <= 1.0.1 that
 * ordinary tsc and newer Deno versions did not reproduce.
 */
const client = createFetch({ baseUrl: '' });
const objectSchema = object({});
const arraySchema = array(object({}));
const tokenSchema = union([object({ access_token: string() }), string()]);
declare const dynamicUrl: string;
declare const accessToken: string;
declare const suppliedHeaders: Record<string, string>;

// HIBP range request.
client.get(`https://api.pwnedpasswords.com/range/${accessToken}`, {
  headers: { 'Add-Padding': 'true' },
});

// OAuth token exchange.
client.post(dynamicUrl, {
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
  },
  body: new URLSearchParams({ code: 'code' }),
  responseSchema: tokenSchema,
});

// Generic OIDC userinfo.
client.get(dynamicUrl, {
  headers: { Authorization: `Bearer ${accessToken}` },
  responseSchema: objectSchema,
});

// GitHub profile and email fallback.
client.get('https://api.github.com/user', {
  headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
  responseSchema: objectSchema,
});
client.get('https://api.github.com/user/emails', {
  headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
  responseSchema: arraySchema,
});

// Webhook delivery with caller-supplied signing headers.
client.post(dynamicUrl, {
  body: '{}',
  headers: { 'Content-Type': 'application/json', ...suppliedHeaders },
});
