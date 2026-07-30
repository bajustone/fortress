import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressUser } from '../../core/types';
import type { ProviderProfile } from './types';
import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestAdapter } from '../../testing';
import { socialLogin } from './index';

// We test the social-login plugin methods directly (not through createFortress)
// since handleCallback requires mocking fetch for OAuth token exchange.

function requireExactlyOne<T>(values: readonly T[], description: string): T {
  if (values.length !== 1)
    throw new Error(`Expected exactly one ${description}, received ${values.length}`);
  const value = values[0];
  if (value === undefined)
    throw new Error(`Expected exactly one ${description}, received no value`);
  return value;
}

interface SocialLoginMethods {
  getAuthorizationUrl: (provider: string, redirectUri: string) => Promise<{ url: string; state: string; codeVerifier: string; nonce: string }>;
  handleCallback: (provider: string, code: string, redirectUri: string, codeVerifier: string, returnedState: string, storedState: string, storedNonce: string) => Promise<{ user: FortressUser; profile: ProviderProfile; isNewUser: boolean }>;
  getLinkedAccounts: (userId: string) => Promise<{ provider: string; providerAccountId: string; email: string | null }[]>;
  getProviderTokens: (userId: string, provider: string) => Promise<{ accessToken: string | null; refreshToken: string | null; tokenExpiresAt: Date | null }>;
  unlinkAccount: (userId: string, provider: string) => Promise<void>;
  getProviders: () => string[];
}

// Stub a full custom-OIDC callback: discovery + a validly-signed id_token +
// the matching token/userinfo/jwks responses. Each call uses a distinct
// `issuer` so concurrent stubs cannot collide; cross-instance JWKS reuse is no
// longer a hazard, since caches belong to the plugin instance (#26).
// `emailVerified` is set on both the id_token and userinfo claims so the merged
// profile carries it faithfully.
async function stubOidcProvider(opts: { issuer: string; email: string; emailVerified: boolean; sub: string }): Promise<void> {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  const kid = 'oidc-kid';
  const idToken = await new SignJWT({ sub: opts.sub, email: opts.email, email_verified: opts.emailVerified, nonce: 'nonce' })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(opts.issuer)
    .setAudience('oidc-client')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);

  vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
    const href = input instanceof Request ? input.url : String(input);
    if (href === `${opts.issuer}/.well-known/openid-configuration`) {
      return Response.json({
        issuer: opts.issuer,
        authorization_endpoint: `${opts.issuer}/authorize`,
        token_endpoint: `${opts.issuer}/token`,
        userinfo_endpoint: `${opts.issuer}/userinfo`,
        jwks_uri: `${opts.issuer}/jwks`,
      });
    }
    if (href === `${opts.issuer}/token`)
      return Response.json({ access_token: 'provider-access-token', id_token: idToken });
    if (href === `${opts.issuer}/userinfo`)
      return Response.json({ sub: opts.sub, email: opts.email, email_verified: opts.emailVerified, name: 'Provider User' });
    if (href === `${opts.issuer}/jwks`)
      return Response.json({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });
    throw new Error(`unexpected fetch ${href}`);
  }));
}

describe('social-login plugin', () => {
  let db: DatabaseAdapter;
  let methods: SocialLoginMethods;
  const onFirstLogin = vi.fn();
  const tokenEncryptionKey = 'a'.repeat(32);

  beforeEach(async () => {
    db = createTestAdapter();
    onFirstLogin.mockClear();

    const plugin = socialLogin({
      providers: [
        { name: 'google', clientId: 'google-id', clientSecret: 'google-secret' },
        { name: 'github', clientId: 'github-id', clientSecret: 'github-secret' },
      ],
      autoRegister: true,
      linkAccounts: true,
      persistTokens: true,
      tokenEncryptionKey,
      onFirstLogin,
    });

    // Get methods directly from plugin
    methods = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('getProviders', () => {
    it('returns configured provider names', () => {
      expect(methods.getProviders()).toEqual(['google', 'github']);
    });
  });

  describe('provider cache scoping (#26)', () => {
    const callbackArgs = ['code', 'https://app.com/callback', 'verifier', 'state', 'state', 'nonce'] as const;

    interface ScopedMethods extends SocialLoginMethods {
      resetProviderCaches: () => void;
    }

    function makeInstance(issuer: string): ScopedMethods {
      const plugin = socialLogin({
        providers: [{ name: 'oidc-scoped', clientId: 'oidc-client', clientSecret: 'secret', issuer }],
        autoRegister: true,
        linkAccounts: true,
        tokenEncryptionKey,
      });
      return plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as ScopedMethods;
    }

    /**
     * Like `stubOidcProvider`, but counts upstream fetches and can rotate the
     * signing key while keeping the same `kid`. Same-kid rotation is what makes
     * a stale JWKS observable: jose only refetches when it sees an unknown kid,
     * so a shared cache would keep verifying against the superseded key.
     */
    async function stubCountingOidcProvider(opts: { issuer: string; sub: string; email: string }): Promise<{
      counts: { discovery: number; jwks: number };
      rotateSigningKey: () => Promise<void>;
    }> {
      const kid = 'rotating-kid';
      const counts = { discovery: 0, jwks: 0 };
      let jwk: Record<string, unknown> = {};
      let idToken = '';

      async function useNewKeyPair(): Promise<void> {
        const { publicKey, privateKey } = await generateKeyPair('RS256');
        jwk = { ...await exportJWK(publicKey), kid, alg: 'RS256', use: 'sig' };
        idToken = await new SignJWT({ sub: opts.sub, email: opts.email, email_verified: true, nonce: 'nonce' })
          .setProtectedHeader({ alg: 'RS256', kid })
          .setIssuer(opts.issuer)
          .setAudience('oidc-client')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey);
      }

      await useNewKeyPair();

      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const href = input instanceof Request ? input.url : String(input);
        if (href === `${opts.issuer}/.well-known/openid-configuration`) {
          counts.discovery += 1;
          return Response.json({
            issuer: opts.issuer,
            authorization_endpoint: `${opts.issuer}/authorize`,
            token_endpoint: `${opts.issuer}/token`,
            userinfo_endpoint: `${opts.issuer}/userinfo`,
            jwks_uri: `${opts.issuer}/jwks`,
          });
        }
        if (href === `${opts.issuer}/token`)
          return Response.json({ access_token: 'provider-access-token', id_token: idToken });
        if (href === `${opts.issuer}/userinfo`)
          return Response.json({ sub: opts.sub, email: opts.email, email_verified: true });
        if (href === `${opts.issuer}/jwks`) {
          counts.jwks += 1;
          return Response.json({ keys: [jwk] });
        }
        throw new Error(`unexpected fetch ${href}`);
      }));

      return { counts, rotateSigningKey: useNewKeyPair };
    }

    it('keeps discovery state separate between two instances sharing an issuer', async () => {
      const issuer = 'https://issuer-isolation.example.com';
      const stub = await stubCountingOidcProvider({ issuer, sub: 'isolation-sub', email: 'isolation@example.com' });

      const first = makeInstance(issuer);
      const second = makeInstance(issuer);

      await first.handleCallback('oidc-scoped', ...callbackArgs);
      expect(stub.counts.discovery).toBe(1);

      // A module-level cache would let the second instance reuse the first's
      // document and never reach the provider.
      await second.handleCallback('oidc-scoped', ...callbackArgs);
      expect(stub.counts.discovery).toBe(2);
      expect(stub.counts.jwks).toBe(2);
    });

    it('verifies a rotated signing key in a second instance on the same JWKS URL', async () => {
      const issuer = 'https://issuer-rotation.example.com';
      const stub = await stubCountingOidcProvider({ issuer, sub: 'rotation-sub', email: 'rotation@example.com' });

      const before = makeInstance(issuer);
      await before.handleCallback('oidc-scoped', ...callbackArgs);

      await stub.rotateSigningKey();

      const after = makeInstance(issuer);
      const result = await after.handleCallback('oidc-scoped', ...callbackArgs);
      expect(result.profile.id).toBe('rotation-sub');
    });

    it('does not cache failed or semantically invalid discovery', async () => {
      const issuer = 'https://issuer-invalid-discovery.example.com';
      const { publicKey, privateKey } = await generateKeyPair('RS256');
      const kid = 'recovery-kid';
      const jwk = { ...await exportJWK(publicKey), kid, alg: 'RS256', use: 'sig' };
      const idToken = await new SignJWT({ sub: 'recovery-sub', email: 'recovery@example.com', email_verified: true, nonce: 'nonce' })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuer(issuer)
        .setAudience('oidc-client')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);

      let discoveryAttempts = 0;
      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const href = input instanceof Request ? input.url : String(input);
        if (href === `${issuer}/.well-known/openid-configuration`) {
          discoveryAttempts += 1;
          // First response advertises a different issuer, which must be rejected
          // as untrusted and, critically, must not be retained.
          return Response.json({
            issuer: discoveryAttempts === 1 ? 'https://attacker.example.com' : issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            userinfo_endpoint: `${issuer}/userinfo`,
            jwks_uri: `${issuer}/jwks`,
          });
        }
        if (href === `${issuer}/token`)
          return Response.json({ access_token: 'provider-access-token', id_token: idToken });
        if (href === `${issuer}/userinfo`)
          return Response.json({ sub: 'recovery-sub', email: 'recovery@example.com', email_verified: true });
        if (href === `${issuer}/jwks`)
          return Response.json({ keys: [jwk] });
        throw new Error(`unexpected fetch ${href}`);
      }));

      const instance = makeInstance(issuer);

      await expect(instance.handleCallback('oidc-scoped', ...callbackArgs)).rejects.toThrow();
      expect(discoveryAttempts).toBe(1);

      // The degraded result was evicted, so the retry re-resolves and succeeds.
      const recovered = await instance.handleCallback('oidc-scoped', ...callbackArgs);
      expect(recovered.profile.id).toBe('recovery-sub');
      expect(discoveryAttempts).toBe(2);
    });

    it('resetProviderCaches forces fresh discovery and JWKS resolution', async () => {
      const issuer = 'https://issuer-reset.example.com';
      const stub = await stubCountingOidcProvider({ issuer, sub: 'reset-sub', email: 'reset@example.com' });
      const instance = makeInstance(issuer);

      await instance.handleCallback('oidc-scoped', ...callbackArgs);
      expect(stub.counts).toEqual({ discovery: 1, jwks: 1 });

      await instance.handleCallback('oidc-scoped', ...callbackArgs);
      expect(stub.counts).toEqual({ discovery: 1, jwks: 1 });

      instance.resetProviderCaches();

      await instance.handleCallback('oidc-scoped', ...callbackArgs);
      expect(stub.counts).toEqual({ discovery: 2, jwks: 2 });
    });

    it('resetProviderCaches drops the cached Apple client secret', async () => {
      const { publicKey, privateKey } = await generateKeyPair('RS256');
      const kid = 'apple-kid';
      const jwk = { ...await exportJWK(publicKey), kid, alg: 'RS256', use: 'sig' };
      const idToken = await new SignJWT({ sub: 'apple-sub', email: 'apple@example.com', email_verified: true, nonce: 'nonce' })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuer('https://appleid.apple.com')
        .setAudience('apple-client')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);

      const appleKey = await generateKeyPair('ES256', { extractable: true });
      const clientSecrets: string[] = [];
      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const request = input instanceof Request ? input : new Request(String(input));
        if (request.url === 'https://appleid.apple.com/auth/token') {
          clientSecrets.push(new URLSearchParams(await request.text()).get('client_secret') ?? '');
          return Response.json({ access_token: 'apple-access-token', id_token: idToken });
        }
        if (request.url === 'https://appleid.apple.com/auth/keys')
          return Response.json({ keys: [jwk] });
        throw new Error(`unexpected fetch ${request.url}`);
      }));

      const plugin = socialLogin({
        providers: [{
          name: 'apple',
          clientId: 'apple-client',
          clientSecret: '',
          teamId: 'TEAM123456',
          keyId: 'KEY1234567',
          privateKey: await exportPKCS8(appleKey.privateKey),
        }],
        autoRegister: true,
        linkAccounts: true,
        tokenEncryptionKey,
      });
      const instance = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as ScopedMethods;

      await instance.handleCallback('apple', ...callbackArgs);
      await instance.handleCallback('apple', ...callbackArgs);
      expect(clientSecrets[1]).toBe(clientSecrets[0]);

      instance.resetProviderCaches();
      // The secret embeds a whole-second `iat`, so regeneration is only
      // observable once the clock has advanced past that resolution.
      await new Promise(resolve => setTimeout(resolve, 1100));
      await instance.handleCallback('apple', ...callbackArgs);
      expect(clientSecrets[2]).not.toBe(clientSecrets[0]);
    });
  });

  describe('token exchange — response validation', () => {
    it('accepts GitHub form-urlencoded token responses and requests JSON first', async () => {
      const requests: Request[] = [];
      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const request = input instanceof Request ? input : new Request(String(input));
        requests.push(request);
        if (request.url === 'https://github.com/login/oauth/access_token') {
          return new Response('access_token=gho_test&token_type=bearer&scope=read%3Auser', {
            status: 200,
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
          });
        }
        if (request.url === 'https://api.github.com/user')
          return Response.json({ id: 123, login: 'octocat', email: null, name: 'Octo Cat' });
        if (request.url === 'https://api.github.com/user/emails')
          return Response.json([{ email: 'octocat@example.com', primary: true, verified: true }]);
        throw new Error(`unexpected fetch ${request.url}`);
      }));

      const result = await methods.handleCallback(
        'github',
        'code',
        'https://app.com/callback',
        'verifier',
        'state',
        'state',
        'nonce',
      );
      expect(result.profile.id).toBe('123');
      expect(result.user.email).toBe('octocat@example.com');
      expect(requests[0]?.headers.get('accept')).toBe('application/json');
      expect(requests[0]?.headers.get('content-type')).toBe('application/x-www-form-urlencoded');
      expect(requests[1]?.headers.get('authorization')).toBe('Bearer gho_test');
      expect(requests[1]?.headers.get('accept')).toBe('application/vnd.github+json');
      expect(requests[2]?.headers.get('authorization')).toBe('Bearer gho_test');
      expect(requests[2]?.headers.get('accept')).toBe('application/vnd.github+json');
    });

    it('rejects a token response missing access_token (schema-validated via fetcher)', async () => {
      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const href = input instanceof Request ? input.url : String(input);
        if (href === 'https://oauth2.googleapis.com/token') {
          // No access_token → fails the response schema → treated as a failed exchange.
          return Response.json({ token_type: 'bearer' });
        }
        throw new Error(`unexpected fetch ${href}`);
      }));

      await expect(
        methods.handleCallback('google', 'code', 'https://app.com/callback', 'verifier', 'state', 'state', 'nonce'),
      ).rejects.toThrow('Failed to exchange authorization code with google');
    });
  });

  describe('getAuthorizationUrl', () => {
    it('generates URL with PKCE and state', async () => {
      const result = await methods.getAuthorizationUrl('google', 'https://app.com/callback');

      expect(result.url).toContain('accounts.google.com');
      expect(result.url).toContain('client_id=google-id');
      expect(result.url).toContain('code_challenge=');
      expect(result.url).toContain('code_challenge_method=S256');
      expect(result.state).toBeTruthy();
      expect(result.codeVerifier).toBeTruthy();
      expect(result.nonce).toBeTruthy();
      expect(result.state).not.toBe(result.nonce);
    });

    it('rejects unknown provider', async () => {
      await expect(
        methods.getAuthorizationUrl('unknown', 'https://app.com/callback'),
      ).rejects.toThrow('not configured');
    });

    it('does not trust or cache discovery whose issuer differs from configured issuer', async () => {
      const issuer = 'https://issuer-trust.example.com';
      let discoveryAttempts = 0;
      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const href = input instanceof Request ? input.url : String(input);
        if (href !== `${issuer}/.well-known/openid-configuration`)
          throw new Error(`unexpected fetch ${href}`);
        discoveryAttempts++;
        return Response.json({
          issuer: discoveryAttempts === 1 ? 'https://attacker.example.com' : issuer,
          authorization_endpoint: `${issuer}/discovered-authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
        });
      }));
      const plugin = socialLogin({
        providers: [{ name: 'oidc-trust', clientId: 'trust-client', clientSecret: 'secret', issuer }],
      });
      const trustMethods = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      const degraded = await trustMethods.getAuthorizationUrl('oidc-trust', 'https://app.com/callback');
      expect(degraded.url).toContain(`${issuer}/authorize`);
      expect(degraded.url).not.toContain('discovered-authorize');

      const recovered = await trustMethods.getAuthorizationUrl('oidc-trust', 'https://app.com/callback');
      expect(recovered.url).toContain(`${issuer}/discovered-authorize`);
      expect(discoveryAttempts).toBe(2);
    });
  });

  describe('getLinkedAccounts', () => {
    it('returns linked social accounts for a user', async () => {
      // Seed a user and social account directly
      const user = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'alice@example.com', name: 'Alice', passwordHash: null, isActive: true },
      });

      await db.create({
        model: 'social_account',
        data: {
          userId: user.id,
          provider: 'google',
          providerAccountId: 'google-123',
          email: 'alice@gmail.com',
          accessToken: null,
          refreshToken: null,
          tokenExpiresAt: null,
          profile: null,
        },
      });

      const accounts = await methods.getLinkedAccounts(user.id);
      const account = requireExactlyOne(accounts, 'linked Google account');
      expect(account.provider).toBe('google');
      expect(account.providerAccountId).toBe('google-123');
    });

    it('returns empty array for user with no linked accounts', async () => {
      const user = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'bob@example.com', name: 'Bob', passwordHash: null, isActive: true },
      });

      const accounts = await methods.getLinkedAccounts(user.id);
      expect(accounts).toEqual([]);
    });
  });

  describe('handleCallback', () => {
    it('rejects a tampered OIDC id_token', async () => {
      const { publicKey, privateKey } = await generateKeyPair('RS256');
      const jwk = await exportJWK(publicKey);
      const kid = 'test-kid';
      const idToken = await new SignJWT({
        sub: 'oidc-123',
        email: 'oidc@example.com',
        email_verified: true,
        nonce: 'stored-nonce',
      })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuer('https://issuer-a.example.com')
        .setAudience('oidc-client')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);
      const parts = idToken.split('.');
      const signature = requireExactlyOne(parts.slice(2), 'OIDC token signature');
      parts[2] = `${signature.startsWith('a') ? 'b' : 'a'}${signature.slice(1)}`;
      const tampered = parts.join('.');

      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL, init?: RequestInit) => {
        // fetcher dispatches a single `Request`; jose passes a URL string.
        const req = input instanceof Request ? input : undefined;
        const href = req ? req.url : String(input);
        const method = req ? req.method : init?.method;
        if (href === 'https://issuer-a.example.com/.well-known/openid-configuration') {
          return Response.json({
            issuer: 'https://issuer-a.example.com',
            authorization_endpoint: 'https://issuer-a.example.com/authorize',
            token_endpoint: 'https://issuer-a.example.com/token',
            userinfo_endpoint: 'https://issuer-a.example.com/userinfo',
            jwks_uri: 'https://issuer-a.example.com/jwks',
          });
        }
        if (href === 'https://issuer-a.example.com/token') {
          expect(method).toBe('POST');
          return Response.json({ access_token: 'provider-access', id_token: tampered });
        }
        if (href === 'https://issuer-a.example.com/jwks') {
          return Response.json({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });
        }
        throw new Error(`unexpected fetch ${href}`);
      }));
      const plugin = socialLogin({
        providers: [{ name: 'oidc-a', clientId: 'oidc-client', clientSecret: 'secret', issuer: 'https://issuer-a.example.com' }],
        tokenEncryptionKey,
      });
      const oidcMethods = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      await expect(
        oidcMethods.handleCallback('oidc-a', 'code', 'https://app.com/callback', 'verifier', 'state', 'state', 'stored-nonce'),
      ).rejects.toThrow('Invalid ID token');
    });

    it('rejects alg:none ID tokens before provider profile resolution', async () => {
      const encode = (value: unknown): string => btoa(JSON.stringify(value))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
      const unsigned = `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
        iss: 'https://issuer-none.example.com',
        aud: 'oidc-client',
        sub: 'attacker',
        nonce: 'stored-nonce',
        exp: Math.floor(Date.now() / 1000) + 300,
      })}.`;

      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const request = input instanceof Request ? input : undefined;
        const href = request ? request.url : String(input);
        if (href.endsWith('/.well-known/openid-configuration')) {
          return Response.json({
            issuer: 'https://issuer-none.example.com',
            authorization_endpoint: 'https://issuer-none.example.com/authorize',
            token_endpoint: 'https://issuer-none.example.com/token',
            userinfo_endpoint: 'https://issuer-none.example.com/userinfo',
            jwks_uri: 'https://issuer-none.example.com/jwks',
          });
        }
        if (href.endsWith('/token'))
          return Response.json({ access_token: 'provider-access', id_token: unsigned });
        if (href.endsWith('/jwks'))
          return Response.json({ keys: [] });
        throw new Error(`unexpected fetch ${href}`);
      }));

      const plugin = socialLogin({
        providers: [{ name: 'oidc-none', clientId: 'oidc-client', clientSecret: 'secret', issuer: 'https://issuer-none.example.com' }],
      });
      const methods = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      await expect(methods.handleCallback(
        'oidc-none',
        'code',
        'https://app.com/callback',
        'verifier',
        'state',
        'state',
        'stored-nonce',
      )).rejects.toThrow('Invalid ID token');
    });

    it('decrypts persisted provider tokens through getProviderTokens', async () => {
      const { publicKey, privateKey } = await generateKeyPair('RS256');
      const jwk = await exportJWK(publicKey);
      const kid = 'token-kid';
      const idToken = await new SignJWT({
        sub: 'google-456',
        email: 'tokens@example.com',
        email_verified: true,
        nonce: 'nonce',
      })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuer('https://accounts.google.com')
        .setAudience('google-id')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);

      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const href = input instanceof Request ? input.url : String(input);
        if (href === 'https://oauth2.googleapis.com/token') {
          return Response.json({
            access_token: 'provider-access-token',
            refresh_token: 'provider-refresh-token',
            expires_in: 3600,
            id_token: idToken,
          });
        }
        if (href === 'https://openidconnect.googleapis.com/v1/userinfo') {
          return Response.json({ sub: 'google-456', email: 'tokens@example.com', email_verified: true, name: 'Token User' });
        }
        if (href === 'https://www.googleapis.com/oauth2/v3/certs') {
          return Response.json({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });
        }
        throw new Error(`unexpected fetch ${href}`);
      }));

      const result = await methods.handleCallback('google', 'code', 'https://app.com/callback', 'verifier', 'state', 'state', 'nonce');
      const tokens = await methods.getProviderTokens(result.user.id, 'google');
      expect(tokens.accessToken).toBe('provider-access-token');
      expect(tokens.refreshToken).toBe('provider-refresh-token');
    });

    it('normalizes verified provider email before linking an existing user', async () => {
      const issuer = 'https://issuer-normalized-link.example.com';
      const existing = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'é.user@example.com', name: 'Existing', passwordHash: 'hashed', isActive: true },
      });
      await stubOidcProvider({
        issuer,
        email: 'E\u0301.User@EXAMPLE.COM',
        emailVerified: true,
        sub: 'normalized-link-sub',
      });
      const plugin = socialLogin({
        providers: [{ name: 'oidc-normalized', clientId: 'oidc-client', clientSecret: 'secret', issuer }],
        autoRegister: true,
        linkAccounts: true,
        tokenEncryptionKey,
      });
      const m = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      const result = await m.handleCallback('oidc-normalized', 'code', 'https://app.com/callback', 'verifier', 'state', 'state', 'nonce');
      expect(result.user.id).toBe(existing.id);
      expect(result.isNewUser).toBe(false);
      expect(await m.getLinkedAccounts(existing.id)).toEqual([
        expect.objectContaining({ email: 'é.user@example.com' }),
      ]);
    });

    it('normalizes provider email for JIT-provisioned users', async () => {
      const issuer = 'https://issuer-normalized-jit.example.com';
      await stubOidcProvider({
        issuer,
        email: 'New.User@EXAMPLE.COM',
        emailVerified: true,
        sub: 'normalized-jit-sub',
      });
      const plugin = socialLogin({
        providers: [{ name: 'oidc-jit', clientId: 'oidc-client', clientSecret: 'secret', issuer }],
        autoRegister: true,
        linkAccounts: true,
        tokenEncryptionKey,
      });
      const m = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      const result = await m.handleCallback('oidc-jit', 'code', 'https://app.com/callback', 'verifier', 'state', 'state', 'nonce');
      expect(result.user.email).toBe('new.user@example.com');
      expect(result.isNewUser).toBe(true);
    });

    it('does not auto-link to an existing account when the provider reports email_verified:false (#5/#7)', async () => {
      const issuer = 'https://issuer-unverified.example.com';
      // A real account a verified-email auto-link would otherwise take over.
      const victim = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'victim@example.com', name: 'Victim', passwordHash: 'hashed', isActive: true },
      });

      // Attacker controls a provider account asserting the victim's email, but unverified.
      await stubOidcProvider({ issuer, email: 'victim@example.com', emailVerified: false, sub: 'attacker-sub-999' });
      const plugin = socialLogin({
        providers: [{ name: 'oidc-x', clientId: 'oidc-client', clientSecret: 'secret', issuer }],
        autoRegister: true,
        linkAccounts: true,
        tokenEncryptionKey,
      });
      const m = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      // The id_token verifies, so we reach the link logic — but the by-email gate
      // (emailVerified===true) is skipped, leaving only JIT provisioning, which
      // collides with the victim's UNIQUE email and fails. The attacker's account
      // must NOT attach to the victim either way.
      await expect(
        m.handleCallback('oidc-x', 'code', 'https://app.com/callback', 'verifier', 'state', 'state', 'nonce'),
      ).rejects.toThrow();

      expect(await m.getLinkedAccounts(victim.id)).toEqual([]);
    });

    it('rejects the callback when the matched verified-email account is inactive (#5/#7 isActive guard)', async () => {
      const issuer = 'https://issuer-inactive.example.com';
      await db.create({
        model: 'user',
        data: { email: 'disabled@example.com', name: 'Disabled', passwordHash: 'hashed', isActive: false },
      });

      // Verified email → the link-by-email path runs and finds the disabled account.
      await stubOidcProvider({ issuer, email: 'disabled@example.com', emailVerified: true, sub: 'provider-sub-1' });
      const plugin = socialLogin({
        providers: [{ name: 'oidc-x', clientId: 'oidc-client', clientSecret: 'secret', issuer }],
        autoRegister: true,
        linkAccounts: true,
        tokenEncryptionKey,
      });
      const m = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      await expect(
        m.handleCallback('oidc-x', 'code', 'https://app.com/callback', 'verifier', 'state', 'state', 'nonce'),
      ).rejects.toThrow('User account not found or disabled');
    });

    it('accepts a Microsoft token from a concrete tenant with the default common authority', async () => {
      const { publicKey, privateKey } = await generateKeyPair('RS256');
      const jwk = await exportJWK(publicKey);
      const tenantId = '11111111-2222-3333-4444-555555555555';
      const issuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
      const idToken = await new SignJWT({
        sub: 'microsoft-sub',
        tid: tenantId,
        email: 'microsoft@example.com',
        nonce: 'nonce',
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'microsoft-kid' })
        .setIssuer(issuer)
        .setAudience('microsoft-client')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);

      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const request = input instanceof Request ? input : new Request(String(input));
        const href = request.url;
        if (href === 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration') {
          return Response.json({
            issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
            authorization_endpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            token_endpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            jwks_uri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
          });
        }
        if (href === 'https://login.microsoftonline.com/common/oauth2/v2.0/token')
          return Response.json({ access_token: 'microsoft-access', id_token: idToken });
        if (href === 'https://login.microsoftonline.com/common/discovery/v2.0/keys')
          return Response.json({ keys: [{ ...jwk, kid: 'microsoft-kid', alg: 'RS256', use: 'sig' }] });
        if (href === 'https://graph.microsoft.com/v1.0/me') {
          expect(request.headers.get('authorization')).toBe('Bearer microsoft-access');
          return Response.json({ id: 'microsoft-sub', mail: 'microsoft@example.com', displayName: 'Microsoft User' });
        }
        throw new Error(`unexpected fetch ${href}`);
      }));

      const plugin = socialLogin({
        providers: [{ name: 'microsoft', clientId: 'microsoft-client', clientSecret: 'secret' }],
        tokenEncryptionKey,
      });
      const microsoftMethods = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      const result = await microsoftMethods.handleCallback(
        'microsoft',
        'code',
        'https://app.com/callback',
        'verifier',
        'state',
        'state',
        'nonce',
      );
      expect(result.user.email).toBe('microsoft@example.com');
    });

    it('retries discovery after a transient failure instead of caching degradation', async () => {
      const issuer = 'https://issuer-discovery-retry.example.com';
      const { publicKey, privateKey } = await generateKeyPair('RS256');
      const jwk = await exportJWK(publicKey);
      const idToken = await new SignJWT({ sub: 'retry-sub', email: 'retry@example.com', email_verified: true, nonce: 'nonce' })
        .setProtectedHeader({ alg: 'RS256', kid: 'retry-kid' })
        .setIssuer(issuer)
        .setAudience('retry-client')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);
      let discoveryAttempts = 0;
      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const href = input instanceof Request ? input.url : String(input);
        if (href === `${issuer}/.well-known/openid-configuration`) {
          discoveryAttempts++;
          if (discoveryAttempts === 1)
            return Response.json({ error: 'temporarily unavailable' }, { status: 503 });
          return Response.json({
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            userinfo_endpoint: `${issuer}/userinfo`,
            jwks_uri: `${issuer}/jwks`,
          });
        }
        if (href === `${issuer}/token`)
          return Response.json({ access_token: 'retry-access', id_token: idToken });
        if (href === `${issuer}/jwks`)
          return Response.json({ keys: [{ ...jwk, kid: 'retry-kid', alg: 'RS256', use: 'sig' }] });
        if (href === `${issuer}/userinfo`)
          return Response.json({ sub: 'retry-sub', email: 'retry@example.com', email_verified: true });
        throw new Error(`unexpected fetch ${href}`);
      }));
      const plugin = socialLogin({
        providers: [{ name: 'oidc-retry', clientId: 'retry-client', clientSecret: 'secret', issuer }],
        tokenEncryptionKey,
      });
      const retryMethods = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      await expect(retryMethods.handleCallback(
        'oidc-retry',
        'code',
        'https://app.com/callback',
        'verifier',
        'state',
        'state',
        'nonce',
      )).rejects.toThrow(/JWKS URI|ID token/);
      const result = await retryMethods.handleCallback(
        'oidc-retry',
        'code',
        'https://app.com/callback',
        'verifier',
        'state',
        'state',
        'nonce',
      );
      expect(result.user.email).toBe('retry@example.com');
      expect(discoveryAttempts).toBe(2);
    });

    it('fails closed when OIDC discovery degrades and the provider has no static jwksUri', async () => {
      const issuer = 'https://issuer-degraded.example.com';
      const { privateKey } = await generateKeyPair('RS256');
      const idToken = await new SignJWT({ sub: 'x', email: 'x@example.com', email_verified: true, nonce: 'nonce' })
        .setProtectedHeader({ alg: 'RS256', kid: 'k' })
        .setIssuer(issuer)
        .setAudience('oidc-client')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);

      // Discovery returns non-2xx → the plugin degrades to the static definition,
      // which for a discovery-only OIDC provider carries NO jwksUri. id_token
      // verification must then THROW (fail closed), never skip verification.
      vi.stubGlobal('fetch', vi.fn(async (input: Request | string | URL) => {
        const href = input instanceof Request ? input.url : String(input);
        if (href === `${issuer}/.well-known/openid-configuration`)
          return Response.json({ error: 'discovery down' }, { status: 503 });
        if (href === `${issuer}/token`)
          return Response.json({ access_token: 'provider-access-token', id_token: idToken });
        throw new Error(`unexpected fetch ${href}`);
      }));

      const plugin = socialLogin({
        providers: [{ name: 'oidc-degraded', clientId: 'oidc-client', clientSecret: 'secret', issuer }],
        tokenEncryptionKey,
      });
      const m = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;

      await expect(
        m.handleCallback('oidc-degraded', 'code', 'https://app.com/callback', 'verifier', 'state', 'state', 'nonce'),
      ).rejects.toThrow(/JWKS URI|ID token/);
    });
  });

  describe('unlinkAccount', () => {
    it('removes a linked social account', async () => {
      const user = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'alice@example.com', name: 'Alice', passwordHash: null, isActive: true },
      });

      await db.create({
        model: 'social_account',
        data: {
          userId: user.id,
          provider: 'google',
          providerAccountId: 'google-123',
          email: 'alice@gmail.com',
          accessToken: null,
          refreshToken: null,
          tokenExpiresAt: null,
          profile: null,
        },
      });

      await methods.unlinkAccount(user.id, 'google');

      const accounts = await methods.getLinkedAccounts(user.id);
      expect(accounts).toEqual([]);
    });
  });

  describe('plugin configuration', () => {
    it('rejects unknown provider in config', () => {
      expect(() => socialLogin({
        providers: [{ name: 'nonexistent', clientId: 'x', clientSecret: 'y' }],
        tokenEncryptionKey,
      })).toThrow('Unknown social login provider');
    });

    it('accepts custom OIDC provider with issuer', () => {
      const plugin = socialLogin({
        providers: [{ name: 'corporate-sso', clientId: 'x', clientSecret: 'y', issuer: 'https://sso.company.com' }],
        tokenEncryptionKey,
      });

      const m = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;
      expect(m.getProviders()).toEqual(['corporate-sso']);
    });
  });
});
