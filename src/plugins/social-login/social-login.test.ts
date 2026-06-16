import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressUser } from '../../core/types';
import type { ProviderProfile } from './types';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestAdapter } from '../../testing';
import { socialLogin } from './index';

// We test the social-login plugin methods directly (not through createFortress)
// since handleCallback requires mocking fetch for OAuth token exchange.

interface SocialLoginMethods {
  getAuthorizationUrl: (provider: string, redirectUri: string) => Promise<{ url: string; state: string; codeVerifier: string; nonce: string }>;
  handleCallback: (provider: string, code: string, redirectUri: string, codeVerifier: string, returnedState: string, storedState: string, storedNonce: string) => Promise<{ user: FortressUser; profile: ProviderProfile; isNewUser: boolean }>;
  getLinkedAccounts: (userId: string) => Promise<{ provider: string; providerAccountId: string; email: string | null }[]>;
  getProviderTokens: (userId: string, provider: string) => Promise<{ accessToken: string | null; refreshToken: string | null; tokenExpiresAt: Date | null }>;
  unlinkAccount: (userId: string, provider: string) => Promise<void>;
  getProviders: () => string[];
}

// Stub a full custom-OIDC callback: discovery + a validly-signed id_token +
// the matching token/userinfo/jwks responses. Each call MUST use a distinct
// `issuer` — the plugin caches the remote JWKS by jwksUri at module scope, so
// reusing an issuer across tests would verify a fresh keypair against a stale
// cached key. `emailVerified` is set on both the id_token and userinfo claims
// so the merged profile carries it faithfully.
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

  describe('token exchange — response validation', () => {
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
      expect(accounts).toHaveLength(1);
      expect(accounts[0].provider).toBe('google');
      expect(accounts[0].providerAccountId).toBe('google-123');
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
      parts[2] = `${parts[2].startsWith('a') ? 'b' : 'a'}${parts[2].slice(1)}`;
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
