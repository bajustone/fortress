import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressUser } from '../../core/types';
import type { ProviderProfile } from './types';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestAdapter } from '../../testing';
import { socialLogin } from './index';

// We test the social-login plugin methods directly (not through createFortress)
// since handleCallback requires mocking fetch for OAuth token exchange.

interface SocialLoginMethods {
  getAuthorizationUrl: (provider: string, redirectUri: string) => Promise<{ url: string; state: { provider: string; codeVerifier: string; nonce: string } }>;
  handleCallback: (provider: string, code: string, redirectUri: string, codeVerifier: string) => Promise<{ user: FortressUser; profile: ProviderProfile; isNewUser: boolean }>;
  getLinkedAccounts: (userId: number) => Promise<{ provider: string; providerAccountId: string; email: string | null }[]>;
  unlinkAccount: (userId: number, provider: string) => Promise<void>;
  getProviders: () => string[];
}

describe('social-login plugin', () => {
  let db: DatabaseAdapter;
  let methods: SocialLoginMethods;
  const onFirstLogin = vi.fn();

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
      onFirstLogin,
    });

    // Get methods directly from plugin
    methods = plugin.methods!({ db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;
  });

  describe('getProviders', () => {
    it('returns configured provider names', () => {
      expect(methods.getProviders()).toEqual(['google', 'github']);
    });
  });

  describe('getAuthorizationUrl', () => {
    it('generates URL with PKCE and state', async () => {
      const result = await methods.getAuthorizationUrl('google', 'https://app.com/callback');

      expect(result.url).toContain('accounts.google.com');
      expect(result.url).toContain('client_id=google-id');
      expect(result.url).toContain('code_challenge=');
      expect(result.url).toContain('code_challenge_method=S256');
      expect(result.state.provider).toBe('google');
      expect(result.state.codeVerifier).toBeTruthy();
      expect(result.state.nonce).toBeTruthy();
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
      const user = await db.create<{ id: number }>({
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
      const user = await db.create<{ id: number }>({
        model: 'user',
        data: { email: 'bob@example.com', name: 'Bob', passwordHash: null, isActive: true },
      });

      const accounts = await methods.getLinkedAccounts(user.id);
      expect(accounts).toEqual([]);
    });
  });

  describe('unlinkAccount', () => {
    it('removes a linked social account', async () => {
      const user = await db.create<{ id: number }>({
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
      })).toThrow('Unknown social login provider');
    });

    it('accepts custom OIDC provider with issuer', () => {
      const plugin = socialLogin({
        providers: [{ name: 'corporate-sso', clientId: 'x', clientSecret: 'y', issuer: 'https://sso.company.com' }],
      });

      const m = plugin.methods!({ db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } }) as unknown as SocialLoginMethods;
      expect(m.getProviders()).toEqual(['corporate-sso']);
    });
  });
});
