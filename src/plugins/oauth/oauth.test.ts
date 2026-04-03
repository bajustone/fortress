import type { DatabaseAdapter } from '../../adapters/database';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { generateCodeChallenge, generateCodeVerifier, oauth } from './index';

interface OAuthMethods {
  createClient: (data: { name: string; redirectUris: string[]; grantTypes: string[] }) => Promise<{ clientId: string; clientSecret: string }>;
  createAuthorizationCode: (params: { clientId: string; userId: number; redirectUri: string; scope?: string; codeChallenge?: string; codeChallengeMethod?: string }) => Promise<{ code: string }>;
  exchangeCode: (params: { code: string; clientId: string; clientSecret: string; redirectUri: string; codeVerifier?: string }) => Promise<{ accessToken: string; tokenType: string; expiresIn: number }>;
  clientCredentialsGrant: (params: { clientId: string; clientSecret: string; scope?: string }) => Promise<{ accessToken: string; tokenType: string; expiresIn: number }>;
  revokeToken: (token: string) => Promise<void>;
  introspectToken: (token: string) => Promise<{ active: boolean; clientId?: string; userId?: number }>;
  createPendingFlow: (params: { clientId: string; redirectUri: string; state: string; scope?: string; codeChallenge?: string; codeChallengeMethod?: string }) => Promise<{ flowId: number }>;
  resumePendingFlow: (flowId: number) => Promise<{ clientId: string; redirectUri: string; state: string }>;
  getUserInfo: (token: string) => Promise<{ id: number; email: string; name: string } | null>;
}

describe('oauth plugin', () => {
  let db: DatabaseAdapter;
  let methods: OAuthMethods;
  let userId: number;

  beforeEach(async () => {
    db = createTestAdapter();

    const plugin = oauth({ authCodeExpirySeconds: 600, accessTokenExpirySeconds: 3600 });
    methods = plugin.methods!({ db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } }) as unknown as OAuthMethods;

    // Create a test user
    const user = await db.create<{ id: number }>({
      model: 'user',
      data: { email: 'alice@example.com', name: 'Alice', passwordHash: 'hash', isActive: true },
    });
    userId = user.id;
  });

  describe('createClient', () => {
    it('creates a client with id and secret', async () => {
      const client = await methods.createClient({
        name: 'Test App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      expect(client.clientId).toBeTruthy();
      expect(client.clientSecret).toBeTruthy();
    });
  });

  describe('authorization code flow', () => {
    it('creates and exchanges an authorization code', async () => {
      const client = await methods.createClient({
        name: 'Test App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/callback',
      });

      const tokens = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        redirectUri: 'https://app.com/callback',
      });

      expect(tokens.accessToken).toBeTruthy();
      expect(tokens.tokenType).toBe('Bearer');
      expect(tokens.expiresIn).toBe(3600);
    });

    it('rejects reused authorization code', async () => {
      const client = await methods.createClient({
        name: 'Test App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/callback',
      });

      await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        redirectUri: 'https://app.com/callback',
      });

      await expect(methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        redirectUri: 'https://app.com/callback',
      })).rejects.toThrow('already used');
    });

    it('validates redirect_uri match', async () => {
      const client = await methods.createClient({
        name: 'Test App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      await expect(methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://evil.com/callback',
      })).rejects.toThrow('Invalid redirect_uri');
    });
  });

  describe('pkce validation', () => {
    it('validates code_verifier against code_challenge', async () => {
      const client = await methods.createClient({
        name: 'PKCE App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/callback',
        codeChallenge,
        codeChallengeMethod: 'S256',
      });

      const tokens = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        redirectUri: 'https://app.com/callback',
        codeVerifier,
      });

      expect(tokens.accessToken).toBeTruthy();
    });

    it('rejects wrong code_verifier', async () => {
      const client = await methods.createClient({
        name: 'PKCE App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/callback',
        codeChallenge,
        codeChallengeMethod: 'S256',
      });

      await expect(methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        redirectUri: 'https://app.com/callback',
        codeVerifier: 'wrong-verifier',
      })).rejects.toThrow('Invalid code_verifier');
    });
  });

  describe('client credentials grant', () => {
    it('issues token for service client', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const tokens = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

      expect(tokens.accessToken).toBeTruthy();
      expect(tokens.tokenType).toBe('Bearer');
    });

    it('rejects client without client_credentials grant type', async () => {
      const client = await methods.createClient({
        name: 'Web App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      await expect(methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      })).rejects.toThrow('does not support');
    });
  });

  describe('token introspection', () => {
    it('introspects a valid token', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const { accessToken } = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

      const info = await methods.introspectToken(accessToken);
      expect(info.active).toBe(true);
      expect(info.clientId).toBe(client.clientId);
    });

    it('returns inactive for unknown token', async () => {
      const info = await methods.introspectToken('nonexistent');
      expect(info.active).toBe(false);
    });
  });

  describe('token revocation', () => {
    it('revokes a token', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const { accessToken } = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

      await methods.revokeToken(accessToken);

      const info = await methods.introspectToken(accessToken);
      expect(info.active).toBe(false);
    });
  });

  describe('pending flow (identity broker)', () => {
    it('creates and resumes a pending flow', async () => {
      const client = await methods.createClient({
        name: 'Moodle',
        redirectUris: ['https://lms.example.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://lms.example.com/callback',
        state: 'random-state-123',
      });

      const flow = await methods.resumePendingFlow(flowId);
      expect(flow.clientId).toBe(client.clientId);
      expect(flow.state).toBe('random-state-123');
    });

    it('pending flow is single-use', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/callback',
        state: 'state-1',
      });

      await methods.resumePendingFlow(flowId);

      await expect(methods.resumePendingFlow(flowId)).rejects.toThrow('not found');
    });
  });

  describe('getUserInfo', () => {
    it('returns user info for valid token', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/callback',
      });

      const { accessToken } = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        redirectUri: 'https://app.com/callback',
      });

      const user = await methods.getUserInfo(accessToken);
      expect(user).not.toBeNull();
      expect(user!.email).toBe('alice@example.com');
    });

    it('returns null for invalid token', async () => {
      const user = await methods.getUserInfo('invalid-token');
      expect(user).toBeNull();
    });
  });
});
