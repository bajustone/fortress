import type { DatabaseAdapter } from '../../adapters/database';
import type { OAuthMethods } from './index';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { generateCodeChallenge, generateCodeVerifier, oauth } from './index';

describe('oauth plugin', () => {
  let db: DatabaseAdapter;
  let methods: OAuthMethods;
  let userId: number;

  beforeEach(async () => {
    db = createTestAdapter();

    const plugin = oauth({
      authCodeExpirySeconds: 600,
      accessTokenExpirySeconds: 3600,
      issuerUrl: 'https://auth.example.com',
      scopePermissionMap: {
        'read:posts': { resource: 'post', action: 'read' },
        'write:posts': { resource: 'post', action: 'create' },
      },
    });
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

  describe('handleTokenRequest', () => {
    it('handles authorization_code grant type', async () => {
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

      const result = await methods.handleTokenRequest(
        { grant_type: 'authorization_code', code, redirect_uri: 'https://app.com/callback' },
        { clientId: client.clientId, clientSecret: client.clientSecret },
      );

      expect(result.access_token).toBeTruthy();
      expect(result.token_type).toBe('Bearer');
      expect(result.expires_in).toBe(3600);
    });

    it('handles client_credentials grant type', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const result = await methods.handleTokenRequest(
        { grant_type: 'client_credentials' },
        { clientId: client.clientId, clientSecret: client.clientSecret },
      );

      expect(result.access_token).toBeTruthy();
      expect(result.token_type).toBe('Bearer');
    });

    it('reads client credentials from body when no auth header', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const result = await methods.handleTokenRequest({
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: client.clientSecret,
      });

      expect(result.access_token).toBeTruthy();
    });

    it('rejects unsupported grant_type', async () => {
      await expect(
        methods.handleTokenRequest(
          { grant_type: 'implicit' },
          { clientId: 'any', clientSecret: 'any' },
        ),
      ).rejects.toThrow('Unsupported grant_type');
    });

    it('rejects missing client authentication', async () => {
      await expect(
        methods.handleTokenRequest({ grant_type: 'client_credentials' }),
      ).rejects.toThrow('Client authentication required');
    });
  });

  describe('handleIntrospectRequest', () => {
    it('returns active token info in RFC 7662 format', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const { accessToken } = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        scope: 'read:posts',
      });

      const result = await methods.handleIntrospectRequest(
        { token: accessToken },
        { clientId: client.clientId, clientSecret: client.clientSecret },
      );

      expect(result.active).toBe(true);
      expect(result.client_id).toBe(client.clientId);
      expect(result.token_type).toBe('Bearer');
      expect(result.scope).toBe('read:posts');
    });

    it('returns inactive for revoked token', async () => {
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

      const result = await methods.handleIntrospectRequest(
        { token: accessToken },
        { clientId: client.clientId, clientSecret: client.clientSecret },
      );

      expect(result.active).toBe(false);
    });
  });

  describe('handleRevokeRequest', () => {
    it('revokes token and always succeeds', async () => {
      // RFC 7009: revocation endpoint always returns 200
      await expect(methods.handleRevokeRequest({ token: 'nonexistent' })).resolves.toBeUndefined();
    });
  });

  describe('handleDiscovery', () => {
    it('returns OIDC discovery document', () => {
      const doc = methods.handleDiscovery();

      expect(doc.issuer).toBe('https://auth.example.com');
      expect(doc.token_endpoint).toBe('https://auth.example.com/oauth/token');
      expect(doc.introspection_endpoint).toBe('https://auth.example.com/oauth/introspect');
      expect(doc.revocation_endpoint).toBe('https://auth.example.com/oauth/revoke');
      expect(doc.userinfo_endpoint).toBe('https://auth.example.com/oauth/userinfo');
      expect(doc.grant_types_supported).toContain('authorization_code');
      expect(doc.grant_types_supported).toContain('client_credentials');
      expect(doc.code_challenge_methods_supported).toContain('S256');
    });
  });

  describe('resolveTokenPermissions', () => {
    it('maps scopes to IAM permissions', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const { accessToken } = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        scope: 'read:posts write:posts',
      });

      const permissions = await methods.resolveTokenPermissions(accessToken);

      expect(permissions).toEqual([
        { resource: 'post', action: 'read' },
        { resource: 'post', action: 'create' },
      ]);
    });

    it('returns empty for unknown scopes', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const { accessToken } = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        scope: 'unknown:scope',
      });

      const permissions = await methods.resolveTokenPermissions(accessToken);
      expect(permissions).toEqual([]);
    });

    it('returns empty for token with no scope', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      const { accessToken } = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

      const permissions = await methods.resolveTokenPermissions(accessToken);
      expect(permissions).toEqual([]);
    });
  });
});
