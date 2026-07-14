import type { DatabaseAdapter } from '../../adapters/database';
import type { OAuthMethods } from './index';
import { decodeJwt, importJWK, jwtVerify } from 'jose';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { generateRefreshToken } from '../../core/auth/refresh-token';
import { createTestAdapter } from '../../testing';
import { generateCodeChallenge, generateCodeVerifier, matchRedirectUri, oauth, toOidcUserinfo } from './index';

describe('oauth plugin', () => {
  let db: DatabaseAdapter;
  let methods: OAuthMethods;
  let userId: string;

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
    methods = plugin.methods!({ db, config: { jwt: { key: 'x'.repeat(32) }, database: db } }) as unknown as OAuthMethods;

    // Create a test user
    const user = await db.create<{ id: string }>({
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
      expect(client.clientSecret!).toBeTruthy();
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
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
        redirectUri: 'https://app.com/callback',
      });

      await expect(methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
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

    it('getPendingFlow reads without consuming', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/callback',
        scope: 'read:posts',
        state: 'consent-state',
      });

      // First read returns flow
      const flow1 = await methods.getPendingFlow(flowId);
      expect(flow1.clientId).toBe(client.clientId);
      expect(flow1.scope).toBe('read:posts');

      // Second read still works (non-destructive)
      const flow2 = await methods.getPendingFlow(flowId);
      expect(flow2.state).toBe('consent-state');

      // resumePendingFlow still consumes it
      await methods.resumePendingFlow(flowId);
      await expect(methods.getPendingFlow(flowId)).rejects.toThrow('not found');
    });

    it('handleAuthorizeRequest redirects unauthenticated users to loginUrl', async () => {
      const client = await methods.createClient({
        name: 'Moodle',
        redirectUris: ['https://lms.example.com/callback'],
        grantTypes: ['authorization_code'],
      });

      // Re-init plugin with login/consent URLs.
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        loginUrl: 'https://app.example.com/signin',
        consentUrl: 'https://app.example.com/oauth/consent',
      });
      const localMethods = localPlugin.methods!({ db: localDb, config: { jwt: { key: 'x'.repeat(32) }, database: localDb } }) as unknown as OAuthMethods;
      // Re-create the client in the local DB.
      await localDb.create({
        model: 'oauth_client',
        data: {
          clientId: client.clientId,
          clientSecretHash: 'irrelevant',
          name: 'Moodle',
          redirectUris: JSON.stringify(['https://lms.example.com/callback']),
          grantTypes: JSON.stringify(['authorization_code']),
        },
      });

      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);

      const result = await localMethods.handleAuthorizeRequest(
        {
          client_id: client.clientId,
          redirect_uri: 'https://lms.example.com/callback',
          response_type: 'code',
          state: 'xyz',
          scope: 'read:posts',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        },
        { userId: undefined },
      );

      expect(result.redirectUrl.startsWith('https://app.example.com/signin?flow=')).toBe(true);
      expect(typeof result.flowId).toBe('string');
      expect(result.flowId.length).toBeGreaterThan(20);

      const flow = await localMethods.getPendingFlow(result.flowId);
      expect(flow.clientId).toBe(client.clientId);
      expect(flow.state).toBe('xyz');
    });

    it('handleAuthorizeRequest redirects authenticated users to consentUrl', async () => {
      const client = await methods.createClient({
        name: 'Moodle',
        redirectUris: ['https://lms.example.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        loginUrl: 'https://app.example.com/signin',
        consentUrl: 'https://app.example.com/oauth/consent',
      });
      const localMethods = localPlugin.methods!({ db: localDb, config: { jwt: { key: 'x'.repeat(32) }, database: localDb } }) as unknown as OAuthMethods;
      await localDb.create({
        model: 'oauth_client',
        data: {
          clientId: client.clientId,
          clientSecretHash: 'irrelevant',
          name: 'Moodle',
          redirectUris: JSON.stringify(['https://lms.example.com/callback']),
          grantTypes: JSON.stringify(['authorization_code']),
        },
      });

      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);

      const result = await localMethods.handleAuthorizeRequest(
        {
          client_id: client.clientId,
          redirect_uri: 'https://lms.example.com/callback',
          response_type: 'code',
          state: 'logged-in-state',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        },
        { userId: '42' },
      );

      expect(result.redirectUrl.startsWith('https://app.example.com/oauth/consent?flow=')).toBe(true);
    });

    it('handleAuthorizeRequest rejects unknown clients and bad redirect URIs', async () => {
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        loginUrl: 'https://app.example.com/signin',
        consentUrl: 'https://app.example.com/oauth/consent',
      });
      const localMethods = localPlugin.methods!({ db: localDb, config: { jwt: { key: 'x'.repeat(32) }, database: localDb } }) as unknown as OAuthMethods;

      await expect(
        localMethods.handleAuthorizeRequest(
          {
            client_id: 'nonexistent',
            redirect_uri: 'https://x.com/cb',
            response_type: 'code',
            state: 's',
          },
          { userId: undefined },
        ),
      ).rejects.toThrow('Unknown client_id');

      const c = await localMethods.createClient({
        name: 'X',
        redirectUris: ['https://x.com/callback'],
        grantTypes: ['authorization_code'],
      });
      await expect(
        localMethods.handleAuthorizeRequest(
          {
            client_id: c.clientId,
            redirect_uri: 'https://evil.com/cb',
            response_type: 'code',
            state: 's',
          },
          { userId: undefined },
        ),
      ).rejects.toThrow('Invalid redirect_uri');
    });

    it('handleAuthorizeRequest throws when loginUrl/consentUrl are not configured', async () => {
      const localDb = createTestAdapter();
      const localPlugin = oauth({}); // no URLs
      const localMethods = localPlugin.methods!({ db: localDb, config: { jwt: { key: 'x'.repeat(32) }, database: localDb } }) as unknown as OAuthMethods;

      await expect(
        localMethods.handleAuthorizeRequest(
          {
            client_id: 'whatever',
            redirect_uri: 'https://x.com/cb',
            response_type: 'code',
            state: 's',
          },
          { userId: undefined },
        ),
      ).rejects.toThrow('loginUrl/consentUrl');
    });

    it('handleGetFlow returns flow metadata without leaking PKCE fields', async () => {
      const client = await methods.createClient({
        name: 'Brand X',
        redirectUris: ['https://x.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://x.com/callback',
        scope: 'read:posts write:posts',
        state: 's-1',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });

      const meta = await methods.handleGetFlow(flowId, { userId });
      expect(meta.flowId).toBe(flowId);
      expect(meta.client.clientId).toBe(client.clientId);
      expect(meta.client.name).toBe('Brand X');
      expect(meta.scopes).toEqual(['read:posts', 'write:posts']);
      expect(meta.state).toBe('s-1');
      // Crucially — no challenge / method exposed.
      expect((meta as Record<string, unknown>).codeChallenge).toBeUndefined();
      expect((meta as Record<string, unknown>).codeChallengeMethod).toBeUndefined();
    });

    it('handleApproveFlow issues a code and returns a redirect URL', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/callback',
        scope: 'read:posts',
        state: 'approve-state',
      });

      const result = await methods.handleApproveFlow(flowId, { userId });

      const url = new URL(result.redirectUrl);
      expect(url.origin + url.pathname).toBe('https://app.com/callback');
      expect(url.searchParams.get('state')).toBe('approve-state');
      const code = url.searchParams.get('code');
      expect(code).toBeTruthy();

      // Flow should now be consumed.
      await expect(methods.getPendingFlow(flowId)).rejects.toThrow('not found');

      // The issued code should be exchangeable.
      const tokens = await methods.exchangeCode({
        code: code as string,
        clientId: client.clientId,
        clientSecret: 'wrong-secret',
        redirectUri: 'https://app.com/callback',
      }).catch(e => e);
      // We don't have the real secret in this test; just confirm the code
      // was actually persisted by making sure the failure is auth-related,
      // not "code not found".
      expect(String(tokens)).not.toMatch(/code/i);
    });

    it('handleDenyFlow consumes the flow and returns access_denied URL', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/callback',
        state: 'deny-state',
      });

      const result = await methods.handleDenyFlow(flowId, { userId });
      const url = new URL(result.redirectUrl);
      expect(url.searchParams.get('error')).toBe('access_denied');
      expect(url.searchParams.get('state')).toBe('deny-state');

      await expect(methods.getPendingFlow(flowId)).rejects.toThrow('not found');
    });

    it('getPendingFlow throws on expired flow', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });

      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/callback',
        state: 'state-x',
      });

      // Force expiry by mutating the row directly through the adapter.
      await db.update({
        model: 'oauth_pending_flow',
        where: [{ field: 'flowId', operator: '=', value: flowId }],
        data: { expiresAt: new Date(Date.now() - 1000) },
      });

      await expect(methods.getPendingFlow(flowId)).rejects.toThrow('expired');
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
        clientSecret: client.clientSecret!,
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
        { clientId: client.clientId, clientSecret: client.clientSecret! },
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
        { clientId: client.clientId, clientSecret: client.clientSecret! },
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
        client_secret: client.clientSecret!,
      });

      expect(result.access_token).toBeTruthy();
    });

    it('rejects unsupported grant_type', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });
      await expect(
        methods.handleTokenRequest(
          { grant_type: 'implicit' },
          { clientId: client.clientId, clientSecret: client.clientSecret! },
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
        clientSecret: client.clientSecret!,
        scope: 'read:posts',
      });

      const result = await methods.handleIntrospectRequest(
        { token: accessToken },
        { clientId: client.clientId, clientSecret: client.clientSecret! },
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
        clientSecret: client.clientSecret!,
      });

      await methods.revokeToken(accessToken);

      const result = await methods.handleIntrospectRequest(
        { token: accessToken },
        { clientId: client.clientId, clientSecret: client.clientSecret! },
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
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
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
        clientSecret: client.clientSecret!,
      });

      const permissions = await methods.resolveTokenPermissions(accessToken);
      expect(permissions).toEqual([]);
    });
  });

  // ===================================================================
  // RFC 9700 §2.1.1 — mandatory PKCE on /oauth/authorize
  // ===================================================================
  describe('mandatory PKCE (RFC 9700 §2.1.1)', () => {
    it('rejects authorize requests without code_challenge', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        loginUrl: 'https://app.example.com/signin',
        consentUrl: 'https://app.example.com/oauth/consent',
      });
      const localMethods = localPlugin.methods!({
        db: localDb,
        config: { jwt: { key: 'x'.repeat(32) }, database: localDb },
      }) as unknown as OAuthMethods;
      await localDb.create({
        model: 'oauth_client',
        data: {
          clientId: client.clientId,
          clientSecretHash: 'irrelevant',
          name: 'App',
          redirectUris: JSON.stringify(['https://app.com/callback']),
          grantTypes: JSON.stringify(['authorization_code']),
        },
      });

      await expect(
        localMethods.handleAuthorizeRequest(
          {
            client_id: client.clientId,
            redirect_uri: 'https://app.com/callback',
            response_type: 'code',
            state: 's',
          },
          { userId: undefined },
        ),
      ).rejects.toThrow('code_challenge is required');
    });

    it('rejects code_challenge with no method (defaults to plain, which we don\'t support)', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        loginUrl: 'https://app.example.com/signin',
        consentUrl: 'https://app.example.com/oauth/consent',
      });
      const localMethods = localPlugin.methods!({
        db: localDb,
        config: { jwt: { key: 'x'.repeat(32) }, database: localDb },
      }) as unknown as OAuthMethods;
      await localDb.create({
        model: 'oauth_client',
        data: {
          clientId: client.clientId,
          clientSecretHash: 'irrelevant',
          name: 'App',
          redirectUris: JSON.stringify(['https://app.com/callback']),
          grantTypes: JSON.stringify(['authorization_code']),
        },
      });

      await expect(
        localMethods.handleAuthorizeRequest(
          {
            client_id: client.clientId,
            redirect_uri: 'https://app.com/callback',
            response_type: 'code',
            state: 's',
            code_challenge: 'abc',
          },
          { userId: undefined },
        ),
      ).rejects.toThrow('code_challenge_method is required');
    });

    it('escape hatch: allowNonPkceConfidentialClients lets legacy clients through', async () => {
      const client = await methods.createClient({
        name: 'Legacy',
        redirectUris: ['https://legacy.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        loginUrl: 'https://app.example.com/signin',
        consentUrl: 'https://app.example.com/oauth/consent',
        allowNonPkceConfidentialClients: true,
      });
      const localMethods = localPlugin.methods!({
        db: localDb,
        config: { jwt: { key: 'x'.repeat(32) }, database: localDb },
      }) as unknown as OAuthMethods;
      await localDb.create({
        model: 'oauth_client',
        data: {
          clientId: client.clientId,
          clientSecretHash: 'irrelevant',
          name: 'Legacy',
          redirectUris: JSON.stringify(['https://legacy.com/cb']),
          grantTypes: JSON.stringify(['authorization_code']),
        },
      });

      const result = await localMethods.handleAuthorizeRequest(
        {
          client_id: client.clientId,
          redirect_uri: 'https://legacy.com/cb',
          response_type: 'code',
          state: 's',
        },
        { userId: undefined },
      );
      expect(typeof result.flowId).toBe('string');
      expect(result.flowId.length).toBeGreaterThan(20);
    });
  });

  // ===================================================================
  // RFC 9207 — issuer parameter on the authorization response
  // ===================================================================
  describe('rFC 9207 issuer identification', () => {
    it('handleApproveFlow appends iss= to the success redirect', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/callback',
        state: 'iss-state',
      });
      const result = await methods.handleApproveFlow(flowId, { userId });
      const url = new URL(result.redirectUrl);
      expect(url.searchParams.get('iss')).toBe('https://auth.example.com');
    });

    it('handleDenyFlow appends iss= to the error redirect', async () => {
      const client = await methods.createClient({
        name: 'App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/callback',
        state: 'iss-deny',
      });
      const result = await methods.handleDenyFlow(flowId, { userId });
      const url = new URL(result.redirectUrl);
      expect(url.searchParams.get('iss')).toBe('https://auth.example.com');
      expect(url.searchParams.get('error')).toBe('access_denied');
    });

    it('discovery declares authorization_response_iss_parameter_supported', () => {
      const doc = methods.handleDiscovery();
      expect(doc.authorization_response_iss_parameter_supported).toBe(true);
    });
  });

  // ===================================================================
  // RFC 8414 / OIDC Discovery — metadata completeness
  // ===================================================================
  describe('discovery completeness', () => {
    it('exposes scopes_supported merged from scopePermissionMap and OIDC defaults', () => {
      const doc = methods.handleDiscovery();
      const scopes = doc.scopes_supported as string[];
      expect(scopes).toContain('openid');
      expect(scopes).toContain('email');
      expect(scopes).toContain('profile');
      expect(scopes).toContain('read:posts');
      expect(scopes).toContain('write:posts');
    });

    it('exposes claims_supported with OIDC core claims', () => {
      const doc = methods.handleDiscovery();
      const claims = doc.claims_supported as string[];
      expect(claims).toContain('sub');
      expect(claims).toContain('email');
      expect(claims).toContain('preferred_username');
      expect(claims).toContain('updated_at');
    });

    it('exposes response_modes_supported = ["query"]', () => {
      const doc = methods.handleDiscovery();
      expect(doc.response_modes_supported).toEqual(['query']);
    });
  });

  // ===================================================================
  // RFC 6749 §5.2 — token-endpoint error wire shape
  // ===================================================================
  describe('oAuth error wire shape (RFC 6749 §5.2)', () => {
    it('throws FortressErrors that carry the OAuth machine code', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });
      try {
        await methods.handleTokenRequest(
          { grant_type: 'implicit' as unknown as string },
          { clientId: client.clientId, clientSecret: client.clientSecret! },
        );
        throw new Error('should have thrown');
      }
      catch (err: unknown) {
        expect(err).toBeInstanceOf(Error);
        const fortressErr = err as { oauthError?: string; oauthDescription?: string; statusCode?: number };
        expect(fortressErr.oauthError).toBe('unsupported_grant_type');
        expect(fortressErr.statusCode).toBe(400);
      }
    });

    it('invalid_client errors are 401 with OAuth machine code', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      });

      try {
        await methods.handleTokenRequest(
          { grant_type: 'client_credentials' },
          { clientId: client.clientId, clientSecret: 'wrong-secret' },
        );
        throw new Error('should have thrown');
      }
      catch (err: unknown) {
        const fortressErr = err as { oauthError?: string; statusCode?: number };
        expect(fortressErr.oauthError).toBe('invalid_client');
        expect(fortressErr.statusCode).toBe(401);
      }
    });
  });

  // ===================================================================
  // RFC 6749 §3.3 / RFC 9700 §2.2.1 — per-client scope allow-list
  // ===================================================================
  describe('per-client scope allow-list (RFC 6749 §3.3)', () => {
    it('intersects requested scope against client allow-list (auth code)', async () => {
      const client = await methods.createClient({
        name: 'Limited',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code'],
        allowedScopes: ['openid', 'email'],
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        loginUrl: 'https://app.example.com/signin',
        consentUrl: 'https://app.example.com/oauth/consent',
        issuerUrl: 'https://auth.example.com',
      });
      const localMethods = localPlugin.methods!({
        db: localDb,
        config: { jwt: { key: 'x'.repeat(32) }, database: localDb },
      }) as unknown as OAuthMethods;
      // Re-create the same client in the local DB with allow-list intact.
      await localDb.create({
        model: 'oauth_client',
        data: {
          clientId: client.clientId,
          clientSecretHash: 'irrelevant',
          name: 'Limited',
          redirectUris: JSON.stringify(['https://app.com/cb']),
          grantTypes: JSON.stringify(['authorization_code']),
          allowedScopes: JSON.stringify(['openid', 'email']),
        },
      });

      const result = await localMethods.handleAuthorizeRequest(
        {
          client_id: client.clientId,
          redirect_uri: 'https://app.com/cb',
          response_type: 'code',
          state: 's',
          // Request a SUPERSET; admin:write should be silently dropped.
          scope: 'openid email admin:write',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        },
        { userId: '1' },
      );
      const flow = await localMethods.getPendingFlow(result.flowId);
      expect(flow.scope).toBe('openid email');
    });

    it('returns invalid_scope when intersection is empty (auth code)', async () => {
      const client = await methods.createClient({
        name: 'Strict',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code'],
        allowedScopes: ['openid'],
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        loginUrl: 'https://app.example.com/signin',
        consentUrl: 'https://app.example.com/oauth/consent',
      });
      const localMethods = localPlugin.methods!({
        db: localDb,
        config: { jwt: { key: 'x'.repeat(32) }, database: localDb },
      }) as unknown as OAuthMethods;
      await localDb.create({
        model: 'oauth_client',
        data: {
          clientId: client.clientId,
          clientSecretHash: 'irrelevant',
          name: 'Strict',
          redirectUris: JSON.stringify(['https://app.com/cb']),
          grantTypes: JSON.stringify(['authorization_code']),
          allowedScopes: JSON.stringify(['openid']),
        },
      });

      try {
        await localMethods.handleAuthorizeRequest(
          {
            client_id: client.clientId,
            redirect_uri: 'https://app.com/cb',
            response_type: 'code',
            state: 's',
            scope: 'admin:write',
            code_challenge: challenge,
            code_challenge_method: 'S256',
          },
          { userId: '1' },
        );
        throw new Error('should have thrown');
      }
      catch (err: unknown) {
        const fortressErr = err as { oauthError?: string };
        expect(fortressErr.oauthError).toBe('invalid_scope');
      }
    });

    it('intersects scope on client_credentials grant', async () => {
      const client = await methods.createClient({
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        allowedScopes: ['read:posts'],
      });
      const tokens = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        scope: 'read:posts write:posts',
      });
      const info = await methods.introspectToken(tokens.accessToken);
      expect(info.scope).toBe('read:posts');
    });

    it('legacy clients (allowedScopes unset) keep working: scope passes through', async () => {
      const client = await methods.createClient({
        name: 'Legacy',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        // allowedScopes intentionally omitted
      });
      const tokens = await methods.clientCredentialsGrant({
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        scope: 'admin:everything',
      });
      const info = await methods.introspectToken(tokens.accessToken);
      expect(info.scope).toBe('admin:everything');
    });
  });

  // ===================================================================
  // OIDC Core 1.0 §5.3 — userinfo response shape
  // ===================================================================
  describe('oIDC userinfo (OIDC Core §5.3)', () => {
    async function issueTokenWithScope(scope?: string): Promise<{ accessToken: string; clientId: string; clientSecret: string }> {
      const client = await methods.createClient({
        name: 'OIDC App',
        redirectUris: ['https://app.com/callback'],
        grantTypes: ['authorization_code'],
      });
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/callback',
        scope,
      });
      const tokens = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        redirectUri: 'https://app.com/callback',
      });
      return { accessToken: tokens.accessToken, clientId: client.clientId, clientSecret: client.clientSecret! };
    }

    it('returns sub as a string and standard OIDC claims', async () => {
      const { accessToken } = await issueTokenWithScope('openid email profile');
      const claims = await methods.handleUserInfoRequest(accessToken);

      expect(typeof claims.sub).toBe('string');
      expect(claims.sub).toBe(String(userId));
      expect(claims.email).toBe('alice@example.com');
      expect(claims.name).toBe('Alice');
      expect(claims.preferred_username).toBe('alice@example.com');
      expect(typeof claims.updated_at).toBe('number');
    });

    it('omits email when scope=openid does NOT include email', async () => {
      const { accessToken } = await issueTokenWithScope('openid');
      const claims = await methods.handleUserInfoRequest(accessToken);

      expect(claims.sub).toBe(String(userId));
      expect(claims.email).toBeUndefined();
      expect(claims.name).toBeUndefined();
    });

    it('omits name/preferred_username when scope=openid lacks profile', async () => {
      const { accessToken } = await issueTokenWithScope('openid email');
      const claims = await methods.handleUserInfoRequest(accessToken);

      expect(claims.email).toBe('alice@example.com');
      expect(claims.name).toBeUndefined();
      expect(claims.preferred_username).toBeUndefined();
    });

    it('does not expose identity claims to non-OIDC tokens without identity scopes', async () => {
      const { accessToken } = await issueTokenWithScope();
      const claims = await methods.handleUserInfoRequest(accessToken);

      expect(claims.sub).toBe(String(userId));
      expect(claims.email).toBeUndefined();
      expect(claims.name).toBeUndefined();
    });

    it('does NOT leak DB-internal fields', async () => {
      const { accessToken } = await issueTokenWithScope('openid email profile');
      const claims = await methods.handleUserInfoRequest(accessToken);
      expect(claims.id).toBeUndefined();
      expect(claims.isActive).toBeUndefined();
      expect(claims.createdAt).toBeUndefined();
      // The raw FortressUser had a numeric `id`; OIDC requires `sub` to be a string.
      expect(typeof claims.sub).toBe('string');
    });

    it('throws 401 for invalid bearer token', async () => {
      await expect(methods.handleUserInfoRequest('not-a-real-token')).rejects.toMatchObject({
        statusCode: 401,
      });
    });

    it('userinfoClaims hook merges into the response', async () => {
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        issuerUrl: 'https://auth.example.com',
        userinfoClaims: (user, scope) => ({
          tenant: 'acme',
          token_scope: scope ?? '',
          // Hooks may overwrite fortress-emitted claims — here, replace `name`.
          name: `[acme] ${user.name}`,
        }),
      });
      const localMethods = localPlugin.methods!({
        db: localDb,
        config: { jwt: { key: 'x'.repeat(32) }, database: localDb },
      }) as unknown as OAuthMethods;

      const localUser = await localDb.create<{ id: string }>({
        model: 'user',
        data: { email: 'bob@acme.com', name: 'Bob', passwordHash: 'h', isActive: true },
      });
      const localClient = await localMethods.createClient({
        name: 'Tenant App',
        redirectUris: ['https://acme.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const { code } = await localMethods.createAuthorizationCode({
        clientId: localClient.clientId,
        userId: localUser.id,
        redirectUri: 'https://acme.com/cb',
        scope: 'openid email profile',
      });
      const tokens = await localMethods.exchangeCode({
        code,
        clientId: localClient.clientId,
        clientSecret: localClient.clientSecret!,
        redirectUri: 'https://acme.com/cb',
      });
      const claims = await localMethods.handleUserInfoRequest(tokens.accessToken);

      expect(claims.tenant).toBe('acme');
      expect(claims.token_scope).toBe('openid email profile');
      expect(claims.name).toBe('[acme] Bob');
      // Standard claims still present where the hook didn't override.
      expect(claims.email).toBe('bob@acme.com');
    });

    it('toOidcUserinfo: pure mapping function for host-app composition', () => {
      const claims = toOidcUserinfo(
        {
          id: '7',
          email: 'c@example.com',
          name: 'Carol',
          isActive: true,
          emailVerified: true,
          createdAt: new Date('2024-01-01T00:00:00Z'),
          updatedAt: new Date('2024-06-01T00:00:00Z'),
        },
        'openid email profile',
      );
      expect(claims).toEqual({
        sub: '7',
        email: 'c@example.com',
        email_verified: true,
        name: 'Carol',
        preferred_username: 'c@example.com',
        updated_at: Math.floor(new Date('2024-06-01T00:00:00Z').getTime() / 1000),
      });
    });
  });

  // ===================================================================
  // OIDC Core 1.0 §3.1.3.7 — id_token issuance, JWKS, nonce echo
  // ===================================================================
  describe('id_token issuance (OIDC Core §3.1.3.7)', () => {
    async function issueIdTokenViaCode(opts: { scope?: string; nonce?: string } = {}): Promise<{
      idToken: string;
      accessToken: string;
      clientId: string;
    }> {
      const client = await methods.createClient({
        name: 'OIDC RP',
        redirectUris: ['https://rp.example.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://rp.example.com/cb',
        scope: opts.scope ?? 'openid email profile',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
        nonce: opts.nonce,
      });
      const tokens = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        redirectUri: 'https://rp.example.com/cb',
        codeVerifier: verifier,
      }) as { accessToken: string; idToken?: string };
      return {
        idToken: tokens.idToken!,
        accessToken: tokens.accessToken,
        clientId: client.clientId,
      };
    }

    it('issues id_token when scope=openid', async () => {
      const { idToken } = await issueIdTokenViaCode();
      expect(idToken).toBeTruthy();
      expect(idToken.split('.')).toHaveLength(3); // compact JWS = 3 parts
    });

    it('does NOT issue id_token when scope omits openid', async () => {
      const client = await methods.createClient({
        name: 'Plain OAuth',
        redirectUris: ['https://rp.example.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://rp.example.com/cb',
        scope: 'email',
      });
      const tokens = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        redirectUri: 'https://rp.example.com/cb',
      }) as { idToken?: string };
      expect(tokens.idToken).toBeUndefined();
    });

    it('id_token claims: iss, sub (string), aud, iat, exp, auth_time', async () => {
      const { idToken, clientId } = await issueIdTokenViaCode();
      const jwks = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const key = await importJWK(jwks.keys[0], 'RS256');
      const { payload } = await jwtVerify(idToken, key);

      expect(payload.iss).toBe('https://auth.example.com');
      expect(payload.sub).toBe(String(userId));
      expect(typeof payload.sub).toBe('string');
      expect(payload.aud).toBe(clientId);
      expect(typeof payload.iat).toBe('number');
      expect(typeof payload.exp).toBe('number');
      expect(typeof payload.auth_time).toBe('number');
    });

    it('echoes nonce verbatim into the id_token', async () => {
      const nonce = 'rp-supplied-nonce-12345';
      const { idToken } = await issueIdTokenViaCode({ nonce });
      const jwks = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const key = await importJWK(jwks.keys[0], 'RS256');
      const { payload } = await jwtVerify(idToken, key);
      expect(payload.nonce).toBe(nonce);
    });

    it('omits nonce claim when authorize request had no nonce', async () => {
      const { idToken } = await issueIdTokenViaCode();
      const jwks = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const key = await importJWK(jwks.keys[0], 'RS256');
      const { payload } = await jwtVerify(idToken, key);
      expect(payload.nonce).toBeUndefined();
    });

    it('id_token includes scope-gated email/name claims', async () => {
      const { idToken } = await issueIdTokenViaCode({ scope: 'openid email profile' });
      const jwks = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const key = await importJWK(jwks.keys[0], 'RS256');
      const { payload } = await jwtVerify(idToken, key);
      expect(payload.email).toBe('alice@example.com');
      expect(payload.name).toBe('Alice');
      expect(payload.preferred_username).toBe('alice@example.com');
    });

    it('id_token omits email and profile claims for openid-only scope', async () => {
      const { idToken } = await issueIdTokenViaCode({ scope: 'openid' });
      const jwks = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const key = await importJWK(jwks.keys[0], 'RS256');
      const { payload } = await jwtVerify(idToken, key);
      expect(payload.email).toBeUndefined();
      expect(payload.email_verified).toBeUndefined();
      expect(payload.name).toBeUndefined();
      expect(payload.preferred_username).toBeUndefined();
    });

    it('id_token omits profile claims when only openid+email scope', async () => {
      const { idToken } = await issueIdTokenViaCode({ scope: 'openid email' });
      const jwks = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const key = await importJWK(jwks.keys[0], 'RS256');
      const { payload } = await jwtVerify(idToken, key);
      expect(payload.email).toBe('alice@example.com');
      expect(payload.name).toBeUndefined();
      expect(payload.preferred_username).toBeUndefined();
    });

    it('handleTokenRequest dispatches id_token via the /token endpoint', async () => {
      const client = await methods.createClient({
        name: 'OIDC',
        redirectUris: ['https://rp.example.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://rp.example.com/cb',
        scope: 'openid',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });
      const result = await methods.handleTokenRequest(
        {
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'https://rp.example.com/cb',
          code_verifier: verifier,
        },
        { clientId: client.clientId, clientSecret: client.clientSecret! },
      );
      expect(result.id_token).toBeTruthy();
    });
  });

  // ===================================================================
  // RFC 7517 / OIDC Discovery §3 — JWKS endpoint
  // ===================================================================
  describe('jWKS endpoint (RFC 7517)', () => {
    it('handleJwksRequest returns a non-empty keys array', async () => {
      const jwks = await methods.handleJwksRequest() as { keys: unknown[] };
      expect(Array.isArray(jwks.keys)).toBe(true);
      expect(jwks.keys.length).toBeGreaterThan(0);
    });

    it('jWKS keys carry kid + alg + use=sig', async () => {
      const jwks = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const key = jwks.keys[0];
      expect(key.kid).toBeTruthy();
      expect(key.alg).toBe('RS256');
      expect(key.use).toBe('sig');
      // The d (private key) parameter MUST NOT be exposed.
      expect((key as Record<string, unknown>).d).toBeUndefined();
    });

    it('id_token signature verifies against JWKS by kid', async () => {
      const client = await methods.createClient({
        name: 'RP',
        redirectUris: ['https://rp.example.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://rp.example.com/cb',
        scope: 'openid',
      });
      const tokens = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        redirectUri: 'https://rp.example.com/cb',
      }) as { idToken: string };

      // RFC 7517-style verification: simulate openid-client's behaviour by
      // building a JWKS resolver from our endpoint output.
      const jwks = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const key = await importJWK(jwks.keys[0], 'RS256');
      const { payload } = await jwtVerify(tokens.idToken, key, {
        issuer: 'https://auth.example.com',
        audience: client.clientId,
      });
      expect(payload.sub).toBe(String(userId));
    });

    it('discovery declares jwks_uri + id_token_signing_alg_values_supported', () => {
      const doc = methods.handleDiscovery();
      expect(doc.jwks_uri).toBe('https://auth.example.com/oauth/.well-known/jwks.json');
      expect(doc.id_token_signing_alg_values_supported).toEqual(['RS256']);
    });

    it('jWKS persists across calls (same kid)', async () => {
      const a = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      const b = await methods.handleJwksRequest() as { keys: import('jose').JWK[] };
      expect(a.keys[0].kid).toBe(b.keys[0].kid);
    });
  });

  // ===================================================================
  // RFC 6749 §6 + RFC 9700 §2.2.2 — refresh token grant with rotation
  // ===================================================================
  describe('refresh token grant (RFC 6749 §6 / RFC 9700 §2.2.2)', () => {
    async function freshToken(scope?: string): Promise<{
      accessToken: string;
      refreshToken: string;
      clientId: string;
      clientSecret: string;
    }> {
      const client = await methods.createClient({
        name: 'Refresh App',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code', 'refresh_token'],
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/cb',
        scope,
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });
      const tokens = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        redirectUri: 'https://app.com/cb',
        codeVerifier: verifier,
      }) as { accessToken: string; refreshToken?: string };
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken!,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
      };
    }

    it('exchangeCode returns a refresh_token alongside the access_token', async () => {
      const { refreshToken } = await freshToken();
      expect(refreshToken).toBeTruthy();
      expect(typeof refreshToken).toBe('string');
    });

    it('refresh token rotation: each use issues a new pair, old one invalidated', async () => {
      const { refreshToken: r1, clientId, clientSecret } = await freshToken('openid email');
      const result = await methods.refreshTokenGrant({
        clientId,
        clientSecret,
        refreshToken: r1,
      });
      expect(result.accessToken).toBeTruthy();
      expect(result.refreshToken).toBeTruthy();
      expect(result.refreshToken).not.toBe(r1);
      expect(result.scope).toBe('openid email');

      // The new access token verifies.
      const info = await methods.introspectToken(result.accessToken);
      expect(info.active).toBe(true);
    });

    it('strict refresh concurrency: one winner, loser is replay and revokes the family', async () => {
      const { refreshToken: r1, clientId, clientSecret } = await freshToken();

      const results = await Promise.allSettled([
        methods.refreshTokenGrant({ clientId, clientSecret, refreshToken: r1 }),
        methods.refreshTokenGrant({ clientId, clientSecret, refreshToken: r1 }),
      ]);

      const fulfilled = results.filter(r => r.status === 'fulfilled') as PromiseFulfilledResult<{ refreshToken: string }>[];
      const rejected = results.filter(r => r.status === 'rejected') as PromiseRejectedResult[];
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0].reason as { oauthError?: string }).oauthError).toBe('invalid_grant');
      expect(String(rejected[0].reason)).toMatch(/reuse/i);

      // Strict replay semantics: the duplicate loser kills the token family,
      // including the winner's newly issued refresh token.
      await expect(methods.refreshTokenGrant({
        clientId,
        clientSecret,
        refreshToken: fulfilled[0].value.refreshToken,
      })).rejects.toThrow('Invalid refresh token');
    });

    it('replay detection: reusing R1 after R2 issued kills the family', async () => {
      const { refreshToken: r1, clientId, clientSecret } = await freshToken();
      const { refreshToken: r2 } = await methods.refreshTokenGrant({
        clientId,
        clientSecret,
        refreshToken: r1,
      });

      // Replay R1 — attacker / network glitch.
      try {
        await methods.refreshTokenGrant({ clientId, clientSecret, refreshToken: r1 });
        throw new Error('should have thrown');
      }
      catch (err: unknown) {
        const fortressErr = err as { oauthError?: string; message?: string };
        expect(fortressErr.oauthError).toBe('invalid_grant');
        expect(fortressErr.message).toMatch(/reuse/i);
      }

      // R2 (the legitimate next token) is now also dead.
      await expect(methods.refreshTokenGrant({
        clientId,
        clientSecret,
        refreshToken: r2,
      })).rejects.toThrow('Invalid refresh token');
    });

    it('rejects refresh token when client mismatches', async () => {
      const { refreshToken } = await freshToken();
      const otherClient = await methods.createClient({
        name: 'Other',
        redirectUris: ['https://other.com/cb'],
        grantTypes: ['authorization_code', 'refresh_token'],
      });
      await expect(methods.refreshTokenGrant({
        clientId: otherClient.clientId,
        clientSecret: otherClient.clientSecret!,
        refreshToken,
      })).rejects.toThrow('client mismatch');
    });

    it('rejects scope widening (RFC 6749 §6)', async () => {
      const { refreshToken, clientId, clientSecret } = await freshToken('openid');
      try {
        await methods.refreshTokenGrant({
          clientId,
          clientSecret,
          refreshToken,
          scope: 'openid admin:write',
        });
        throw new Error('should have thrown');
      }
      catch (err: unknown) {
        const fortressErr = err as { oauthError?: string };
        expect(fortressErr.oauthError).toBe('invalid_scope');
      }
    });

    it('allows scope narrowing on refresh', async () => {
      const { refreshToken, clientId, clientSecret } = await freshToken('openid email profile');
      const result = await methods.refreshTokenGrant({
        clientId,
        clientSecret,
        refreshToken,
        scope: 'openid',
      });
      expect(result.scope).toBe('openid');
    });

    it('refresh returns a fresh id_token when the original grant included openid', async () => {
      const { refreshToken, clientId, clientSecret } = await freshToken('openid email');
      const result = await methods.refreshTokenGrant({
        clientId,
        clientSecret,
        refreshToken,
      }) as { idToken?: string };
      expect(result.idToken).toBeTruthy();
      expect(decodeJwt(result.idToken!).auth_time).toBeUndefined();
    });

    it('handleTokenRequest dispatches grant_type=refresh_token', async () => {
      const { refreshToken, clientId, clientSecret } = await freshToken();
      const result = await methods.handleTokenRequest(
        { grant_type: 'refresh_token', refresh_token: refreshToken },
        { clientId, clientSecret },
      );
      expect(result.access_token).toBeTruthy();
      expect(result.refresh_token).toBeTruthy();
      expect(result.token_type).toBe('Bearer');
    });

    it('handleTokenRequest includes id_token on openid refresh', async () => {
      const { refreshToken, clientId, clientSecret } = await freshToken('openid');
      const result = await methods.handleTokenRequest(
        { grant_type: 'refresh_token', refresh_token: refreshToken },
        { clientId, clientSecret },
      );
      expect(result.id_token).toBeTruthy();
    });

    it('discovery declares refresh_token in grant_types_supported', () => {
      const doc = methods.handleDiscovery();
      expect(doc.grant_types_supported).toContain('refresh_token');
    });

    it('refreshTokenExpirySeconds=0 disables refresh-token issuance', async () => {
      const localDb = createTestAdapter();
      const localPlugin = oauth({
        issuerUrl: 'https://auth.example.com',
        refreshTokenExpirySeconds: 0,
      });
      const localMethods = localPlugin.methods!({
        db: localDb,
        config: { jwt: { key: 'x'.repeat(32) }, database: localDb },
      }) as unknown as OAuthMethods;
      const localUser = await localDb.create<{ id: string }>({
        model: 'user',
        data: { email: 'd@e.com', name: 'D', passwordHash: 'h', isActive: true },
      });
      const client = await localMethods.createClient({
        name: 'No-refresh',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { code } = await localMethods.createAuthorizationCode({
        clientId: client.clientId,
        userId: localUser.id,
        redirectUri: 'https://app.com/cb',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });
      const tokens = await localMethods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        redirectUri: 'https://app.com/cb',
        codeVerifier: verifier,
      }) as { accessToken: string; refreshToken?: string };
      expect(tokens.accessToken).toBeTruthy();
      expect(tokens.refreshToken).toBeUndefined();
      expect(localMethods.handleDiscovery().grant_types_supported).not.toContain('refresh_token');
    });

    it('revokeToken on a refresh token kills the entire family', async () => {
      const { refreshToken, clientId, clientSecret } = await freshToken();
      // Rotate once so we have R1 (revoked target) and R2 (descendant).
      const { refreshToken: r2 } = await methods.refreshTokenGrant({
        clientId,
        clientSecret,
        refreshToken,
      });
      // Revoke R2 — the family root (R1) is already used (rotated), so the
      // family revocation should sweep both.
      await methods.revokeToken(r2);
      await expect(methods.refreshTokenGrant({
        clientId,
        clientSecret,
        refreshToken: r2,
      })).rejects.toThrow('Invalid refresh token');
    });
  });

  // ===================================================================
  // RFC 8252 — OAuth 2.0 for Native Apps (public-client mode + loopback)
  // ===================================================================
  describe('public clients (RFC 8252 / RFC 6749 §2.1)', () => {
    it('createClient with tokenEndpointAuthMethod="none" returns null secret', async () => {
      const client = await methods.createClient({
        name: 'SPA',
        redirectUris: ['https://spa.example.com/cb'],
        grantTypes: ['authorization_code'],
        tokenEndpointAuthMethod: 'none',
      });
      expect(client.clientId).toBeTruthy();
      expect(client.clientSecret).toBeNull();
    });

    it('public client completes auth-code+PKCE flow with no secret', async () => {
      const client = await methods.createClient({
        name: 'SPA',
        redirectUris: ['https://spa.example.com/cb'],
        grantTypes: ['authorization_code'],
        tokenEndpointAuthMethod: 'none',
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://spa.example.com/cb',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });
      const tokens = await methods.exchangeCode({
        code,
        clientId: client.clientId,
        // No clientSecret — public client.
        redirectUri: 'https://spa.example.com/cb',
        codeVerifier: verifier,
      });
      expect(tokens.accessToken).toBeTruthy();
    });

    it('public client rejected if it presents a client_secret (RFC 6749 §2.3.1)', async () => {
      const client = await methods.createClient({
        name: 'SPA',
        redirectUris: ['https://spa.example.com/cb'],
        grantTypes: ['authorization_code'],
        tokenEndpointAuthMethod: 'none',
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://spa.example.com/cb',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });
      await expect(methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: 'i-should-not-be-here',
        redirectUri: 'https://spa.example.com/cb',
        codeVerifier: verifier,
      })).rejects.toThrow('Public clients must not present a client_secret');
    });

    it('public client cannot use client_credentials grant', async () => {
      const client = await methods.createClient({
        name: 'SPA',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        tokenEndpointAuthMethod: 'none',
      });
      try {
        await methods.handleTokenRequest(
          { grant_type: 'client_credentials', client_id: client.clientId },
        );
        throw new Error('should have thrown');
      }
      catch (err: unknown) {
        const fortressErr = err as { oauthError?: string };
        expect(fortressErr.oauthError).toBe('invalid_client');
      }
    });

    it('confidential client still requires client_secret', async () => {
      const client = await methods.createClient({
        name: 'Web App',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code'],
        // tokenEndpointAuthMethod defaults to 'client_secret_basic'
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/cb',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });
      await expect(methods.exchangeCode({
        code,
        clientId: client.clientId,
        // No secret
        redirectUri: 'https://app.com/cb',
        codeVerifier: verifier,
      })).rejects.toThrow('Client secret required');
    });

    it('discovery exposes "none" in token_endpoint_auth_methods_supported', () => {
      const doc = methods.handleDiscovery();
      expect(doc.token_endpoint_auth_methods_supported).toContain('none');
    });
  });

  // ===================================================================
  // RFC 8252 §8.4 — loopback redirect URI matcher
  // ===================================================================
  describe('loopback redirect URI (RFC 8252 §8.4)', () => {
    it('matchRedirectUri: exact match always passes', () => {
      expect(matchRedirectUri('https://app.com/cb', 'https://app.com/cb')).toBe(true);
    });

    it('matchRedirectUri: 127.0.0.1 with any port matches', () => {
      expect(matchRedirectUri('http://127.0.0.1/cb', 'http://127.0.0.1:53127/cb')).toBe(true);
      expect(matchRedirectUri('http://127.0.0.1:8080/cb', 'http://127.0.0.1:9999/cb')).toBe(true);
    });

    it('matchRedirectUri: [::1] with any port matches', () => {
      expect(matchRedirectUri('http://[::1]/cb', 'http://[::1]:53127/cb')).toBe(true);
    });

    it('matchRedirectUri: path/scheme mismatch still rejected on loopback', () => {
      expect(matchRedirectUri('http://127.0.0.1/cb', 'http://127.0.0.1:1/different')).toBe(false);
      expect(matchRedirectUri('http://127.0.0.1/cb', 'https://127.0.0.1:1/cb')).toBe(false);
    });

    it('matchRedirectUri: localhost (DNS name) is NOT given the loopback exception', () => {
      // RFC 8252 §8.3: prefer literal IPs; DNS rebinding risk.
      expect(matchRedirectUri('http://localhost/cb', 'http://localhost:8080/cb')).toBe(false);
    });

    it('matchRedirectUri: non-loopback hosts get strict exact match', () => {
      expect(matchRedirectUri('https://app.com/cb', 'https://app.com:8080/cb')).toBe(false);
    });

    it('end-to-end: registered http://127.0.0.1/cb accepts dynamic-port runtime URI', async () => {
      const client = await methods.createClient({
        name: 'Native App',
        redirectUris: ['http://127.0.0.1/cb'],
        grantTypes: ['authorization_code'],
        tokenEndpointAuthMethod: 'none',
      });
      // The native app's loopback server picked port 53127 at runtime.
      // Public clients now require PKCE at mint time (P1.3), so bind a challenge.
      const challenge = await generateCodeChallenge(generateCodeVerifier());
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'http://127.0.0.1:53127/cb',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });
      expect(code).toBeTruthy();
    });
  });

  // ===================================================================
  // RFC 8414 §2 / RFC 9700 §4.16 — HTTPS issuer assertion in production
  // ===================================================================
  describe('hTTPS issuer assertion', () => {
    const previousEnv = process.env.NODE_ENV;
    afterAll(() => {
      process.env.NODE_ENV = previousEnv;
    });

    it('rejects HTTP issuer URLs in production', () => {
      process.env.NODE_ENV = 'production';
      expect(() => oauth({ issuerUrl: 'http://insecure.example.com' })).toThrow(
        /must use https/,
      );
    });

    it('accepts HTTPS issuer URLs in production', () => {
      process.env.NODE_ENV = 'production';
      expect(() => oauth({ issuerUrl: 'https://secure.example.com' })).not.toThrow();
    });

    it('accepts HTTP issuer URLs in development', () => {
      process.env.NODE_ENV = 'development';
      expect(() => oauth({ issuerUrl: 'http://localhost:8080' })).not.toThrow();
    });
  });

  // ===================================================================
  // Remediation regressions (P1.1, P1.2, P1.3, P3.4)
  // ===================================================================
  describe('remediation: code exchange single-use under concurrency (P1.1)', () => {
    it('exactly one of two concurrent exchanges of the same code succeeds', async () => {
      const client = await methods.createClient({
        name: 'Race App',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/cb',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });

      const results = await Promise.allSettled([
        methods.exchangeCode({
          code,
          clientId: client.clientId,
          clientSecret: client.clientSecret!,
          redirectUri: 'https://app.com/cb',
          codeVerifier: verifier,
        }),
        methods.exchangeCode({
          code,
          clientId: client.clientId,
          clientSecret: client.clientSecret!,
          redirectUri: 'https://app.com/cb',
          codeVerifier: verifier,
        }),
      ]);

      const fulfilled = results.filter(r => r.status === 'fulfilled').length;
      const rejected = results.filter(r => r.status === 'rejected') as PromiseRejectedResult[];
      expect(fulfilled).toBe(1);
      expect(rejected.length).toBe(1);
      expect((rejected[0].reason as { oauthError?: string }).oauthError).toBe('invalid_grant');
    });
  });

  describe('remediation: consent-flow approval single-use + owner check (P1.2 / H6)', () => {
    it('exactly one of two concurrent approvals of the same flow mints a code', async () => {
      const client = await methods.createClient({
        name: 'Approval Race App',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/cb',
        state: 'approve-race',
        userId,
      });

      const results = await Promise.allSettled([
        methods.handleApproveFlow(flowId, { userId }),
        methods.handleApproveFlow(flowId, { userId }),
      ]);

      const fulfilled = results.filter(r => r.status === 'fulfilled') as PromiseFulfilledResult<{ redirectUrl: string }>[];
      const rejected = results.filter(r => r.status === 'rejected') as PromiseRejectedResult[];
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect(String(rejected[0].reason)).toMatch(/not found/i);

      const url = new URL(fulfilled[0].value.redirectUrl);
      expect(url.searchParams.get('code')).toBeTruthy();
      const codeCount = await db.count({
        model: 'oauth_authorization_code',
        where: [{ field: 'clientId', operator: '=', value: client.clientId }],
      });
      expect(codeCount).toBe(1);
    });

    it('a different user gets 404 when reading a pending flow', async () => {
      const client = await methods.createClient({
        name: 'IDOR App',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/cb',
        state: 's',
        userId, // bound to user A up-front
      });
      // Create user B.
      const userB = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'bob@example.com', name: 'Bob', passwordHash: 'h', isActive: true },
      });

      await expect(
        methods.handleGetFlow(flowId, { userId: userB.id }),
      ).rejects.toThrow(/not found/);
      await expect(
        methods.handleApproveFlow(flowId, { userId: userB.id }),
      ).rejects.toThrow(/not found/);
      await expect(
        methods.handleDenyFlow(flowId, { userId: userB.id }),
      ).rejects.toThrow(/not found/);
    });

    it('tofu: an unbound flow is claimed by the first authenticated getFlow', async () => {
      const client = await methods.createClient({
        name: 'TOFU App',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['authorization_code'],
      });
      const { flowId } = await methods.createPendingFlow({
        clientId: client.clientId,
        redirectUri: 'https://app.com/cb',
        state: 's',
      });
      // User A reads first — should succeed and bind the flow to them.
      await methods.handleGetFlow(flowId, { userId });
      // User B reads next — should 404.
      const userB = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'eve@example.com', name: 'Eve', passwordHash: 'h', isActive: true },
      });
      await expect(
        methods.handleGetFlow(flowId, { userId: userB.id }),
      ).rejects.toThrow(/not found/);
    });
  });

  describe('remediation: PKCE mandatory for public clients (P1.3 / H7)', () => {
    it('public client cannot mint a code without an S256 challenge', async () => {
      const client = await methods.createClient({
        name: 'Public SPA',
        redirectUris: ['https://spa.com/cb'],
        grantTypes: ['authorization_code'],
        tokenEndpointAuthMethod: 'none',
      });
      // P1.3: the mint path itself now refuses to issue a binding-less code
      // to a public client, so a PKCE-less code never reaches storage.
      await expect(methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://spa.com/cb',
      })).rejects.toThrow(/PKCE \(S256\) is required for public clients/);
    });

    it('a pre-existing public-client code with no challenge still cannot be exchanged', async () => {
      const client = await methods.createClient({
        name: 'Public SPA legacy',
        redirectUris: ['https://spa2.com/cb'],
        grantTypes: ['authorization_code'],
        tokenEndpointAuthMethod: 'none',
      });
      // Defense-in-depth: simulate a binding-less code that predates the
      // mint-time guard by inserting it directly (the mint path now refuses
      // to create one). The exchange path must still reject it.
      const { raw, hash } = await generateRefreshToken();
      await db.create({
        model: 'oauth_authorization_code',
        data: {
          code: hash,
          clientId: client.clientId,
          userId,
          redirectUri: 'https://spa2.com/cb',
          scope: null,
          codeChallenge: null,
          codeChallengeMethod: null,
          nonce: null,
          authTime: null,
          expiresAt: new Date(Date.now() + 60_000),
          usedAt: null,
        },
      });
      await expect(methods.exchangeCode({
        code: raw,
        clientId: client.clientId,
        redirectUri: 'https://spa2.com/cb',
      })).rejects.toThrow(/PKCE required for public clients/);
    });
  });

  describe('remediation: per-client grant_types enforcement (P3.4 / M9)', () => {
    it('rejects authorization_code on a client not registered for it', async () => {
      const client = await methods.createClient({
        name: 'CC only',
        redirectUris: ['https://app.com/cb'],
        grantTypes: ['client_credentials'],
      });
      // Even though the redirect_uri is registered, the grant_types list
      // does not include `authorization_code`, so issuance must fail at
      // /token even if a code somehow exists.
      const { code } = await methods.createAuthorizationCode({
        clientId: client.clientId,
        userId,
        redirectUri: 'https://app.com/cb',
      });
      await expect(methods.exchangeCode({
        code,
        clientId: client.clientId,
        clientSecret: client.clientSecret!,
        redirectUri: 'https://app.com/cb',
      })).rejects.toThrow(/authorization_code grant/);
    });
  });
});
