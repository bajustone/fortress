import type { FortressPlugin } from '../../core/plugin';
import type { FortressUser } from '../../core/types';
import { generateRefreshToken, hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';
import { verifyCodeChallenge } from './pkce';

export interface OAuthConfig {
  /** Authorization code expiry in seconds (default: 600 = 10 min) */
  authCodeExpirySeconds?: number;
  /** Pending flow expiry in seconds (default: 600 = 10 min) */
  pendingFlowExpirySeconds?: number;
  /** Access token expiry in seconds (default: 3600 = 1 hour) */
  accessTokenExpirySeconds?: number;
}

interface OAuthClientRecord {
  id: number;
  clientId: string;
  clientSecretHash: string;
  name: string;
  redirectUris: string; // JSON
  grantTypes: string; // JSON
  createdAt: string;
}

interface AuthCodeRecord {
  id: number;
  code: string;
  clientId: string;
  userId: number;
  redirectUri: string;
  scope: string | null;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: string;
  usedAt: string | null;
}

interface AccessTokenRecord {
  id: number;
  token: string;
  clientId: string;
  userId: number | null;
  scope: string | null;
  expiresAt: string;
}

interface PendingFlowRecord {
  id: number;
  clientId: string;
  redirectUri: string;
  scope: string | null;
  state: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: string;
}

export function oauth(config: OAuthConfig = {}): FortressPlugin {
  const authCodeExpiry = config.authCodeExpirySeconds ?? 600;
  const pendingFlowExpiry = config.pendingFlowExpirySeconds ?? 600;
  const accessTokenExpiry = config.accessTokenExpirySeconds ?? 3600;

  return {
    name: 'oauth',

    models: [
      {
        name: 'oauth_client',
        fields: {
          id: { type: 'number', required: true },
          clientId: { type: 'string', required: true, unique: true },
          clientSecretHash: { type: 'string', required: true },
          name: { type: 'string', required: true },
          redirectUris: { type: 'string', required: true },
          grantTypes: { type: 'string', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        name: 'oauth_authorization_code',
        fields: {
          id: { type: 'number', required: true },
          code: { type: 'string', required: true, unique: true },
          clientId: { type: 'string', required: true },
          userId: { type: 'number', required: true },
          redirectUri: { type: 'string', required: true },
          scope: { type: 'string' },
          codeChallenge: { type: 'string' },
          codeChallengeMethod: { type: 'string' },
          expiresAt: { type: 'date', required: true },
          usedAt: { type: 'date' },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        name: 'oauth_access_token',
        fields: {
          id: { type: 'number', required: true },
          token: { type: 'string', required: true, unique: true },
          clientId: { type: 'string', required: true },
          userId: { type: 'number' },
          scope: { type: 'string' },
          expiresAt: { type: 'date', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        name: 'oauth_pending_flow',
        fields: {
          id: { type: 'number', required: true },
          clientId: { type: 'string', required: true },
          redirectUri: { type: 'string', required: true },
          scope: { type: 'string' },
          state: { type: 'string', required: true },
          codeChallenge: { type: 'string' },
          codeChallengeMethod: { type: 'string' },
          expiresAt: { type: 'date', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
    ],

    methods: ctx => ({
      /**
       * Register a new OAuth client.
       * Returns the clientId and raw clientSecret (shown once, stored as hash).
       */
      async createClient(data: {
        name: string;
        redirectUris: string[];
        grantTypes: string[];
      }): Promise<{ clientId: string; clientSecret: string }> {
        const { raw: clientSecret, hash: clientSecretHash } = await generateRefreshToken();
        const { raw: clientIdRaw } = await generateRefreshToken();
        const clientId = clientIdRaw.slice(0, 24); // Shorter, readable client ID

        await ctx.db.create({
          model: 'oauth_client',
          data: {
            clientId,
            clientSecretHash,
            name: data.name,
            redirectUris: JSON.stringify(data.redirectUris),
            grantTypes: JSON.stringify(data.grantTypes),
          },
        });

        return { clientId, clientSecret };
      },

      /**
       * Generate an authorization code for a user+client.
       * Used after the user authenticates and authorizes the client.
       */
      async createAuthorizationCode(params: {
        clientId: string;
        userId: number;
        redirectUri: string;
        scope?: string;
        codeChallenge?: string;
        codeChallengeMethod?: string;
      }): Promise<{ code: string }> {
        // Validate client
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: params.clientId }],
        });

        if (!client)
          throw Errors.badRequest('Invalid client_id');

        const uris = JSON.parse(client.redirectUris) as string[];
        if (!uris.includes(params.redirectUri))
          throw Errors.badRequest('Invalid redirect_uri');

        const { raw: code, hash: codeHash } = await generateRefreshToken();
        const expiresAt = new Date(Date.now() + authCodeExpiry * 1000);

        await ctx.db.create({
          model: 'oauth_authorization_code',
          data: {
            code: codeHash,
            clientId: params.clientId,
            userId: params.userId,
            redirectUri: params.redirectUri,
            scope: params.scope ?? null,
            codeChallenge: params.codeChallenge ?? null,
            codeChallengeMethod: params.codeChallengeMethod ?? null,
            expiresAt: expiresAt.toISOString(),
            usedAt: null,
          },
        });

        return { code };
      },

      /**
       * Exchange an authorization code for an access token.
       */
      async exchangeCode(params: {
        code: string;
        clientId: string;
        clientSecret: string;
        redirectUri: string;
        codeVerifier?: string;
      }): Promise<{ accessToken: string; tokenType: string; expiresIn: number; scope?: string }> {
        // Validate client credentials
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: params.clientId }],
        });

        if (!client)
          throw Errors.unauthorized('Invalid client credentials');

        const secretValid = await hashToken(params.clientSecret) === client.clientSecretHash;
        if (!secretValid)
          throw Errors.unauthorized('Invalid client credentials');

        // Look up the authorization code
        const codeHash = await hashToken(params.code);
        const authCode = await ctx.db.findOne<AuthCodeRecord>({
          model: 'oauth_authorization_code',
          where: [{ field: 'code', operator: '=', value: codeHash }],
        });

        if (!authCode)
          throw Errors.badRequest('Invalid authorization code');

        if (authCode.usedAt)
          throw Errors.badRequest('Authorization code already used');

        if (new Date(authCode.expiresAt) < new Date())
          throw Errors.badRequest('Authorization code expired');

        if (authCode.clientId !== params.clientId)
          throw Errors.badRequest('Client mismatch');

        if (authCode.redirectUri !== params.redirectUri)
          throw Errors.badRequest('Redirect URI mismatch');

        // Verify PKCE
        if (authCode.codeChallenge && authCode.codeChallengeMethod) {
          if (!params.codeVerifier)
            throw Errors.badRequest('code_verifier required');

          const valid = await verifyCodeChallenge(
            params.codeVerifier,
            authCode.codeChallenge,
            authCode.codeChallengeMethod,
          );

          if (!valid)
            throw Errors.badRequest('Invalid code_verifier');
        }

        // Mark code as used
        await ctx.db.update({
          model: 'oauth_authorization_code',
          where: [{ field: 'id', operator: '=', value: authCode.id }],
          data: { usedAt: new Date().toISOString() },
        });

        // Issue access token
        const { raw: tokenRaw, hash: tokenHash } = await generateRefreshToken();
        const expiresAt = new Date(Date.now() + accessTokenExpiry * 1000);

        await ctx.db.create({
          model: 'oauth_access_token',
          data: {
            token: tokenHash,
            clientId: params.clientId,
            userId: authCode.userId,
            scope: authCode.scope,
            expiresAt: expiresAt.toISOString(),
          },
        });

        return {
          accessToken: tokenRaw,
          tokenType: 'Bearer',
          expiresIn: accessTokenExpiry,
          scope: authCode.scope ?? undefined,
        };
      },

      /**
       * Client credentials grant — issue token for a service client (no user).
       */
      async clientCredentialsGrant(params: {
        clientId: string;
        clientSecret: string;
        scope?: string;
      }): Promise<{ accessToken: string; tokenType: string; expiresIn: number }> {
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: params.clientId }],
        });

        if (!client)
          throw Errors.unauthorized('Invalid client credentials');

        const grantTypes = JSON.parse(client.grantTypes) as string[];
        if (!grantTypes.includes('client_credentials'))
          throw Errors.badRequest('Client does not support client_credentials grant');

        const secretValid = await hashToken(params.clientSecret) === client.clientSecretHash;
        if (!secretValid)
          throw Errors.unauthorized('Invalid client credentials');

        const { raw: tokenRaw, hash: tokenHash } = await generateRefreshToken();
        const expiresAt = new Date(Date.now() + accessTokenExpiry * 1000);

        await ctx.db.create({
          model: 'oauth_access_token',
          data: {
            token: tokenHash,
            clientId: params.clientId,
            userId: null,
            scope: params.scope ?? null,
            expiresAt: expiresAt.toISOString(),
          },
        });

        return {
          accessToken: tokenRaw,
          tokenType: 'Bearer',
          expiresIn: accessTokenExpiry,
        };
      },

      /**
       * Revoke an access token (RFC 7009).
       */
      async revokeToken(token: string): Promise<void> {
        const tokenHash = await hashToken(token);
        await ctx.db.delete({
          model: 'oauth_access_token',
          where: [{ field: 'token', operator: '=', value: tokenHash }],
        });
      },

      /**
       * Validate an access token and return associated user/client info.
       */
      async introspectToken(token: string): Promise<{
        active: boolean;
        clientId?: string;
        userId?: number;
        scope?: string;
      }> {
        const tokenHash = await hashToken(token);
        const record = await ctx.db.findOne<AccessTokenRecord>({
          model: 'oauth_access_token',
          where: [{ field: 'token', operator: '=', value: tokenHash }],
        });

        if (!record || new Date(record.expiresAt) < new Date()) {
          return { active: false };
        }

        return {
          active: true,
          clientId: record.clientId,
          userId: record.userId ?? undefined,
          scope: record.scope ?? undefined,
        };
      },

      /**
       * Create a pending OAuth flow for unauthenticated users (identity broker pattern).
       */
      async createPendingFlow(params: {
        clientId: string;
        redirectUri: string;
        scope?: string;
        state: string;
        codeChallenge?: string;
        codeChallengeMethod?: string;
      }): Promise<{ flowId: number }> {
        const expiresAt = new Date(Date.now() + pendingFlowExpiry * 1000);

        const flow = await ctx.db.create<PendingFlowRecord>({
          model: 'oauth_pending_flow',
          data: {
            clientId: params.clientId,
            redirectUri: params.redirectUri,
            scope: params.scope ?? null,
            state: params.state,
            codeChallenge: params.codeChallenge ?? null,
            codeChallengeMethod: params.codeChallengeMethod ?? null,
            expiresAt: expiresAt.toISOString(),
          },
        });

        return { flowId: flow.id };
      },

      /**
       * Resume a pending OAuth flow after user authenticates.
       * Returns the stored flow params so the caller can generate an auth code.
       */
      async resumePendingFlow(flowId: number): Promise<PendingFlowRecord> {
        const flow = await ctx.db.findOne<PendingFlowRecord>({
          model: 'oauth_pending_flow',
          where: [{ field: 'id', operator: '=', value: flowId }],
        });

        if (!flow)
          throw Errors.notFound('Pending flow not found');

        if (new Date(flow.expiresAt) < new Date())
          throw Errors.badRequest('Pending flow expired');

        // Delete the flow (single-use)
        await ctx.db.delete({
          model: 'oauth_pending_flow',
          where: [{ field: 'id', operator: '=', value: flowId }],
        });

        return flow;
      },

      /**
       * Get userinfo for an access token (OpenID Connect userinfo endpoint).
       */
      async getUserInfo(token: string): Promise<FortressUser | null> {
        const tokenHash = await hashToken(token);
        const record = await ctx.db.findOne<AccessTokenRecord>({
          model: 'oauth_access_token',
          where: [{ field: 'token', operator: '=', value: tokenHash }],
        });

        if (!record || !record.userId || new Date(record.expiresAt) < new Date())
          return null;

        return ctx.db.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: record.userId }],
        });
      },
    }),
  };
}

export { generateCodeChallenge, generateCodeVerifier, verifyCodeChallenge } from './pkce';
