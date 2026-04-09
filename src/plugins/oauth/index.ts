/**
 * OAuth 2.0 authorization server plugin for fortress.
 *
 * Implements the authorization-code grant (with PKCE) and client-credentials
 * grant for confidential and public clients. Persists clients, authorization
 * codes, access tokens, and pending flows via the fortress database adapter,
 * and exposes the standard `/authorize` and `/token` endpoints when mounted.
 *
 * @module
 */

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
  /** Map OAuth scopes to IAM permissions. Example: `{ 'read:posts': { resource: 'post', action: 'read' } }` */
  scopePermissionMap?: Record<string, { resource: string; action: string }>;
  /** Base URL for the OAuth server (used in OIDC discovery document) */
  issuerUrl?: string;
}

interface OAuthClientRecord {
  id: number;
  clientId: string;
  clientSecretHash: string;
  name: string;
  redirectUris: string; // JSON
  grantTypes: string; // JSON
  createdAt: Date;
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
  expiresAt: Date;
  usedAt: Date | null;
}

interface AccessTokenRecord {
  id: number;
  token: string;
  clientId: string;
  userId: number | null;
  scope: string | null;
  expiresAt: Date;
}

export interface PendingFlowRecord {
  id: number;
  clientId: string;
  redirectUri: string;
  scope: string | null;
  state: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: Date;
}

/** Client authentication extracted from HTTP request (Basic auth or body params) */
export interface ClientAuth {
  clientId: string;
  clientSecret: string;
}

/** Token endpoint request body (application/x-www-form-urlencoded) */
export interface TokenRequestBody {
  grant_type: string;
  code?: string;
  redirect_uri?: string;
  client_id?: string;
  client_secret?: string;
  code_verifier?: string;
  scope?: string;
}

/** Authorization endpoint query params */
export interface AuthorizeRequestParams {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

export interface OAuthMethods {
  // Programmatic API
  createClient: (data: { name: string; redirectUris: string[]; grantTypes: string[] }) => Promise<{ clientId: string; clientSecret: string }>;
  createAuthorizationCode: (params: { clientId: string; userId: number; redirectUri: string; scope?: string; codeChallenge?: string; codeChallengeMethod?: string }) => Promise<{ code: string }>;
  exchangeCode: (params: { code: string; clientId: string; clientSecret: string; redirectUri: string; codeVerifier?: string }) => Promise<{ accessToken: string; tokenType: string; expiresIn: number; scope?: string }>;
  clientCredentialsGrant: (params: { clientId: string; clientSecret: string; scope?: string }) => Promise<{ accessToken: string; tokenType: string; expiresIn: number }>;
  revokeToken: (token: string) => Promise<void>;
  introspectToken: (token: string) => Promise<{ active: boolean; clientId?: string; userId?: number; scope?: string }>;
  createPendingFlow: (params: { clientId: string; redirectUri: string; scope?: string; state: string; codeChallenge?: string; codeChallengeMethod?: string }) => Promise<{ flowId: number }>;
  resumePendingFlow: (flowId: number) => Promise<PendingFlowRecord>;
  getUserInfo: (token: string) => Promise<FortressUser | null>;
  // HTTP handler methods (transport-agnostic, accept/return plain objects)
  handleTokenRequest: (body: TokenRequestBody, clientAuth?: ClientAuth) => Promise<Record<string, unknown>>;
  handleIntrospectRequest: (body: { token: string }, clientAuth: ClientAuth) => Promise<Record<string, unknown>>;
  handleRevokeRequest: (body: { token: string }) => Promise<void>;
  handleUserInfoRequest: (bearerToken: string) => Promise<FortressUser | null>;
  handleDiscovery: () => Record<string, unknown>;
  resolveTokenPermissions: (token: string) => Promise<{ resource: string; action: string }[]>;
}
export function oauth(config: OAuthConfig = {}): FortressPlugin & { readonly name: 'oauth' } {
  const authCodeExpiry = config.authCodeExpirySeconds ?? 600;
  const pendingFlowExpiry = config.pendingFlowExpirySeconds ?? 600;
  const accessTokenExpiry = config.accessTokenExpirySeconds ?? 3600;
  const scopePermissionMap = config.scopePermissionMap;

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
            expiresAt,
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

        if (authCode.expiresAt < new Date())
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
          data: { usedAt: new Date() },
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
            expiresAt,
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
            expiresAt,
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

        if (!record || record.expiresAt < new Date()) {
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
            expiresAt,
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

        if (flow.expiresAt < new Date())
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

        if (!record || !record.userId || record.expiresAt < new Date())
          return null;

        return ctx.db.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: record.userId }],
        });
      },

      // --- HTTP handler methods (RFC 6749 / 7662 / 7009) ---

      /**
       * Handle POST /oauth/token — dispatches to exchangeCode or clientCredentialsGrant.
       */
      async handleTokenRequest(
        body: TokenRequestBody,
        clientAuth?: ClientAuth,
      ): Promise<Record<string, unknown>> {
        const clientId = clientAuth?.clientId ?? body.client_id;
        const clientSecret = clientAuth?.clientSecret ?? body.client_secret;

        if (!clientId || !clientSecret)
          throw Errors.unauthorized('Client authentication required');

        if (body.grant_type === 'authorization_code') {
          if (!body.code || !body.redirect_uri)
            throw Errors.badRequest('Missing required parameters: code, redirect_uri');

          const result = await this.exchangeCode({
            code: body.code,
            clientId,
            clientSecret,
            redirectUri: body.redirect_uri,
            codeVerifier: body.code_verifier,
          });

          return {
            access_token: result.accessToken,
            token_type: result.tokenType,
            expires_in: result.expiresIn,
            ...(result.scope ? { scope: result.scope } : {}),
          };
        }

        if (body.grant_type === 'client_credentials') {
          const result = await this.clientCredentialsGrant({
            clientId,
            clientSecret,
            scope: body.scope,
          });

          return {
            access_token: result.accessToken,
            token_type: result.tokenType,
            expires_in: result.expiresIn,
          };
        }

        throw Errors.badRequest(`Unsupported grant_type: ${body.grant_type}`);
      },

      /**
       * Handle POST /oauth/introspect (RFC 7662).
       */
      async handleIntrospectRequest(
        body: { token: string },
        clientAuth: ClientAuth,
      ): Promise<Record<string, unknown>> {
        // Validate client credentials
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: clientAuth.clientId }],
        });

        if (!client)
          throw Errors.unauthorized('Invalid client credentials');

        const secretValid = await hashToken(clientAuth.clientSecret) === client.clientSecretHash;
        if (!secretValid)
          throw Errors.unauthorized('Invalid client credentials');

        const result = await this.introspectToken(body.token);

        if (!result.active)
          return { active: false };

        return {
          active: true,
          client_id: result.clientId,
          ...(result.userId != null ? { sub: String(result.userId) } : {}),
          ...(result.scope ? { scope: result.scope } : {}),
          token_type: 'Bearer',
        };
      },

      /**
       * Handle POST /oauth/revoke (RFC 7009). Always returns success.
       */
      async handleRevokeRequest(body: { token: string }): Promise<void> {
        await this.revokeToken(body.token);
      },

      /**
       * Handle GET /oauth/userinfo (OpenID Connect).
       */
      async handleUserInfoRequest(bearerToken: string): Promise<FortressUser | null> {
        return this.getUserInfo(bearerToken);
      },

      /**
       * Handle GET /.well-known/openid-configuration (RFC 8414).
       */
      handleDiscovery(): Record<string, unknown> {
        const issuer = config.issuerUrl ?? 'https://localhost';
        return {
          issuer,
          authorization_endpoint: `${issuer}/oauth/authorize`,
          token_endpoint: `${issuer}/oauth/token`,
          introspection_endpoint: `${issuer}/oauth/introspect`,
          revocation_endpoint: `${issuer}/oauth/revoke`,
          userinfo_endpoint: `${issuer}/oauth/userinfo`,
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code', 'client_credentials'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
          code_challenge_methods_supported: ['S256'],
          subject_types_supported: ['public'],
        };
      },

      /**
       * Resolve an access token's scopes to IAM permissions using the configured scopePermissionMap.
       */
      async resolveTokenPermissions(token: string): Promise<{ resource: string; action: string }[]> {
        const info = await this.introspectToken(token);
        if (!info.active || !info.scope || !scopePermissionMap)
          return [];

        const scopes = info.scope.split(' ');
        const permissions: { resource: string; action: string }[] = [];

        for (const scope of scopes) {
          const mapping = scopePermissionMap[scope];
          if (mapping) {
            permissions.push(mapping);
          }
        }

        return permissions;
      },
    }),

    routes: [
      {
        method: 'POST',
        path: '/oauth/token',
        handler: 'handleTokenRequest',
        meta: { summary: 'Exchange credentials for tokens', tags: ['OAuth'], security: ['basic'] },
        input: {
          body: {
            type: 'object',
            properties: {
              grant_type: { type: 'string', enum: ['authorization_code', 'client_credentials'], description: 'OAuth grant type' },
              code: { type: 'string', description: 'Authorization code' },
              redirect_uri: { type: 'string', format: 'uri', description: 'Redirect URI used in authorize' },
              client_id: { type: 'string', description: 'Client ID (if not using Basic auth)' },
              client_secret: { type: 'string', description: 'Client secret (if not using Basic auth)' },
              code_verifier: { type: 'string', description: 'PKCE code verifier' },
              scope: { type: 'string', description: 'Space-separated scopes' },
            },
            required: ['grant_type'],
          },
        },
        responses: {
          200: { description: 'Token issued', schema: { type: 'object', properties: { access_token: { type: 'string' }, token_type: { type: 'string' }, expires_in: { type: 'number' }, scope: { type: 'string' } } } },
          400: { description: 'Invalid request' },
          401: { description: 'Invalid client credentials' },
        },
      },
      {
        method: 'POST',
        path: '/oauth/introspect',
        handler: 'handleIntrospectRequest',
        meta: { summary: 'Introspect a token (RFC 7662)', tags: ['OAuth'], security: ['basic'] },
        input: { body: { type: 'object', properties: { token: { type: 'string' } }, required: ['token'] } },
        responses: {
          200: { description: 'Token info', schema: { type: 'object', properties: { active: { type: 'boolean' }, sub: { type: 'string' }, scope: { type: 'string' }, exp: { type: 'number' } } } },
          401: { description: 'Client authentication required' },
        },
      },
      {
        method: 'POST',
        path: '/oauth/revoke',
        handler: 'handleRevokeRequest',
        meta: { summary: 'Revoke a token (RFC 7009)', tags: ['OAuth'], security: ['none'] },
        input: { body: { type: 'object', properties: { token: { type: 'string' } }, required: ['token'] } },
        responses: { 200: { description: 'Token revoked' } },
      },
      {
        method: 'GET',
        path: '/oauth/userinfo',
        handler: 'handleUserInfoRequest',
        meta: { summary: 'Get user info (OIDC)', tags: ['OAuth'], security: ['bearer'] },
        responses: {
          200: { description: 'User info', schema: { type: 'object', properties: { sub: { type: 'string' }, email: { type: 'string' }, name: { type: 'string' } } } },
          401: { description: 'Invalid bearer token' },
        },
      },
      {
        method: 'GET',
        path: '/oauth/.well-known/openid-configuration',
        handler: 'handleDiscovery',
        meta: { summary: 'OIDC discovery document', tags: ['OAuth'], security: ['none'] },
        responses: { 200: { description: 'OIDC configuration', schema: { type: 'object', additionalProperties: true } } },
      },
    ],
  };
}

export { generateCodeChallenge, generateCodeVerifier, verifyCodeChallenge } from './pkce';
