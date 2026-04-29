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
  /**
   * Mount the front-door `GET /oauth/authorize` endpoint. Off by default —
   * opt in once your host app has wired up `loginUrl` and `consentUrl`.
   * Plugin methods (`createPendingFlow`, `handleAuthorizeRequest`) stay
   * available regardless.
   */
  enableAuthorizeEndpoint?: boolean;
  /**
   * Mount the consent-API endpoints (`GET /oauth/flows/:flowId`,
   * `POST /oauth/flows/:flowId/approve`, `POST /oauth/flows/:flowId/deny`).
   * Off by default — opt in for the SPA-friendly consent flow (Pattern B).
   * The corresponding methods stay available regardless.
   */
  enableConsentApi?: boolean;
  /**
   * Where the host app's sign-in page lives, e.g.
   * `'https://app.example.com/signin'`. The authorize endpoint redirects
   * unauthenticated users to `${loginUrl}?flow=<id>`.
   */
  loginUrl?: string;
  /**
   * Where the host app's consent page lives, e.g.
   * `'https://app.example.com/oauth/consent'`. The authorize endpoint
   * redirects authenticated users to `${consentUrl}?flow=<id>`.
   */
  consentUrl?: string;
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

/** Persisted state for an in-flight OAuth authorization-code flow. */
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
/** Resolved client credentials parsed from a token-endpoint request. */
export interface ClientAuth {
  clientId: string;
  clientSecret: string;
}

/** Token endpoint request body (application/x-www-form-urlencoded) */
/** Body shape accepted by the OAuth `/token` endpoint. */
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
/** Query parameters accepted by the OAuth `/authorize` endpoint. */
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
  /** Read a pending flow without consuming it. Throws if not found or expired. */
  getPendingFlow: (flowId: number) => Promise<PendingFlowRecord>;
  /** Read and delete a pending flow (single-use). Throws if not found or expired. */
  resumePendingFlow: (flowId: number) => Promise<PendingFlowRecord>;
  getUserInfo: (token: string) => Promise<FortressUser | null>;
  // HTTP handler methods (transport-agnostic, accept/return plain objects)
  handleTokenRequest: (body: TokenRequestBody, clientAuth?: ClientAuth) => Promise<Record<string, unknown>>;
  handleIntrospectRequest: (body: { token: string }, clientAuth: ClientAuth) => Promise<Record<string, unknown>>;
  handleRevokeRequest: (body: { token: string }) => Promise<void>;
  handleUserInfoRequest: (bearerToken: string) => Promise<FortressUser | null>;
  handleDiscovery: () => Record<string, unknown>;
  /**
   * Handle GET /oauth/authorize. Validates the query, creates a pending
   * flow, and returns the URL to redirect the browser to (login if no
   * user, consent if authenticated).
   */
  handleAuthorizeRequest: (
    query: Record<string, string | undefined>,
    context: { userId?: number },
  ) => Promise<{ redirectUrl: string; flowId: number }>;
  /**
   * Handle GET /oauth/flows/:flowId. Returns the consent metadata the host
   * app's consent page renders. Throws if the flow is unknown or expired.
   */
  handleGetFlow: (flowId: number) => Promise<{
    flowId: number;
    client: { clientId: string; name: string };
    redirectUri: string;
    scopes: string[];
    state: string;
  }>;
  /**
   * Handle POST /oauth/flows/:flowId/approve. Issues an authorization code
   * for the authenticated user, deletes the pending flow, and returns the
   * URL the browser should be sent back to (the OAuth client's redirect_uri
   * with `?code=...&state=...`).
   */
  handleApproveFlow: (
    flowId: number,
    context: { userId: number },
  ) => Promise<{ redirectUrl: string }>;
  /**
   * Handle POST /oauth/flows/:flowId/deny. Deletes the pending flow and
   * returns the URL the browser should be sent back to (redirect_uri with
   * `?error=access_denied&state=...`).
   */
  handleDenyFlow: (flowId: number) => Promise<{ redirectUrl: string }>;
  resolveTokenPermissions: (token: string) => Promise<{ resource: string; action: string }[]>;
}
/**
 * OAuth 2.0 server plugin factory. Returns a {@link FortressPlugin} that
 * implements the authorization-code grant (with PKCE) and client-credentials
 * grant, persists clients and tokens, and exposes `/authorize` and `/token`
 * endpoints when mounted on a framework adapter.
 */
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
       * Read a pending OAuth flow without consuming it.
       *
       * Used by the consent UI to fetch flow metadata (client, scopes, redirect URI)
       * before the user approves or denies. Safe to call multiple times.
       *
       * @throws {FortressError} `not_found` if the flow doesn't exist.
       * @throws {FortressError} `bad_request` if the flow has expired.
       */
      async getPendingFlow(flowId: number): Promise<PendingFlowRecord> {
        const flow = await ctx.db.findOne<PendingFlowRecord>({
          model: 'oauth_pending_flow',
          where: [{ field: 'id', operator: '=', value: flowId }],
        });

        if (!flow)
          throw Errors.notFound('Pending flow not found');

        if (flow.expiresAt < new Date())
          throw Errors.badRequest('Pending flow expired');

        return flow;
      },

      /**
       * Resume a pending OAuth flow after user authenticates (single-use consume).
       *
       * Returns the stored flow params and deletes the row so the same flow can't
       * be replayed. Use {@link OAuthMethods.getPendingFlow} for non-destructive reads.
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
      /**
       * Handle the authorize endpoint. Validates the OAuth query, creates a
       * pending flow row, and decides whether the browser should be sent to
       * the host app's login page or consent page next.
       *
       * The dispatcher turns `redirectUrl` into a 302 response. Errors are
       * thrown as {@link FortressError}s so they surface as a 4xx JSON body
       * (the OAuth client is expected to handle that).
       */
      async handleAuthorizeRequest(
        query: Record<string, string | undefined>,
        context: { userId?: number },
      ): Promise<{ redirectUrl: string; flowId: number }> {
        if (!config.loginUrl || !config.consentUrl) {
          throw Errors.badRequest(
            'OAuth plugin is missing loginUrl/consentUrl configuration',
          );
        }

        const clientId = query.client_id;
        const redirectUri = query.redirect_uri;
        const responseType = query.response_type;
        const state = query.state;
        const scope = query.scope;
        const codeChallenge = query.code_challenge;
        const codeChallengeMethod = query.code_challenge_method;

        if (!clientId)
          throw Errors.badRequest('client_id is required');
        if (!redirectUri)
          throw Errors.badRequest('redirect_uri is required');
        if (responseType !== 'code')
          throw Errors.badRequest('response_type must be "code"');
        if (!state)
          throw Errors.badRequest('state is required');

        // Validate the client and redirect URI up front so a bogus client
        // never reaches the user-facing pages.
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: clientId }],
        });
        if (!client)
          throw Errors.badRequest('Unknown client_id');

        const allowedRedirects = JSON.parse(client.redirectUris) as string[];
        if (!allowedRedirects.includes(redirectUri))
          throw Errors.badRequest('Invalid redirect_uri');

        // PKCE method validation — we only support S256 (matches the
        // discovery document).
        if (codeChallenge && codeChallengeMethod && codeChallengeMethod !== 'S256') {
          throw Errors.badRequest('Only S256 code_challenge_method is supported');
        }

        const expiresAt = new Date(Date.now() + pendingFlowExpiry * 1000);
        const flow = await ctx.db.create<PendingFlowRecord>({
          model: 'oauth_pending_flow',
          data: {
            clientId,
            redirectUri,
            scope: scope ?? null,
            state,
            codeChallenge: codeChallenge ?? null,
            codeChallengeMethod: codeChallengeMethod ?? null,
            expiresAt,
          },
        });

        const target = context.userId ? config.consentUrl : config.loginUrl;
        const url = new URL(target);
        url.searchParams.set('flow', String(flow.id));
        return { redirectUrl: url.toString(), flowId: flow.id };
      },

      /**
       * Read a pending flow as the consent UI's data source. Strips fields
       * that should never leave the server (PKCE challenge / method).
       */
      async handleGetFlow(flowId: number): Promise<{
        flowId: number;
        client: { clientId: string; name: string };
        redirectUri: string;
        scopes: string[];
        state: string;
      }> {
        const flow = await this.getPendingFlow(flowId);
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: flow.clientId }],
        });
        if (!client)
          throw Errors.notFound('OAuth client not found');

        return {
          flowId: flow.id,
          client: { clientId: client.clientId, name: client.name },
          redirectUri: flow.redirectUri,
          scopes: flow.scope ? flow.scope.split(' ').filter(Boolean) : [],
          state: flow.state,
        };
      },

      /**
       * Approve a pending flow on behalf of the authenticated user. Creates
       * the authorization code, consumes the pending flow, and returns the
       * client's redirect URI with `?code=...&state=...` appended.
       */
      async handleApproveFlow(
        flowId: number,
        context: { userId: number },
      ): Promise<{ redirectUrl: string }> {
        // Read first so we can fail before issuing a code if anything's wrong.
        const flow = await this.getPendingFlow(flowId);
        const { code } = await this.createAuthorizationCode({
          clientId: flow.clientId,
          userId: context.userId,
          redirectUri: flow.redirectUri,
          scope: flow.scope ?? undefined,
          codeChallenge: flow.codeChallenge ?? undefined,
          codeChallengeMethod: flow.codeChallengeMethod ?? undefined,
        });
        // Consume the pending flow only after the code is in place.
        await ctx.db.delete({
          model: 'oauth_pending_flow',
          where: [{ field: 'id', operator: '=', value: flow.id }],
        });

        const url = new URL(flow.redirectUri);
        url.searchParams.set('code', code);
        url.searchParams.set('state', flow.state);
        return { redirectUrl: url.toString() };
      },

      /**
       * Deny a pending flow. Consumes the flow row and returns the OAuth
       * client's redirect URI with `?error=access_denied&state=...`.
       */
      async handleDenyFlow(flowId: number): Promise<{ redirectUrl: string }> {
        const flow = await this.resumePendingFlow(flowId);
        const url = new URL(flow.redirectUri);
        url.searchParams.set('error', 'access_denied');
        url.searchParams.set('state', flow.state);
        return { redirectUrl: url.toString() };
      },

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

    routes: {
      // Front door for the auth-code flow. Opt-in: only mounted when the
      // host app has wired up `loginUrl` and `consentUrl`.
      ...(config.enableAuthorizeEndpoint
        ? {
            handleAuthorizeRequest: {
              method: 'GET' as const,
              path: '/oauth/authorize',
              handler: 'handleAuthorizeRequest',
              meta: {
                summary: 'Start an OAuth authorization-code flow',
                tags: ['OAuth'],
                security: ['none'] as ('none' | 'basic' | 'bearer')[],
              },
              input: {
                query: {
                  type: 'object' as const,
                  properties: {
                    client_id: { type: 'string' as const, description: 'Registered OAuth client ID' },
                    redirect_uri: { type: 'string' as const, format: 'uri', description: 'Must match a redirect URI registered with the client' },
                    response_type: { type: 'string' as const, enum: ['code'], description: 'Only "code" is supported' },
                    scope: { type: 'string' as const, description: 'Space-separated requested scopes' },
                    state: { type: 'string' as const, description: 'Opaque value returned to the client; required to prevent CSRF' },
                    code_challenge: { type: 'string' as const, description: 'PKCE code challenge (recommended for public clients)' },
                    code_challenge_method: { type: 'string' as const, enum: ['S256'], description: 'PKCE method — only S256 is supported' },
                  },
                  required: ['client_id', 'redirect_uri', 'response_type', 'state'],
                },
              },
              responses: {
                302: { description: 'Redirect to login (unauthenticated) or consent (authenticated) page with ?flow=<id>' },
                400: { description: 'Invalid request' },
              },
            },
          }
        : {}),
      // Consent API — SPA-friendly flow inspection + approve/deny.
      ...(config.enableConsentApi
        ? {
            handleGetFlow: {
              method: 'GET' as const,
              path: '/oauth/flows/:flowId',
              handler: 'handleGetFlow',
              meta: {
                summary: 'Fetch pending OAuth flow metadata',
                tags: ['OAuth'],
                security: ['bearer'] as ('none' | 'basic' | 'bearer')[],
              },
              responses: {
                200: {
                  description: 'Flow metadata',
                  schema: {
                    type: 'object' as const,
                    properties: {
                      flowId: { type: 'number' as const },
                      client: {
                        type: 'object' as const,
                        properties: {
                          clientId: { type: 'string' as const },
                          name: { type: 'string' as const },
                        },
                      },
                      redirectUri: { type: 'string' as const },
                      scopes: { type: 'array' as const, items: { type: 'string' as const } },
                      state: { type: 'string' as const },
                    },
                  },
                },
                401: { description: 'Authentication required' },
                404: { description: 'Flow not found' },
              },
            },
            handleApproveFlow: {
              method: 'POST' as const,
              path: '/oauth/flows/:flowId/approve',
              handler: 'handleApproveFlow',
              meta: {
                summary: 'Approve a pending OAuth flow',
                tags: ['OAuth'],
                security: ['bearer'] as ('none' | 'basic' | 'bearer')[],
              },
              responses: {
                200: {
                  description: 'Authorization code issued',
                  schema: {
                    type: 'object' as const,
                    properties: { redirectUrl: { type: 'string' as const } },
                  },
                },
                401: { description: 'Authentication required' },
                404: { description: 'Flow not found' },
              },
            },
            handleDenyFlow: {
              method: 'POST' as const,
              path: '/oauth/flows/:flowId/deny',
              handler: 'handleDenyFlow',
              meta: {
                summary: 'Deny a pending OAuth flow',
                tags: ['OAuth'],
                security: ['bearer'] as ('none' | 'basic' | 'bearer')[],
              },
              responses: {
                200: {
                  description: 'Flow denied',
                  schema: {
                    type: 'object' as const,
                    properties: { redirectUrl: { type: 'string' as const } },
                  },
                },
                401: { description: 'Authentication required' },
                404: { description: 'Flow not found' },
              },
            },
          }
        : {}),
      handleTokenRequest: {
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
      handleIntrospectRequest: {
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
      handleRevokeRequest: {
        method: 'POST',
        path: '/oauth/revoke',
        handler: 'handleRevokeRequest',
        meta: { summary: 'Revoke a token (RFC 7009)', tags: ['OAuth'], security: ['none'] },
        input: { body: { type: 'object', properties: { token: { type: 'string' } }, required: ['token'] } },
        responses: { 200: { description: 'Token revoked' } },
      },
      handleUserInfoRequest: {
        method: 'GET',
        path: '/oauth/userinfo',
        handler: 'handleUserInfoRequest',
        meta: { summary: 'Get user info (OIDC)', tags: ['OAuth'], security: ['bearer'] },
        responses: {
          200: { description: 'User info', schema: { type: 'object', properties: { sub: { type: 'string' }, email: { type: 'string' }, name: { type: 'string' } } } },
          401: { description: 'Invalid bearer token' },
        },
      },
      handleDiscovery: {
        method: 'GET',
        path: '/oauth/.well-known/openid-configuration',
        handler: 'handleDiscovery',
        meta: { summary: 'OIDC discovery document', tags: ['OAuth'], security: ['none'] },
        responses: { 200: { description: 'OIDC configuration', schema: { type: 'object', additionalProperties: true } } },
      },
    },
  };
}

export { generateCodeChallenge, generateCodeVerifier, verifyCodeChallenge } from './pkce';
