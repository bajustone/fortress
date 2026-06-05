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
import { generateRefreshToken, generateTokenFamily, hashToken } from '../../core/auth/refresh-token';
import { timingSafeEqualHex } from '../../core/auth/timing-safe';
import { Errors } from '../../core/errors';
import { issueIdToken } from './id-token';
import { getActiveSigningKey, listJwks } from './jwks';
import { verifyCodeChallenge } from './pkce';

export interface OAuthConfig {
  /** Authorization code expiry in seconds (default: 600 = 10 min) */
  authCodeExpirySeconds?: number;
  /** Pending flow expiry in seconds (default: 600 = 10 min) */
  pendingFlowExpirySeconds?: number;
  /** Access token expiry in seconds (default: 3600 = 1 hour) */
  accessTokenExpirySeconds?: number;
  /**
   * Refresh token expiry in seconds (default: 30 days). Refresh tokens are
   * sliding — each rotation issues a fresh token with a new expiry. Set to
   * 0 to disable refresh-token issuance entirely.
   *
   * @see RFC 6749 §6 · RFC 9700 §2.2.2
   */
  refreshTokenExpirySeconds?: number;
  /**
   * id_token expiry in seconds (default: 3600 = 1 hour). Only relevant
   * when the request includes `scope=openid`.
   *
   * @see OIDC Core 1.0 §2
   */
  idTokenExpirySeconds?: number;
  /** Map OAuth scopes to IAM permissions. Example: `{ 'read:posts': { resource: 'post', action: 'read' } }` */
  scopePermissionMap?: Record<string, { resource: string; action: string }>;
  /** Base URL for the OAuth server (used in OIDC discovery document) */
  issuerUrl?: string;
  /**
   * RFC 9700 §2.1.1 escape hatch: when `true`, `/oauth/authorize` will accept
   * requests without a `code_challenge` from confidential clients. Defaults
   * to `false`. Strongly discouraged — PKCE is mandatory in current OAuth
   * BCP. Provided only so legacy server-side RPs can be migrated
   * incrementally.
   */
  allowNonPkceConfidentialClients?: boolean;
  /**
   * Static list of OIDC/OAuth scope names the AS knows about, surfaced in
   * discovery's `scopes_supported`. Merged with the keys of
   * {@link OAuthConfig.scopePermissionMap} and the default OIDC scopes
   * (`openid`, `email`, `profile`). Optional — informational metadata only;
   * does not enforce per-client allow-listing on its own.
   */
  scopesSupported?: string[];
  /**
   * Per-deployment extension hook for `/oauth/userinfo`. Receives the
   * {@link FortressUser} resolved from the access token plus the token's
   * scope (or `null` if no scope was issued), and returns a claims record
   * that is merged into the OIDC-shaped response on top of the standard
   * claims fortress emits.
   *
   * Use this to attach app-specific claims (tenant, roles, custom
   * profile fields). Returning `{}` is the no-op; returning a key already
   * emitted by fortress overwrites it (you'd typically only do that for
   * `preferred_username` or `name` when the host app stores its own).
   *
   * @example
   * ```ts
   * userinfoClaims: (user, scope) => ({
   *   tenant_id: user.tenantId,
   *   ...(scope?.includes('profile') ? { picture: user.avatarUrl } : {}),
   * })
   * ```
   */
  userinfoClaims?: (
    user: FortressUser,
    scope: string | null,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;
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
  /**
   * RFC 6749 §3.3 + RFC 9700 §2.2.1: per-client scope allow-list (JSON
   * array). When set, requested scopes are intersected against this list at
   * authorize / token time — unauthorised scopes are dropped silently per
   * §3.3, and an empty intersection returns `error=invalid_scope`. When
   * `null`, fortress passes through whatever scope the client requested
   * (legacy v0 behaviour, deprecated — set `allowedScopes: []` to deny all
   * or pass an explicit list).
   */
  allowedScopes: string | null;
  /**
   * RFC 6749 §2.1 client type. Persisted as the OIDC discovery alias:
   * `'client_secret_basic'` (default), `'client_secret_post'`, or `'none'`
   * for public clients (SPAs, native apps — RFC 8252). Public clients use
   * PKCE in lieu of a secret; the token endpoint accepts them on `client_id`
   * + verifier alone.
   */
  tokenEndpointAuthMethod: string | null;
  createdAt: Date;
}

/** RFC 6749 §2.1 / OIDC Discovery `token_endpoint_auth_methods_supported` aliases. */
export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'none';

interface AuthCodeRecord {
  id: number;
  code: string;
  clientId: string;
  userId: number;
  redirectUri: string;
  scope: string | null;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  /** OIDC Core §3.1.2.1 — echoed into the id_token if the authorize request supplied one. */
  nonce: string | null;
  /** Unix seconds (OIDC `auth_time` claim) recorded when the user approved the flow. */
  authTime: number | null;
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

/**
 * Persisted refresh token row. Stores only the SHA-256 hash; the raw token
 * is returned to the client exactly once and never retained.
 *
 * Rotation tracking: every refresh-token request mints a fresh token with a
 * new id, marks the old one's `usedAt`, and links via `parentId`. The
 * `familyId` is shared across the entire chain — detecting reuse of an
 * already-rotated token revokes every member of the family (RFC 9700
 * §2.2.2).
 */
interface RefreshTokenRecord {
  id: number;
  token: string;
  familyId: string;
  clientId: string;
  userId: number;
  scope: string | null;
  issuedAt: Date;
  expiresAt: Date;
  usedAt: Date | null;
  parentId: number | null;
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
  /** OIDC Core §3.1.2.1 nonce — mirrored from the authorize query if present. */
  nonce: string | null;
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
  /** RFC 6749 §6 refresh-token grant payload. */
  refresh_token?: string;
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
  createClient: (data: { name: string; redirectUris: string[]; grantTypes: string[]; allowedScopes?: string[]; tokenEndpointAuthMethod?: TokenEndpointAuthMethod }) => Promise<{ clientId: string; clientSecret: string | null }>;
  createAuthorizationCode: (params: { clientId: string; userId: number; redirectUri: string; scope?: string; codeChallenge?: string; codeChallengeMethod?: string; nonce?: string; authTime?: number }) => Promise<{ code: string }>;
  exchangeCode: (params: { code: string; clientId: string; clientSecret?: string; redirectUri: string; codeVerifier?: string }) => Promise<{ accessToken: string; tokenType: string; expiresIn: number; scope?: string; refreshToken?: string; idToken?: string }>;
  refreshTokenGrant: (params: { clientId: string; clientSecret?: string; refreshToken: string; scope?: string }) => Promise<{ accessToken: string; tokenType: string; expiresIn: number; refreshToken: string; scope?: string }>;
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
  /**
   * OIDC Core 1.0 §5.3 userinfo endpoint. Returns the standard claims set
   * (`sub`, `email`, `email_verified`, `name`, `preferred_username`,
   * `updated_at`) gated by the access token's scope (§5.4), plus anything
   * the {@link OAuthConfig.userinfoClaims} hook contributes. Throws 401
   * for invalid / expired tokens (RFC 6750).
   */
  handleUserInfoRequest: (bearerToken: string) => Promise<Record<string, unknown>>;
  /**
   * RFC 7517 / OIDC Discovery JWKS endpoint. Returns the AS's public
   * verification keys (`{ keys: [...] }`). The first call materialises the
   * active signing key if none has been generated yet; subsequent calls
   * are cheap reads.
   */
  handleJwksRequest: () => Promise<Record<string, unknown>>;
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
  // 30 days. RFC 9700 §2.2.2 doesn't mandate a duration; this matches the
  // default fortress core uses for user-session refresh tokens.
  const refreshTokenExpiry = config.refreshTokenExpirySeconds ?? 30 * 24 * 3600;
  const refreshEnabled = refreshTokenExpiry > 0;
  const idTokenExpiry = config.idTokenExpirySeconds ?? 3600;
  const scopePermissionMap = config.scopePermissionMap;
  const issuerUrl = config.issuerUrl ?? 'https://localhost';

  // RFC 8414 §2 + RFC 9700 §4.16: production issuer URL MUST be HTTPS.
  // Dev / test (`NODE_ENV !== 'production'`) keeps localhost-HTTP working
  // for the example app and integration suites.
  if (
    typeof process !== 'undefined'
    && process.env?.NODE_ENV === 'production'
    && !issuerUrl.startsWith('https://')
  ) {
    throw new Error(
      `[fortress/oauth] issuerUrl must use https:// in production (got: ${issuerUrl})`,
    );
  }

  return {
    name: 'oauth',

    models: [
      {
        name: 'oauth_client',
        fields: {
          id: { type: 'number', required: true },
          clientId: { type: 'string', required: true, unique: true },
          // For public clients (`tokenEndpointAuthMethod === 'none'`) the
          // hash is set to the empty string — the column is required by the
          // adapter for backwards compat, but never compared against an
          // inbound secret.
          clientSecretHash: { type: 'string', required: true },
          name: { type: 'string', required: true },
          redirectUris: { type: 'string', required: true },
          grantTypes: { type: 'string', required: true },
          // RFC 6749 §3.3 / RFC 9700 §2.2.1 per-client scope allow-list.
          // Optional for backwards compatibility with legacy v0 clients
          // created before this column existed.
          allowedScopes: { type: 'string' },
          // RFC 6749 §2.1 client type. Optional — absent on legacy clients,
          // which are treated as confidential (`client_secret_basic`).
          tokenEndpointAuthMethod: { type: 'string' },
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
          // OIDC Core §3.1.2.1 nonce — echoed into the id_token verbatim.
          nonce: { type: 'string' },
          // Unix seconds; OIDC `auth_time` claim source.
          authTime: { type: 'number' },
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
        name: 'oauth_refresh_token',
        fields: {
          id: { type: 'number', required: true },
          token: { type: 'string', required: true, unique: true },
          familyId: { type: 'string', required: true },
          clientId: { type: 'string', required: true },
          userId: { type: 'number', required: true },
          scope: { type: 'string' },
          issuedAt: { type: 'date', required: true },
          expiresAt: { type: 'date', required: true },
          usedAt: { type: 'date' },
          parentId: { type: 'number' },
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
          nonce: { type: 'string' },
          expiresAt: { type: 'date', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        // OIDC Core §2 / RFC 7517 signing key persistence. RS256 only for
        // now; the row stores both public and private JWKs as JSON. Active
        // key has rotatedAt == null.
        name: 'oauth_signing_key',
        fields: {
          id: { type: 'number', required: true },
          kid: { type: 'string', required: true, unique: true },
          alg: { type: 'string', required: true },
          publicJwk: { type: 'string', required: true },
          privateJwk: { type: 'string', required: true },
          createdAt: { type: 'date', required: true },
          rotatedAt: { type: 'date' },
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
        /**
         * RFC 6749 §3.3 / RFC 9700 §2.2.1 scope allow-list. Optional — omit
         * to allow whatever scope the client requests (legacy v0
         * behaviour); pass `[]` to deny all; pass `['openid', 'email']` to
         * gate to a known set.
         */
        allowedScopes?: string[];
        /**
         * RFC 6749 §2.1 / OIDC Discovery client authentication method.
         * Defaults to `'client_secret_basic'` (confidential client). Pass
         * `'none'` for public clients (SPAs, native apps — RFC 8252) which
         * authenticate via PKCE alone; no secret is generated.
         */
        tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
      }): Promise<{ clientId: string; clientSecret: string | null }> {
        const isPublic = data.tokenEndpointAuthMethod === 'none';
        const { raw: clientSecret, hash: clientSecretHash } = isPublic
          ? { raw: '', hash: '' }
          : await generateRefreshToken();
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
            allowedScopes: data.allowedScopes ? JSON.stringify(data.allowedScopes) : null,
            tokenEndpointAuthMethod: data.tokenEndpointAuthMethod ?? 'client_secret_basic',
          },
        });

        return {
          clientId,
          // Public clients have no secret — returning `null` makes the
          // contract explicit at compile time.
          clientSecret: isPublic ? null : clientSecret,
        };
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
        /** OIDC Core §3.1.2.1 nonce; echoed verbatim into the id_token. */
        nonce?: string;
        /** Unix seconds when the user authenticated; OIDC `auth_time`. */
        authTime?: number;
      }): Promise<{ code: string }> {
        // Validate client
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: params.clientId }],
        });

        if (!client)
          throw Errors.oauth('invalid_request', 'Invalid client_id');

        const uris = JSON.parse(client.redirectUris) as string[];
        if (!uris.some(r => matchRedirectUri(r, params.redirectUri)))
          throw Errors.oauth('invalid_request', 'Invalid redirect_uri');

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
            nonce: params.nonce ?? null,
            authTime: params.authTime ?? null,
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
        /**
         * Required for confidential clients; ignored for public clients
         * (`tokenEndpointAuthMethod === 'none'`), which authenticate via
         * PKCE alone (RFC 8252 §8.6).
         */
        clientSecret?: string;
        redirectUri: string;
        codeVerifier?: string;
      }): Promise<{ accessToken: string; tokenType: string; expiresIn: number; scope?: string }> {
        // Validate client credentials
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: params.clientId }],
        });

        if (!client)
          throw Errors.oauth('invalid_client', 'Invalid client credentials');

        const isPublic = client.tokenEndpointAuthMethod === 'none';
        if (!isPublic) {
          if (!params.clientSecret)
            throw Errors.oauth('invalid_client', 'Client secret required');
          const secretValid = timingSafeEqualHex(
            await hashToken(params.clientSecret),
            client.clientSecretHash,
          );
          if (!secretValid)
            throw Errors.oauth('invalid_client', 'Invalid client credentials');
        }
        else if (params.clientSecret) {
          // RFC 6749 §2.3.1: a public client MUST NOT present credentials.
          throw Errors.oauth('invalid_client', 'Public clients must not present a client_secret');
        }

        // Look up the authorization code
        const codeHash = await hashToken(params.code);
        const authCode = await ctx.db.findOne<AuthCodeRecord>({
          model: 'oauth_authorization_code',
          where: [{ field: 'code', operator: '=', value: codeHash }],
        });

        if (!authCode)
          throw Errors.oauth('invalid_grant', 'Invalid authorization code');

        if (authCode.usedAt)
          throw Errors.oauth('invalid_grant', 'Authorization code already used');

        if (authCode.expiresAt < new Date())
          throw Errors.oauth('invalid_grant', 'Authorization code expired');

        if (authCode.clientId !== params.clientId)
          throw Errors.oauth('invalid_grant', 'Client mismatch');

        if (authCode.redirectUri !== params.redirectUri)
          throw Errors.oauth('invalid_grant', 'Redirect URI mismatch');

        // Verify PKCE — RFC 7636 §4.6. The authorize endpoint enforces that
        // every code is bound to a challenge (§4.5 of the compliance plan),
        // so missing PKCE state on the code is itself a server-side bug, but
        // we still treat a missing verifier here as `invalid_grant` to give
        // the right wire response.
        if (authCode.codeChallenge && authCode.codeChallengeMethod) {
          if (!params.codeVerifier)
            throw Errors.oauth('invalid_grant', 'code_verifier required');

          const valid = await verifyCodeChallenge(
            params.codeVerifier,
            authCode.codeChallenge,
            authCode.codeChallengeMethod,
          );

          if (!valid)
            throw Errors.oauth('invalid_grant', 'Invalid code_verifier');
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

        // OIDC Core §3.1.3.7: id_token alongside the access token when the
        // request used scope=openid. Resolve user + active signing key.
        let idToken: string | undefined;
        const scopes = (authCode.scope ?? '').split(' ').filter(Boolean);
        if (scopes.includes('openid')) {
          const user = await ctx.db.findOne<FortressUser>({
            model: 'user',
            where: [{ field: 'id', operator: '=', value: authCode.userId }],
          });
          if (user) {
            const signingKey = await getActiveSigningKey(ctx.db);
            idToken = await issueIdToken({
              user,
              clientId: params.clientId,
              issuerUrl,
              ttlSeconds: idTokenExpiry,
              nonce: authCode.nonce ?? undefined,
              authTimeSeconds: authCode.authTime ?? Math.floor(Date.now() / 1000),
              scope: authCode.scope,
              signingKey,
            });
          }
        }

        // RFC 6749 §6 + RFC 9700 §2.2.2: issue a refresh token alongside the
        // access token at the start of a new rotation family. Public clients
        // (RFC 8252) get them too; rotation + replay detection is the
        // mitigation, not client confidentiality.
        let refreshTokenRaw: string | undefined;
        if (refreshEnabled) {
          const { raw, hash } = await generateRefreshToken();
          refreshTokenRaw = raw;
          await ctx.db.create({
            model: 'oauth_refresh_token',
            data: {
              token: hash,
              familyId: generateTokenFamily(),
              clientId: params.clientId,
              userId: authCode.userId,
              scope: authCode.scope ?? null,
              issuedAt: new Date(),
              expiresAt: new Date(Date.now() + refreshTokenExpiry * 1000),
              usedAt: null,
              parentId: null,
            },
          });
        }

        return {
          accessToken: tokenRaw,
          tokenType: 'Bearer',
          expiresIn: accessTokenExpiry,
          scope: authCode.scope ?? undefined,
          ...(refreshTokenRaw ? { refreshToken: refreshTokenRaw } : {}),
          ...(idToken ? { idToken } : {}),
        };
      },

      /**
       * RFC 6749 §6 refresh-token grant with RFC 9700 §2.2.2 rotation.
       *
       * Flow:
       * 1. Look up the inbound refresh token by hash.
       * 2. If it's already been used (`usedAt != null`), this is a replay
       *    attack — delete every refresh token in the same family and
       *    throw `invalid_grant`. The legitimate client's most recent
       *    refresh dies with the family, so the user is forced to
       *    re-authenticate, but the attacker's stolen token is now
       *    useless.
       * 3. Otherwise mark the old token used, mint a new access token +
       *    a new refresh token in the same family, link the new refresh
       *    via `parentId`, and return the pair.
       */
      async refreshTokenGrant(params: {
        clientId: string;
        clientSecret?: string;
        refreshToken: string;
        scope?: string;
      }): Promise<{ accessToken: string; tokenType: string; expiresIn: number; refreshToken: string; scope?: string }> {
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: params.clientId }],
        });
        if (!client)
          throw Errors.oauth('invalid_client', 'Invalid client credentials');

        const isPublic = client.tokenEndpointAuthMethod === 'none';
        if (!isPublic) {
          if (!params.clientSecret)
            throw Errors.oauth('invalid_client', 'Client secret required');
          const secretValid = timingSafeEqualHex(
            await hashToken(params.clientSecret),
            client.clientSecretHash,
          );
          if (!secretValid)
            throw Errors.oauth('invalid_client', 'Invalid client credentials');
        }

        const tokenHash = await hashToken(params.refreshToken);

        const grant = await ctx.db.transaction(async (tx) => {
          const record = await tx.findOne<RefreshTokenRecord>({
            model: 'oauth_refresh_token',
            where: [{ field: 'token', operator: '=', value: tokenHash }],
          });
          if (!record)
            throw Errors.oauth('invalid_grant', 'Invalid refresh token');

          if (record.clientId !== params.clientId)
            throw Errors.oauth('invalid_grant', 'Refresh token client mismatch');

          if (record.expiresAt < new Date())
            throw Errors.oauth('invalid_grant', 'Refresh token expired');

          // RFC 9700 §2.2.2 replay detection. Reuse of a rotated token means
          // an attacker stole it, OR the legitimate client missed the
          // response and is retrying. Either way, the family is compromised
          // and must die.
          if (record.usedAt) {
            await tx.delete({
              model: 'oauth_refresh_token',
              where: [{ field: 'familyId', operator: '=', value: record.familyId }],
            });
            return { replayDetected: true as const };
          }

          // RFC 6749 §6: refreshed scope MUST NOT include any scope not
          // originally granted. We allow narrowing only.
          let scope = record.scope;
          if (params.scope) {
            const requested = params.scope.split(' ').filter(Boolean);
            const original = (record.scope ?? '').split(' ').filter(Boolean);
            const originalSet = new Set(original);
            const widened = requested.find(s => !originalSet.has(s));
            if (widened) {
              throw Errors.oauth('invalid_scope', `Refreshed scope cannot widen: ${widened}`);
            }
            scope = requested.join(' ');
          }

          // Atomic compare-and-set claim: only one concurrent caller can mark
          // a never-used refresh token as used.
          const claimed = await tx.update<RefreshTokenRecord>({
            model: 'oauth_refresh_token',
            where: [
              { field: 'id', operator: '=', value: record.id },
              { field: 'usedAt', operator: 'isNull', value: null },
            ],
            data: { usedAt: new Date() },
          });
          if (!claimed) {
            await tx.delete({
              model: 'oauth_refresh_token',
              where: [{ field: 'familyId', operator: '=', value: record.familyId }],
            });
            return { replayDetected: true as const };
          }

          // Mint the new access token.
          const { raw: accessRaw, hash: accessHash } = await generateRefreshToken();
          await tx.create({
            model: 'oauth_access_token',
            data: {
              token: accessHash,
              clientId: params.clientId,
              userId: record.userId,
              scope,
              expiresAt: new Date(Date.now() + accessTokenExpiry * 1000),
            },
          });

          // Mint the new refresh token in the same family.
          const { raw: refreshRaw, hash: refreshHash } = await generateRefreshToken();
          await tx.create({
            model: 'oauth_refresh_token',
            data: {
              token: refreshHash,
              familyId: record.familyId,
              clientId: params.clientId,
              userId: record.userId,
              scope,
              issuedAt: new Date(),
              expiresAt: new Date(Date.now() + refreshTokenExpiry * 1000),
              usedAt: null,
              parentId: record.id,
            },
          });

          return {
            accessToken: accessRaw,
            tokenType: 'Bearer',
            expiresIn: accessTokenExpiry,
            refreshToken: refreshRaw,
            ...(scope ? { scope } : {}),
          };
        });

        if ('replayDetected' in grant)
          throw Errors.oauth('invalid_grant', 'Refresh token reuse detected; family revoked');
        return grant;
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
          throw Errors.oauth('invalid_client', 'Invalid client credentials');

        // RFC 6749 §4.4 client_credentials inherently requires a secret.
        // Public clients have no secret, so they cannot use this grant.
        if (client.tokenEndpointAuthMethod === 'none')
          throw Errors.oauth('unauthorized_client', 'Public clients cannot use client_credentials');

        const grantTypes = JSON.parse(client.grantTypes) as string[];
        if (!grantTypes.includes('client_credentials'))
          throw Errors.oauth('unauthorized_client', 'Client does not support client_credentials grant');

        const secretValid = timingSafeEqualHex(
          await hashToken(params.clientSecret),
          client.clientSecretHash,
        );
        if (!secretValid)
          throw Errors.oauth('invalid_client', 'Invalid client credentials');

        // RFC 6749 §3.3 scope intersection — same as authorize code grant.
        const effectiveScope = intersectScope(params.scope ?? null, client.allowedScopes);
        if (params.scope && effectiveScope === '') {
          throw Errors.oauth('invalid_scope', 'No requested scope is allowed for this client');
        }

        const { raw: tokenRaw, hash: tokenHash } = await generateRefreshToken();
        const expiresAt = new Date(Date.now() + accessTokenExpiry * 1000);

        await ctx.db.create({
          model: 'oauth_access_token',
          data: {
            token: tokenHash,
            clientId: params.clientId,
            userId: null,
            scope: effectiveScope || null,
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
       * Revoke an access token OR refresh token (RFC 7009).
       *
       * Per §2.1: revoking a refresh token also revokes the related access
       * tokens. When a refresh token is revoked here, the entire token
       * family is dropped — every rotated descendant becomes unusable.
       */
      async revokeToken(token: string): Promise<void> {
        const tokenHash = await hashToken(token);
        // Try as access token first.
        await ctx.db.delete({
          model: 'oauth_access_token',
          where: [{ field: 'token', operator: '=', value: tokenHash }],
        });
        // Try as refresh token — if the hash matches, kill the whole family.
        if (refreshEnabled) {
          const refreshRecord = await ctx.db.findOne<RefreshTokenRecord>({
            model: 'oauth_refresh_token',
            where: [{ field: 'token', operator: '=', value: tokenHash }],
          });
          if (refreshRecord) {
            await ctx.db.delete({
              model: 'oauth_refresh_token',
              where: [{ field: 'familyId', operator: '=', value: refreshRecord.familyId }],
            });
          }
        }
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
        const nonce = query.nonce;
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
          throw Errors.oauth('invalid_request', 'client_id is required');
        if (!redirectUri)
          throw Errors.oauth('invalid_request', 'redirect_uri is required');
        if (responseType !== 'code')
          throw Errors.oauth('unsupported_response_type', 'response_type must be "code"');
        if (!state)
          throw Errors.oauth('invalid_request', 'state is required');

        // Validate the client and redirect URI up front so a bogus client
        // never reaches the user-facing pages. Per RFC 6749 §4.1.2.1, the AS
        // MUST NOT redirect when the client_id or redirect_uri can't be
        // trusted — returning the error directly here is the correct shape.
        const client = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: clientId }],
        });
        if (!client)
          throw Errors.oauth('invalid_request', 'Unknown client_id');

        const allowedRedirects = JSON.parse(client.redirectUris) as string[];
        if (!allowedRedirects.some(r => matchRedirectUri(r, redirectUri)))
          throw Errors.oauth('invalid_request', 'Invalid redirect_uri');

        // RFC 9700 §2.1.1: PKCE is mandatory. The escape hatch
        // `allowNonPkceConfidentialClients` exists for legacy server-side RPs
        // and is documented as discouraged.
        if (!codeChallenge && !config.allowNonPkceConfidentialClients) {
          throw Errors.oauth('invalid_request', 'code_challenge is required (PKCE)');
        }

        // PKCE method validation — we only support S256 (matches the
        // discovery document).
        if (codeChallenge && codeChallengeMethod && codeChallengeMethod !== 'S256') {
          throw Errors.oauth('invalid_request', 'Only S256 code_challenge_method is supported');
        }
        // RFC 7636 §4.3 default for `code_challenge_method` when only the
        // challenge is sent is `plain`, which we don't support — require the
        // method to be explicit.
        if (codeChallenge && !codeChallengeMethod) {
          throw Errors.oauth(
            'invalid_request',
            'code_challenge_method is required when code_challenge is set; only S256 is supported',
          );
        }

        // RFC 6749 §3.3: intersect the requested scopes against the client's
        // allow-list. Empty intersection (after non-empty request) returns
        // `invalid_scope`; subset is silently narrowed.
        const effectiveScope = intersectScope(scope ?? null, client.allowedScopes);
        if (scope && effectiveScope === '') {
          throw Errors.oauth('invalid_scope', 'No requested scope is allowed for this client');
        }

        const expiresAt = new Date(Date.now() + pendingFlowExpiry * 1000);
        const flow = await ctx.db.create<PendingFlowRecord>({
          model: 'oauth_pending_flow',
          data: {
            clientId,
            redirectUri,
            scope: effectiveScope || null,
            state,
            codeChallenge: codeChallenge ?? null,
            codeChallengeMethod: codeChallengeMethod ?? null,
            nonce: nonce ?? null,
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
        context: { userId: number; authTimeSeconds?: number },
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
          nonce: flow.nonce ?? undefined,
          // OIDC Core §2 `auth_time` — if the host app passes the user's
          // session-issued-at, use it; otherwise fall back to "now" (i.e.
          // the user has just consented).
          authTime: context.authTimeSeconds ?? Math.floor(Date.now() / 1000),
        });
        // Consume the pending flow only after the code is in place.
        await ctx.db.delete({
          model: 'oauth_pending_flow',
          where: [{ field: 'id', operator: '=', value: flow.id }],
        });

        const url = new URL(flow.redirectUri);
        url.searchParams.set('code', code);
        url.searchParams.set('state', flow.state);
        // RFC 9207 §2: the AS MUST identify itself in the authorization
        // response so the RP can detect mix-up attacks (RFC 9700 §4.4).
        url.searchParams.set('iss', issuerUrl);
        return { redirectUrl: url.toString() };
      },

      /**
       * Deny a pending flow. Consumes the flow row and returns the OAuth
       * client's redirect URI with `?error=access_denied&state=...&iss=...`.
       *
       * Per RFC 9207 §2, the issuer parameter is included on error responses
       * too — the RP needs to validate the AS identity before trusting any
       * field, including `error`.
       */
      async handleDenyFlow(flowId: number): Promise<{ redirectUrl: string }> {
        const flow = await this.resumePendingFlow(flowId);
        const url = new URL(flow.redirectUri);
        url.searchParams.set('error', 'access_denied');
        url.searchParams.set('state', flow.state);
        url.searchParams.set('iss', issuerUrl);
        return { redirectUrl: url.toString() };
      },

      async getUserInfo(token: string): Promise<FortressUser | null> {
        const result = await this._lookupBearer(token);
        return result?.user ?? null;
      },

      /**
       * Internal: resolve a bearer token to its access-token row + user.
       * Shared by `getUserInfo` (returns the raw user) and
       * `handleUserInfoRequest` (maps to OIDC claims).
       */
      async _lookupBearer(token: string): Promise<{ user: FortressUser; scope: string | null } | null> {
        const tokenHash = await hashToken(token);
        const record = await ctx.db.findOne<AccessTokenRecord>({
          model: 'oauth_access_token',
          where: [{ field: 'token', operator: '=', value: tokenHash }],
        });

        if (!record || !record.userId || record.expiresAt < new Date())
          return null;

        const user = await ctx.db.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: record.userId }],
        });
        if (!user)
          return null;
        return { user, scope: record.scope };
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

        if (!clientId)
          throw Errors.oauth('invalid_client', 'Client authentication required');

        // Resolve client to know whether it's public; we only short-circuit
        // the secret check if the registered method is `'none'`.
        const clientRecord = await ctx.db.findOne<OAuthClientRecord>({
          model: 'oauth_client',
          where: [{ field: 'clientId', operator: '=', value: clientId }],
        });
        if (!clientRecord)
          throw Errors.oauth('invalid_client', 'Invalid client credentials');
        const isPublic = clientRecord.tokenEndpointAuthMethod === 'none';
        if (!isPublic && !clientSecret)
          throw Errors.oauth('invalid_client', 'Client authentication required');

        if (body.grant_type === 'authorization_code') {
          if (!body.code || !body.redirect_uri)
            throw Errors.oauth('invalid_request', 'Missing required parameters: code, redirect_uri');
          // RFC 7636 §4.1: PKCE verifier is REQUIRED for public clients.
          if (isPublic && !body.code_verifier)
            throw Errors.oauth('invalid_grant', 'code_verifier required for public clients');

          const result = await this.exchangeCode({
            code: body.code,
            clientId,
            clientSecret: isPublic ? undefined : clientSecret,
            redirectUri: body.redirect_uri,
            codeVerifier: body.code_verifier,
          }) as { accessToken: string; tokenType: string; expiresIn: number; scope?: string; refreshToken?: string; idToken?: string };

          return {
            access_token: result.accessToken,
            token_type: result.tokenType,
            expires_in: result.expiresIn,
            ...(result.refreshToken ? { refresh_token: result.refreshToken } : {}),
            ...(result.idToken ? { id_token: result.idToken } : {}),
            ...(result.scope ? { scope: result.scope } : {}),
          };
        }

        if (body.grant_type === 'refresh_token') {
          if (!body.refresh_token)
            throw Errors.oauth('invalid_request', 'refresh_token is required');
          const result = await this.refreshTokenGrant({
            clientId,
            clientSecret: isPublic ? undefined : clientSecret,
            refreshToken: body.refresh_token,
            scope: body.scope,
          });
          return {
            access_token: result.accessToken,
            token_type: result.tokenType,
            expires_in: result.expiresIn,
            refresh_token: result.refreshToken,
            ...(result.scope ? { scope: result.scope } : {}),
          };
        }

        if (body.grant_type === 'client_credentials') {
          if (!clientSecret)
            throw Errors.oauth('invalid_client', 'client_credentials requires a client secret');
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

        throw Errors.oauth('unsupported_grant_type', `Unsupported grant_type: ${body.grant_type}`);
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

        const secretValid = timingSafeEqualHex(
          await hashToken(clientAuth.clientSecret),
          client.clientSecretHash,
        );
        if (!secretValid)
          throw Errors.oauth('invalid_client', 'Invalid client credentials');

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
       * Handle GET /oauth/userinfo (OpenID Connect Core §5.3).
       *
       * Returns the OIDC-shaped claims object expected by strict RPs (Moodle
       * `core\oauth2\client::get_userinfo()`, openid-client, Keycloak
       * federation, Spring Security). The pre-1.0 fortress shape that
       * leaked DB-internal fields (`id`, `isActive`, `createdAt`) is gone
       * — callers must rely on the spec-conformant fields below.
       *
       * Standard claim coverage (OIDC Core §5.1) gated by access-token
       * scope (§5.4):
       * - `sub` always (stringified `user.id`)
       * - `email`, `email_verified` when scope contains `email` or no
       *   `openid` scope was issued (legacy non-OIDC compatibility)
       * - `name`, `preferred_username` when scope contains `profile` or
       *   no `openid` scope was issued
       * - `updated_at` always (Unix seconds, per §5.1)
       *
       * Extra claims can be added per-deployment via
       * {@link OAuthConfig.userinfoClaims}.
       */
      async handleUserInfoRequest(bearerToken: string): Promise<Record<string, unknown>> {
        const result = await this._lookupBearer(bearerToken);
        if (!result)
          throw Errors.unauthorized('Invalid or expired access token');

        const claims = toOidcUserinfo(result.user, result.scope);
        if (config.userinfoClaims) {
          const extra = await config.userinfoClaims(result.user, result.scope);
          Object.assign(claims, extra);
        }
        return claims;
      },

      /**
       * Handle GET /.well-known/openid-configuration (RFC 8414 + OIDC
       * Discovery 1.0). Includes the RFC 9207 metadata flag and the OIDC
       * fields strict RPs (Moodle, openid-client, Spring Security) require
       * for autoconfig.
       */
      handleDiscovery(): Record<string, unknown> {
        const issuer = issuerUrl;
        const mappedScopes = scopePermissionMap ? Object.keys(scopePermissionMap) : [];
        const scopesSupported = Array.from(new Set([
          'openid',
          'email',
          'profile',
          ...(config.scopesSupported ?? []),
          ...mappedScopes,
        ]));
        return {
          issuer,
          authorization_endpoint: `${issuer}/oauth/authorize`,
          token_endpoint: `${issuer}/oauth/token`,
          introspection_endpoint: `${issuer}/oauth/introspect`,
          revocation_endpoint: `${issuer}/oauth/revoke`,
          userinfo_endpoint: `${issuer}/oauth/userinfo`,
          jwks_uri: `${issuer}/oauth/.well-known/jwks.json`,
          response_types_supported: ['code'],
          response_modes_supported: ['query'],
          grant_types_supported: refreshEnabled
            ? ['authorization_code', 'client_credentials', 'refresh_token']
            : ['authorization_code', 'client_credentials'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
          code_challenge_methods_supported: ['S256'],
          subject_types_supported: ['public'],
          // OIDC Discovery §3 REQUIRED when id_tokens are issued.
          id_token_signing_alg_values_supported: ['RS256'],
          scopes_supported: scopesSupported,
          claims_supported: [
            'sub',
            'email',
            'email_verified',
            'name',
            'preferred_username',
            'updated_at',
            'iss',
            'aud',
            'exp',
            'iat',
            'auth_time',
            'nonce',
          ],
          // RFC 9207 §3.
          authorization_response_iss_parameter_supported: true,
        };
      },

      /**
       * Handle GET /oauth/.well-known/jwks.json (RFC 7517).
       *
       * Returns the AS's JSON Web Key Set: the active RS256 public key
       * plus any rotated keys still in the verification grace window. RPs
       * fetch this URL (advertised via discovery's `jwks_uri`) and use it
       * to verify id_token signatures by `kid`.
       */
      async handleJwksRequest(): Promise<Record<string, unknown>> {
        const jwks = await listJwks(ctx.db);
        // First call materialises the active key if none exists yet —
        // ensures discovery + JWKS stay in sync without a deploy step.
        if (jwks.keys.length === 0) {
          await getActiveSigningKey(ctx.db);
          return await listJwks(ctx.db);
        }
        return jwks;
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
                bearerKind: 'oauth' as const,
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
        meta: { summary: 'Exchange credentials for tokens', tags: ['OAuth'], security: ['basic'], bearerKind: 'oauth' as const },
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
        meta: { summary: 'Introspect a token (RFC 7662)', tags: ['OAuth'], security: ['basic'], bearerKind: 'oauth' as const },
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
        meta: { summary: 'Revoke a token (RFC 7009)', tags: ['OAuth'], security: ['none'], bearerKind: 'oauth' as const },
        input: { body: { type: 'object', properties: { token: { type: 'string' } }, required: ['token'] } },
        responses: { 200: { description: 'Token revoked' } },
      },
      handleUserInfoRequest: {
        method: 'GET',
        path: '/oauth/userinfo',
        handler: 'handleUserInfoRequest',
        meta: { summary: 'Get user info (OIDC Core §5.3)', tags: ['OAuth'], security: ['bearer'], bearerKind: 'oauth' as const },
        responses: {
          200: {
            description: 'OIDC userinfo response',
            schema: {
              type: 'object',
              properties: {
                sub: { type: 'string', description: 'Stringified user identifier' },
                email: { type: 'string', format: 'email' },
                email_verified: { type: 'boolean' },
                name: { type: 'string' },
                preferred_username: { type: 'string' },
                updated_at: { type: 'number', description: 'Unix seconds since the user record was last updated' },
              },
              required: ['sub'],
              additionalProperties: true,
            },
          },
          401: { description: 'Invalid or expired bearer token' },
        },
      },
      handleDiscovery: {
        method: 'GET',
        path: '/oauth/.well-known/openid-configuration',
        handler: 'handleDiscovery',
        meta: { summary: 'OIDC discovery document', tags: ['OAuth'], security: ['none'], bearerKind: 'oauth' as const },
        responses: { 200: { description: 'OIDC configuration', schema: { type: 'object', additionalProperties: true } } },
      },
      handleJwksRequest: {
        method: 'GET',
        path: '/oauth/.well-known/jwks.json',
        handler: 'handleJwksRequest',
        meta: { summary: 'JSON Web Key Set (RFC 7517)', tags: ['OAuth'], security: ['none'], bearerKind: 'oauth' as const },
        responses: {
          200: {
            description: 'JWKS for verifying id_token signatures',
            schema: {
              type: 'object',
              properties: {
                keys: {
                  type: 'array',
                  items: { type: 'object', additionalProperties: true },
                },
              },
              required: ['keys'],
            },
          },
        },
      },
    },
  };
}

/**
 * RFC 8252 §8.4 redirect-URI matcher with the loopback exception.
 *
 * Confidential clients still get exact-match (the registered URI must equal
 * the inbound URI byte-for-byte). Native / public clients that registered an
 * `http://127.0.0.1/<path>` or `http://[::1]/<path>` redirect MUST be allowed
 * to vary the port at runtime, because the loopback HTTP server picks one
 * dynamically. Path, query, and fragment still have to match.
 *
 * This is intentionally narrow: only `127.0.0.1` and `[::1]` get the
 * any-port leniency. `localhost` (DNS-resolved) is NOT widened — RFC 8252
 * §8.3 actively recommends against it for security reasons (DNS rebinding).
 */
export function matchRedirectUri(registered: string, inbound: string): boolean {
  if (registered === inbound)
    return true;
  let r: URL, i: URL;
  try {
    r = new URL(registered);
    i = new URL(inbound);
  }
  catch {
    return false;
  }
  const isLoopback = r.protocol === 'http:'
    && (r.hostname === '127.0.0.1' || r.hostname === '[::1]')
    && r.hostname === i.hostname;
  if (!isLoopback)
    return false;
  return (
    r.protocol === i.protocol
    && r.pathname === i.pathname
    && r.search === i.search
  );
}

/**
 * RFC 6749 §3.3 scope-intersection helper.
 *
 * - When `clientAllowed` is `null` (legacy / unset), the request scope is
 *   passed through unchanged.
 * - When `clientAllowed` is `[]`, no scope is allowed — returns `''`.
 * - Otherwise returns the intersection as a space-separated string,
 *   preserving the original ordering of the requested scopes (so RPs see
 *   the scopes back in the order they asked for, minus the dropped ones).
 */
function intersectScope(
  requested: string | null,
  clientAllowedJson: string | null | undefined,
): string {
  // No requested scope: empty result, regardless of client allow-list.
  if (!requested)
    return '';
  // Legacy v0 clients (created before `allowedScopes` existed) have a
  // missing column — the adapter returns `null` or `undefined`. Treat
  // both as "unset" and pass scope through.
  if (clientAllowedJson == null)
    return requested;
  const allowed = JSON.parse(clientAllowedJson) as string[];
  const allowedSet = new Set(allowed);
  return requested
    .split(' ')
    .filter(Boolean)
    .filter(s => allowedSet.has(s))
    .join(' ');
}

export { generateCodeChallenge, generateCodeVerifier, verifyCodeChallenge } from './pkce';

/**
 * Map a fortress user record to an OIDC-Core-§5.1 claims object, gated by
 * the access token's scope per §5.4.
 *
 * Exported so host apps with a custom `handleUserInfoRequest` (e.g. one
 * that adds tenant claims) can compose on top of the same baseline rather
 * than re-implementing the OIDC shape from scratch.
 */
export function toOidcUserinfo(
  user: FortressUser,
  scope: string | null | undefined,
): Record<string, unknown> {
  const scopes = scope ? scope.split(' ').filter(Boolean) : [];
  // OIDC Core §5.4 only governs scope gating when the request was an
  // OIDC request (i.e. used `openid`). For non-OIDC OAuth tokens we expose
  // the full claim set — this preserves the long-standing fortress
  // behaviour for callers that rely on /oauth/userinfo as a generic
  // user-profile endpoint and matches what the TDMP override emitted.
  const isOidc = scopes.includes('openid');
  const exposeEmail = !isOidc || scopes.includes('email');
  const exposeProfile = !isOidc || scopes.includes('profile');

  const claims: Record<string, unknown> = { sub: String(user.id) };
  if (exposeEmail) {
    claims.email = user.email;
    if (typeof user.emailVerified === 'boolean')
      claims.email_verified = user.emailVerified;
  }
  if (exposeProfile) {
    claims.name = user.name;
    // OIDC has no canonical "username" field on a fortress user record
    // (email serves that role); use email as the stable, human-readable
    // identifier RPs expect in `preferred_username`.
    claims.preferred_username = user.email;
  }
  if (user.updatedAt) {
    claims.updated_at = Math.floor(new Date(user.updatedAt).getTime() / 1000);
  }
  return claims;
}
