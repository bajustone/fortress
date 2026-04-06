# OAuth Plugin

OAuth 2.0 authorization server with PKCE support and scope-to-IAM permission mapping.

Implements RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7662 (Token Introspection), RFC 7009 (Token Revocation), and partial RFC 8414 (OIDC Discovery). Supports authorization code and client credentials grant types.

The unique differentiator is `scopePermissionMap`, which bridges OAuth scopes to Fortress IAM permissions so that token-based access control and role-based access control share a single permission model.

## Installation

```ts
import { createFortress } from "@bajustone/fortress";
import { oauth } from "@bajustone/fortress/plugins/oauth";

const fortress = createFortress({
  jwt: { secret: "your-secret-minimum-32-bytes-long!" },
  database: db,
  plugins: [
    oauth({
      issuerUrl: "https://auth.example.com",
      scopePermissionMap: {
        "read:posts": { resource: "post", action: "read" },
        "write:posts": { resource: "post", action: "create" },
        "read:users": { resource: "user", action: "list" },
      },
    }),
  ],
});
```

## Configuration

All fields in `OAuthConfig` are optional.

| Option | Type | Default | Description |
|---|---|---|---|
| `authCodeExpirySeconds` | `number` | `600` (10 min) | How long an authorization code is valid. |
| `pendingFlowExpirySeconds` | `number` | `600` (10 min) | How long a pending flow (identity broker) survives before expiry. |
| `accessTokenExpirySeconds` | `number` | `3600` (1 hour) | Lifetime of issued access tokens. |
| `scopePermissionMap` | `Record<string, { resource: string; action: string }>` | `undefined` | Maps OAuth scope strings to Fortress IAM resource+action pairs. |
| `issuerUrl` | `string` | `"https://localhost"` | Base URL of the authorization server. Used in the OIDC discovery document and endpoint URLs. |

### scopePermissionMap

This is the bridge between OAuth and Fortress IAM. When a token carries scopes like `"read:posts write:posts"`, calling `resolveTokenPermissions(token)` returns the corresponding IAM permissions:

```ts
const fortress = createFortress({
  // ...
  plugins: [
    oauth({
      scopePermissionMap: {
        "read:posts":  { resource: "post", action: "read" },
        "write:posts": { resource: "post", action: "create" },
        "admin:users": { resource: "user", action: "delete" },
      },
    }),
  ],
});

// Later, in a request handler:
const permissions = await fortress.plugins.oauth.resolveTokenPermissions(token);
// => [{ resource: "post", action: "read" }, { resource: "post", action: "create" }]
```

Scopes not present in the map are silently ignored. Tokens with no scope return an empty array.

## Usage

All methods are available on `fortress.plugins.oauth`.

### Client Registration

Register an OAuth client. The returned `clientSecret` is shown once and stored as a hash.

```ts
const { clientId, clientSecret } = await fortress.plugins.oauth.createClient({
  name: "My Web App",
  redirectUris: ["https://app.example.com/callback"],
  grantTypes: ["authorization_code"],
});

// Store clientId and clientSecret securely in the consuming application.
// clientSecret cannot be retrieved again.
```

For service-to-service clients that do not involve a user:

```ts
const { clientId, clientSecret } = await fortress.plugins.oauth.createClient({
  name: "Background Worker",
  redirectUris: [],
  grantTypes: ["client_credentials"],
});
```

A client can support both grant types:

```ts
const { clientId, clientSecret } = await fortress.plugins.oauth.createClient({
  name: "Hybrid App",
  redirectUris: ["https://app.example.com/callback"],
  grantTypes: ["authorization_code", "client_credentials"],
});
```

### Authorization Code Flow

The standard three-step flow: redirect the user to your authorization UI, generate a code after they approve, then exchange the code for tokens.

**Step 1: Generate an authorization code** (after the user authenticates and consents)

```ts
const { code } = await fortress.plugins.oauth.createAuthorizationCode({
  clientId: "the-client-id",
  userId: authenticatedUser.id,
  redirectUri: "https://app.example.com/callback",
  scope: "read:posts write:posts",
});

// Redirect the user back to the client:
// https://app.example.com/callback?code=<code>&state=<state>
```

**Step 2: Exchange the code for an access token** (the client calls this)

```ts
const tokens = await fortress.plugins.oauth.exchangeCode({
  code: "the-authorization-code",
  clientId: "the-client-id",
  clientSecret: "the-client-secret",
  redirectUri: "https://app.example.com/callback",
});

// tokens = {
//   accessToken: "...",
//   tokenType: "Bearer",
//   expiresIn: 3600,
//   scope: "read:posts write:posts",
// }
```

Authorization codes are single-use. Attempting to exchange a code twice throws an error.

### PKCE Support

PKCE (Proof Key for Code Exchange, RFC 7636) prevents authorization code interception attacks. Only S256 is supported.

The plugin exports `generateCodeVerifier` and `generateCodeChallenge` helpers:

```ts
import {
  generateCodeChallenge,
  generateCodeVerifier,
} from "@bajustone/fortress/plugins/oauth";

// Client generates a verifier and challenge before starting the flow
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Pass the challenge when creating the authorization code
const { code } = await fortress.plugins.oauth.createAuthorizationCode({
  clientId: "the-client-id",
  userId: authenticatedUser.id,
  redirectUri: "https://app.example.com/callback",
  codeChallenge,
  codeChallengeMethod: "S256",
});

// When exchanging, provide the original verifier
const tokens = await fortress.plugins.oauth.exchangeCode({
  code,
  clientId: "the-client-id",
  clientSecret: "the-client-secret",
  redirectUri: "https://app.example.com/callback",
  codeVerifier,
});
```

If a code was created with a `codeChallenge`, the `codeVerifier` is mandatory at exchange time. A wrong verifier is rejected with `"Invalid code_verifier"`.

### Client Credentials Grant

For service-to-service authentication where no user is involved:

```ts
const tokens = await fortress.plugins.oauth.clientCredentialsGrant({
  clientId: "the-client-id",
  clientSecret: "the-client-secret",
  scope: "read:posts",
});

// tokens = {
//   accessToken: "...",
//   tokenType: "Bearer",
//   expiresIn: 3600,
// }
```

The client must have `"client_credentials"` in its `grantTypes` list, otherwise the call is rejected.

### Token Introspection

Check whether an access token is active and retrieve its metadata (RFC 7662):

```ts
const info = await fortress.plugins.oauth.introspectToken(accessToken);

if (info.active) {
  console.log(info.clientId); // which client issued this token
  console.log(info.userId);   // associated user (undefined for client_credentials)
  console.log(info.scope);    // space-separated scopes
}
```

### Token Revocation

Immediately invalidate an access token (RFC 7009):

```ts
await fortress.plugins.oauth.revokeToken(accessToken);
```

Revoking a nonexistent or already-revoked token is a no-op (no error thrown), per the RFC.

### Pending Flows (Identity Broker Pattern)

When the user arrives at your `/authorize` endpoint but is not yet authenticated, you can park the OAuth flow, send the user through login, then resume:

```ts
// 1. User hits /authorize but is not logged in -- save the flow
const { flowId } = await fortress.plugins.oauth.createPendingFlow({
  clientId: query.client_id,
  redirectUri: query.redirect_uri,
  scope: query.scope,
  state: query.state,
  codeChallenge: query.code_challenge,
  codeChallengeMethod: query.code_challenge_method,
});

// 2. Redirect to login, passing flowId (e.g. /login?flow=<flowId>)

// 3. After login, resume the flow
const flow = await fortress.plugins.oauth.resumePendingFlow(flowId);

// 4. Now issue the authorization code with the authenticated user
const { code } = await fortress.plugins.oauth.createAuthorizationCode({
  clientId: flow.clientId,
  userId: authenticatedUser.id,
  redirectUri: flow.redirectUri,
  scope: flow.scope ?? undefined,
  codeChallenge: flow.codeChallenge ?? undefined,
  codeChallengeMethod: flow.codeChallengeMethod ?? undefined,
});

// 5. Redirect back to the client
// https://app.example.com/callback?code=<code>&state=<flow.state>
```

Pending flows are single-use and expire after `pendingFlowExpirySeconds` (default 10 minutes).

### Scope-to-IAM Permission Mapping

Resolve an access token's scopes into Fortress IAM permissions:

```ts
const permissions = await fortress.plugins.oauth.resolveTokenPermissions(token);
// => [{ resource: "post", action: "read" }, { resource: "post", action: "create" }]

// Use with fortress.iam to check access
for (const perm of permissions) {
  const allowed = await fortress.iam.checkPermission(userId, perm.resource, perm.action);
  // ...
}
```

Returns an empty array if the token has no scope, is inactive, or if no `scopePermissionMap` was configured.

### UserInfo

Retrieve the user associated with an access token (OpenID Connect userinfo):

```ts
const user = await fortress.plugins.oauth.getUserInfo(accessToken);
// => { id: 1, email: "alice@example.com", name: "Alice", ... } or null
```

Returns `null` for invalid/expired tokens or client_credentials tokens (which have no user).

## HTTP Endpoints

Mount all plugin routes onto a Hono app with a single call:

```ts
import { Hono } from "hono";
import { mountPluginRoutes } from "@bajustone/fortress/hono";

const app = new Hono();
mountPluginRoutes(app, fortress);
```

This registers the following endpoints. An optional `prefix` can be passed: `mountPluginRoutes(app, fortress, { prefix: "/api" })`.

### POST /oauth/token

Exchange an authorization code or client credentials for an access token.

**Content-Type:** `application/x-www-form-urlencoded`

**Client authentication:** HTTP Basic (`Authorization: Basic base64(clientId:clientSecret)`) or body params (`client_id` + `client_secret`).

Authorization code grant:

```bash
curl -X POST https://auth.example.com/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=the-auth-code" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "code_verifier=the-pkce-verifier"
```

Client credentials grant:

```bash
curl -X POST https://auth.example.com/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=read:posts"
```

**Response:**

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:posts"
}
```

### POST /oauth/introspect

Validate an access token (RFC 7662). Requires client authentication via HTTP Basic.

```bash
curl -X POST https://auth.example.com/oauth/introspect \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=the-access-token"
```

**Response (active):**

```json
{
  "active": true,
  "client_id": "...",
  "sub": "42",
  "scope": "read:posts",
  "token_type": "Bearer"
}
```

**Response (inactive/expired/revoked):**

```json
{
  "active": false
}
```

### POST /oauth/revoke

Revoke an access token (RFC 7009). Always returns HTTP 200, even if the token does not exist.

```bash
curl -X POST https://auth.example.com/oauth/revoke \
  -d "token=the-access-token"
```

### GET /oauth/userinfo

Get the user profile for a valid access token (OIDC userinfo). Requires a Bearer token.

```bash
curl https://auth.example.com/oauth/userinfo \
  -H "Authorization: Bearer the-access-token"
```

**Response:**

```json
{
  "sub": "42",
  "email": "alice@example.com",
  "name": "Alice"
}
```

Returns HTTP 401 if the token is invalid, expired, or belongs to a client_credentials grant (no user).

### GET /oauth/.well-known/openid-configuration

OIDC discovery document (RFC 8414). No authentication required.

```bash
curl https://auth.example.com/oauth/.well-known/openid-configuration
```

**Response:**

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "introspection_endpoint": "https://auth.example.com/oauth/introspect",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "userinfo_endpoint": "https://auth.example.com/oauth/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"],
  "subject_types_supported": ["public"]
}
```

## API Reference

All methods are accessed via `fortress.plugins.oauth`.

| Method | Description |
|---|---|
| `createClient(data)` | Register an OAuth client. Returns `{ clientId, clientSecret }`. |
| `createAuthorizationCode(params)` | Generate an auth code for a user+client. Returns `{ code }`. |
| `exchangeCode(params)` | Exchange an auth code for an access token. Returns `{ accessToken, tokenType, expiresIn, scope? }`. |
| `clientCredentialsGrant(params)` | Issue a token via client credentials. Returns `{ accessToken, tokenType, expiresIn }`. |
| `introspectToken(token)` | Check if a token is active. Returns `{ active, clientId?, userId?, scope? }`. |
| `revokeToken(token)` | Revoke an access token. |
| `createPendingFlow(params)` | Park an OAuth flow for unauthenticated users. Returns `{ flowId }`. |
| `resumePendingFlow(flowId)` | Resume and consume a pending flow. Returns `PendingFlowRecord`. |
| `getUserInfo(token)` | Get the user for a token. Returns `FortressUser \| null`. |
| `resolveTokenPermissions(token)` | Map a token's scopes to IAM permissions via `scopePermissionMap`. Returns `{ resource, action }[]`. |
| `handleTokenRequest(body, clientAuth?)` | HTTP handler for POST /oauth/token. |
| `handleIntrospectRequest(body, clientAuth)` | HTTP handler for POST /oauth/introspect. |
| `handleRevokeRequest(body)` | HTTP handler for POST /oauth/revoke. |
| `handleUserInfoRequest(bearerToken)` | HTTP handler for GET /oauth/userinfo. |
| `handleDiscovery()` | HTTP handler for GET /oauth/.well-known/openid-configuration. |

## Database Models

The plugin creates four tables automatically via the Fortress model system:

- `oauth_client` -- registered OAuth clients (clientId, secretHash, redirectUris, grantTypes)
- `oauth_authorization_code` -- authorization codes (hashed, single-use, expiry, PKCE fields)
- `oauth_access_token` -- issued access tokens (hashed, expiry, scope, optional userId)
- `oauth_pending_flow` -- parked authorization flows for the identity broker pattern

## Working Example

See `examples/hono-app/index.ts` for a complete Hono application that mounts the OAuth plugin alongside authentication, RBAC, two-factor, and audit logging.
