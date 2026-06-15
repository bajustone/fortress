# Social Login Plugin

## Overview

The `social-login` plugin is an OAuth/OIDC consumer that lets users sign in with external identity providers. It handles the full OAuth 2.0 authorization code flow with PKCE, profile normalization, JIT (just-in-time) user provisioning, and account linking.

Built-in providers: **Google**, **GitHub**, **Microsoft**, **Apple**, **Discord**.
Any OIDC-compliant provider can be added via the `issuer` option.

## Installation

```typescript
import { createFortress } from '@bajustone/fortress';
import { socialLogin } from '@bajustone/fortress/plugins/social-login';

const fortress = createFortress({
  database: adapter,
  jwt: { key: process.env.JWT_SECRET!, issuer: 'my-app' },
  plugins: [
    socialLogin({
      providers: [
        {
          name: 'google',
          clientId: process.env.GOOGLE_CLIENT_ID!,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        },
        {
          name: 'github',
          clientId: process.env.GITHUB_CLIENT_ID!,
          clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        },
      ],
    }),
  ],
});
```

The plugin registers a `social_account` table that links provider identities to Fortress users. Your database adapter must support this model (the Drizzle adapter handles it automatically).

## Configuration

`socialLogin(config)` accepts a `SocialLoginConfig` object:

| Option | Type | Default | Description |
|---|---|---|---|
| `providers` | `ProviderConfig[]` | (required) | List of configured providers. |
| `autoRegister` | `boolean` | `true` | Create a new Fortress user on first social login (JIT provisioning). |
| `linkAccounts` | `boolean` | `true` | When a social login email matches an existing user, link the social identity to that user instead of creating a duplicate. |
| `mapProfile` | `(provider, profile) => { email, name }` | `undefined` | Custom mapping from provider profile to Fortress user fields during JIT provisioning. |
| `onFirstLogin` | `(user, provider, profile) => Promise<void>` | `undefined` | Callback invoked once when a user is created via social login. Useful for assigning default roles, sending welcome emails, etc. |

### ProviderConfig

Each entry in `providers` has these fields:

| Option | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | Yes | Provider identifier. Use a built-in name (`google`, `github`, `microsoft`, `apple`, `discord`) or any string for custom OIDC. |
| `clientId` | `string` | Yes | OAuth client ID from the provider. |
| `clientSecret` | `string` | Yes | OAuth client secret from the provider. |
| `scopes` | `string[]` | No | Override the default scopes for this provider. |
| `tenant` | `string` | No | Microsoft only. Azure AD tenant: a tenant ID, `'common'`, or `'organizations'`. Defaults to `'common'`. |
| `allowedDomains` | `string[]` | No | Restrict sign-in to specific email domains (e.g., `['acme.com']`). |
| `issuer` | `string` | No | OIDC issuer URL for custom providers. Enables discovery of authorization, token, and userinfo endpoints. |

## Usage

### Setting Up Providers

**Built-in providers** require only `name`, `clientId`, and `clientSecret`:

```typescript
socialLogin({
  providers: [
    { name: 'google', clientId: '...', clientSecret: '...' },
    { name: 'github', clientId: '...', clientSecret: '...' },
    { name: 'apple', clientId: '...', clientSecret: '...' },
    { name: 'discord', clientId: '...', clientSecret: '...' },
  ],
})
```

**Custom OIDC providers** use the `issuer` field. Fortress constructs the standard OIDC endpoints from the issuer URL:

```typescript
socialLogin({
  providers: [
    {
      name: 'okta',
      clientId: '...',
      clientSecret: '...',
      issuer: 'https://dev-123456.okta.com',
    },
    {
      name: 'keycloak',
      clientId: '...',
      clientSecret: '...',
      issuer: 'https://auth.example.com/realms/my-realm',
    },
  ],
})
```

### Authorization URL Generation

Redirect the user to the provider's authorization page. The plugin generates a PKCE challenge and nonce automatically.

```typescript
const { url, state } = await fortress.plugins['social-login'].getAuthorizationUrl(
  'google',
  'https://myapp.com/auth/google/callback',
);

// Store `state` in the user's session (needed for callback verification)
session.set('oauth_state', state);

// Redirect the user
return redirect(url);
```

The returned `state` object contains:
- `provider` -- the provider name
- `codeVerifier` -- PKCE code verifier (required for the callback)
- `nonce` -- random value for CSRF protection

### Handling the Callback

When the provider redirects back to your app, exchange the authorization code for tokens and resolve the user:

```typescript
app.get('/auth/google/callback', async (c) => {
  const code = c.req.query('code');
  const savedState = session.get('oauth_state');

  const { user, profile, isNewUser } = await fortress.plugins['social-login'].handleCallback(
    savedState.provider,
    code,
    'https://myapp.com/auth/google/callback', // must match the redirect URI used above
    savedState.codeVerifier,
  );

  // Issue a Fortress session (JWT) for the user
  const tokens = await fortress.auth.login({ email: user.email });

  if (isNewUser) {
    // First-time social login -- maybe redirect to onboarding
  }

  return c.json({ accessToken: tokens.accessToken, user });
});
```

`handleCallback` returns:
- `user` -- the Fortress user (existing or newly created)
- `profile` -- normalized provider profile (`id`, `email`, `name`, `avatar`, `raw`)
- `isNewUser` -- `true` if the user was created during this call (JIT provisioning)

### JIT User Provisioning

When `autoRegister` is `true` (the default) and no existing Fortress user matches the social identity, the plugin creates a new user automatically. The new user has `passwordHash: null`, marking them as a social-only account.

To customize the user record created during provisioning, use `mapProfile`:

```typescript
socialLogin({
  autoRegister: true,
  mapProfile: (provider, profile) => ({
    email: profile.email,
    name: profile.displayName ?? profile.name ?? profile.email,
  }),
  providers: [/* ... */],
})
```

To run logic after user creation (assign roles, send a welcome email), use `onFirstLogin`:

```typescript
socialLogin({
  onFirstLogin: async (user, provider, profile) => {
    await fortress.iam.assignRole(user.id, 'member');
    await sendWelcomeEmail(profile.email, profile.name);
  },
  providers: [/* ... */],
})
```

Set `autoRegister: false` to require users to exist before they can sign in via social login. The plugin will throw an `unauthorized` error if no matching user is found.

### Account Linking

When `linkAccounts` is `true` (the default) and a social login email matches an existing Fortress user, the social identity is linked to that user rather than creating a duplicate.

This means a user who first registered with email/password and later signs in with Google (using the same email) will have their Google identity attached to their existing account.

### Domain Restrictions

Restrict sign-in to specific email domains per provider using `allowedDomains`. This is useful for corporate SSO where only company emails should be accepted:

```typescript
socialLogin({
  providers: [
    {
      name: 'google',
      clientId: '...',
      clientSecret: '...',
      allowedDomains: ['acme.com', 'acme.io'],
    },
  ],
})
```

If a user attempts to sign in with an email outside the allowed domains, `handleCallback` throws an `unauthorized` error with the message `"Email domain 'gmail.com' is not allowed for google"`.

### Managing Linked Accounts

List all social identities linked to a user:

```typescript
const accounts = await fortress.plugins['social-login'].getLinkedAccounts(userId);
// [
//   { provider: 'google', providerAccountId: '1234567890', email: 'alice@acme.com' },
//   { provider: 'github', providerAccountId: '987654', email: 'alice@acme.com' },
// ]
```

Unlink a social identity from a user:

```typescript
await fortress.plugins['social-login'].unlinkAccount(userId, 'github');
```

List all configured providers:

```typescript
const providers = fortress.plugins['social-login'].getProviders();
// ['google', 'github']
```

## Provider-Specific Notes

### Google

- Uses OpenID Connect. Default scopes: `openid`, `profile`, `email`.
- Create credentials at [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
- Profile fields: `sub` (id), `email`, `name`, `picture`.

### GitHub

- Uses custom OAuth 2.0 (not OIDC -- no discovery URL). Default scopes: `read:user`, `user:email`.
- Create an OAuth App at [GitHub Developer Settings](https://github.com/settings/developers).
- Profile fields: `id`, `email`, `name`/`login`, `avatar_url`.

### Microsoft

- Uses OpenID Connect via Azure AD. Default scopes: `openid`, `profile`, `email`, `User.Read`.
- The `tenant` option controls which Azure AD tenant is used:
  - `'common'` (default) -- any Microsoft account (personal + work/school).
  - `'organizations'` -- work/school accounts only.
  - A specific tenant ID -- restricts to a single Azure AD directory.

```typescript
{
  name: 'microsoft',
  clientId: '...',
  clientSecret: '...',
  tenant: 'your-azure-tenant-id',
}
```

- Register your app at [Azure Portal](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps).
- Profile is fetched from Microsoft Graph (`/v1.0/me`). Avatar requires a separate Graph API call and is not included.

### Apple

- Uses OpenID Connect, but profile data comes from the ID token only (no userinfo endpoint).
- Apple sends the user's name only on the **first** authorization. Subsequent logins provide only `sub` and `email`.
- Default scopes: `name`, `email`.
- Create a Service ID at [Apple Developer](https://developer.apple.com/account/resources/identifiers/list/serviceId).

### Discord

- Uses custom OAuth 2.0. Default scopes: `identify`, `email`.
- Create an application at [Discord Developer Portal](https://discord.com/developers/applications).
- Profile fields: `id`, `email`, `username`, `global_name`, `avatar`.

## API Reference

All methods are accessed via `fortress.plugins['social-login']`.

| Method | Signature | Description |
|---|---|---|
| `getAuthorizationUrl` | `(providerName: string, redirectUri: string) => Promise<{ url: string; state: { provider: string; codeVerifier: string; nonce: string } }>` | Generate the OAuth authorization URL. Store the returned `state` in the user's session. |
| `handleCallback` | `(providerName: string, code: string, redirectUri: string, codeVerifier: string) => Promise<{ user: FortressUser; profile: ProviderProfile; isNewUser: boolean }>` | Exchange the authorization code, fetch the profile, and resolve or create the Fortress user. |
| `getLinkedAccounts` | `(userId: string) => Promise<{ provider: string; providerAccountId: string; email: string \| null }[]>` | List social identities linked to a user. |
| `unlinkAccount` | `(userId: string, provider: string) => Promise<void>` | Remove a social identity from a user. |
| `getProviders` | `() => string[]` | List the names of all configured providers. |

### ProviderProfile

The normalized profile returned by `handleCallback`:

```typescript
interface ProviderProfile {
  id: string;             // Provider's unique user ID
  email: string;
  name?: string;
  displayName?: string;
  avatar?: string;
  raw: Record<string, unknown>; // Full raw response from the provider
}
```
