# WebAuthn Plugin

## Overview

The `webauthn` plugin adds passkey and WebAuthn support to Fortress, enabling passwordless authentication using platform authenticators (Touch ID, Face ID, Windows Hello) and security keys. It is built on [@simplewebauthn/server](https://simplewebauthn.dev/).

The plugin supports both registration (adding a passkey to an existing account) and authentication (signing in with a passkey). In passwordless mode, successful authentication returns JWT tokens directly.

## Installation

Import the `webauthn` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { webauthn } from '@bajustone/fortress/plugins/webauthn';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    webauthn({
      rpName: 'My App',
      rpID: 'example.com',
      origin: 'https://example.com',
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['webauthn']` with full type safety.

## Configuration

| Option | Type | Default | Required | Description |
|---|---|---|---|---|
| `rpName` | `string` | -- | Yes | Human-readable relying party name shown to users (e.g., "My App"). |
| `rpID` | `string` | -- | Yes | Relying party identifier, typically the domain (e.g., "example.com"). |
| `origin` | `string \| string[]` | -- | Yes | Expected origin(s) for credentials (e.g., "https://example.com"). |
| `attestation` | `'none' \| 'indirect' \| 'direct' \| 'enterprise'` | `'none'` | No | Attestation preference. |
| `authenticatorSelection.authenticatorAttachment` | `'platform' \| 'cross-platform'` | -- | No | Restrict to platform or roaming authenticators. |
| `authenticatorSelection.residentKey` | `'discouraged' \| 'preferred' \| 'required'` | `'preferred'` | No | Resident key (discoverable credential) preference. |
| `authenticatorSelection.userVerification` | `'discouraged' \| 'preferred' \| 'required'` | `'preferred'` | No | User verification preference. |
| `timeout` | `number` | `60000` (60s) | No | Timeout for WebAuthn ceremonies in milliseconds. |
| `challengeTTLSeconds` | `number` | `300` (5 min) | No | How long a challenge remains valid, in seconds. |
| `supportPasswordless` | `boolean` | `true` | No | When `true`, `verifyAuthentication` returns JWT tokens for direct passwordless login. When `false`, the plugin hooks into `afterLogin` to require WebAuthn as a second factor. |

## HTTP Routes

The plugin defines four routes that are auto-mounted via `mountPluginRoutes`:

| Method | Path | Auth Required | Description |
|---|---|---|---|
| POST | `/webauthn/register/options` | Yes (bearer) | Generate registration options for a new passkey. |
| POST | `/webauthn/register/verify` | Yes (bearer) | Verify the registration response and store the credential. |
| POST | `/webauthn/authenticate/options` | No | Generate authentication options. Optionally pass `userId` for non-discoverable flow. |
| POST | `/webauthn/authenticate/verify` | No | Verify the authentication assertion and return tokens (if passwordless). |

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `generateRegistrationOptions` | `(input: { userId: number })` | `Promise<{ options: PublicKeyCredentialCreationOptionsJSON }>` |
| `verifyRegistration` | `(input: { userId: number; response: RegistrationResponseJSON })` | `Promise<{ verified, credentialId, credentialDeviceType, credentialBackedUp }>` |
| `generateAuthenticationOptions` | `(input: { userId?: number })` | `Promise<{ options: PublicKeyCredentialRequestOptionsJSON }>` |
| `verifyAuthentication` | `(input: { response: AuthenticationResponseJSON })` | `Promise<{ verified, userId, accessToken?, refreshToken? }>` |

### generateRegistrationOptions

Generates options for `navigator.credentials.create()`. Existing credentials for the user are included in `excludeCredentials` to prevent duplicate registration:

```ts
const { options } = await fortress.plugins['webauthn'].generateRegistrationOptions({ userId });
// Pass options to the browser: navigator.credentials.create({ publicKey: options })
```

Throws `NotFound` if the user does not exist.

### verifyRegistration

Verifies the authenticator's response and stores the new credential:

```ts
const result = await fortress.plugins['webauthn'].verifyRegistration({
  userId,
  response: registrationResponseFromBrowser,
});
// result.verified, result.credentialId, result.credentialDeviceType, result.credentialBackedUp
```

Throws:
- `BadRequest` -- No pending challenge, challenge expired, or verification failed.

### generateAuthenticationOptions

Generates options for `navigator.credentials.get()`. Pass `userId` to restrict to that user's credentials, or omit for discoverable credential (passkey) flow:

```ts
// Discoverable flow (user selects passkey)
const { options } = await fortress.plugins['webauthn'].generateAuthenticationOptions({});

// User-specific flow
const { options } = await fortress.plugins['webauthn'].generateAuthenticationOptions({ userId });
```

### verifyAuthentication

Verifies the authentication assertion. In passwordless mode, returns a JWT access token:

```ts
const result = await fortress.plugins['webauthn'].verifyAuthentication({
  response: authenticationResponseFromBrowser,
});
// result.verified, result.userId, result.accessToken (if supportPasswordless)
```

The method also validates the authenticator counter to detect credential cloning (skipped for synced passkeys where both counters are 0).

Throws:
- `Unauthorized` -- Unknown credential or verification failed.
- `BadRequest` -- No pending challenge or challenge expired.

## Example

```ts
import { createFortress } from '@bajustone/fortress';
import { webauthn } from '@bajustone/fortress/plugins/webauthn';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    webauthn({
      rpName: 'My App',
      rpID: 'myapp.com',
      origin: 'https://myapp.com',
      supportPasswordless: true,
    }),
  ],
});

// --- Registration (browser + server) ---

// Server: generate options
const { options } = await fortress.plugins['webauthn'].generateRegistrationOptions({ userId });

// Browser: create credential
// const credential = await navigator.credentials.create({ publicKey: options });

// Server: verify and store
const result = await fortress.plugins['webauthn'].verifyRegistration({
  userId,
  response: credentialResponseFromBrowser,
});

// --- Authentication (browser + server) ---

// Server: generate options
const { options: authOptions } = await fortress.plugins['webauthn'].generateAuthenticationOptions({});

// Browser: get assertion
// const assertion = await navigator.credentials.get({ publicKey: authOptions });

// Server: verify and get tokens
const authResult = await fortress.plugins['webauthn'].verifyAuthentication({
  response: assertionFromBrowser,
});
// authResult.accessToken -- use this to authenticate the user
```
