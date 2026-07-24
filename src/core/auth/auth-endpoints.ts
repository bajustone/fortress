import type { EndpointDefinition } from '../endpoint';
import type { FortressSchema } from '../json-schema';
import type { AuthMethod, PendingReason } from '../types';
import { defineEndpoints } from '../define-endpoints';
import { arr, bool, defineComponents, email, endpoint, enums, id, int, nullable, nullType, obj, oneOf, record, str, strFormat } from '../schema-builder';

// Sentinel for "no body / query / params" that matches EndpointDefinition's
// defaults so the intersection-based InferEndpointCallInput collapses cleanly.

interface EmptyInput {}

// ── Wire-format shapes (what endpoint handlers serialize to JSON) ──────
//
// These mirror the domain types in `src/core/types.ts` but use `string`
// everywhere the domain uses `Date` (ISO 8601 on the wire). Declared here
// explicitly so JSR's fast-check doesn't walk through the deeply-inferred
// types produced by `obj(...)` / `oneOf(...)`.

/** Wire shape of a fortress user — domain `Date` fields are ISO strings on the wire. */
export interface UserWire {
  id: string;
  email: string;
  name: string;
  isActive: boolean;
  emailVerified?: boolean;
  createdAt: string;
  updatedAt: string;
}

/** Wire shape of a pending post-auth challenge. */
export interface AuthChallengeWire {
  reason: PendingReason;
  continuationToken: string;
}

/** Wire shape of a successful sign-in. */
export interface AuthSuccessWire {
  status: 'success';
  user: UserWire;
  method: AuthMethod;
  accessToken: string;
  refreshToken: string;
  pluginData?: Record<string, unknown>;
}

/** Wire shape of a pending sign-in (2FA, email verification, etc.). */
export interface AuthPendingWire {
  status: 'pending';
  user: UserWire;
  pending: AuthChallengeWire;
  pluginData?: Record<string, unknown>;
}

/** Wire shape of an impersonation sign-in (no refresh token). */
export interface AuthImpersonationWire {
  status: 'impersonation';
  user: UserWire;
  accessToken: string;
  refreshToken: null;
  pluginData?: Record<string, unknown>;
}

/** Discriminated union of every auth-flow wire outcome. */
export type AuthResultWire
  = | AuthSuccessWire
    | AuthPendingWire
    | AuthImpersonationWire;

/** Wire shape of a refreshed access/refresh token pair. */
export interface AuthTokenPairWire {
  accessToken: string;
  refreshToken: string;
}

/** Wire shape of a persisted refresh-token session. */
export interface SessionInfoWire {
  id: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  deviceName?: string | null;
  createdAt: string;
  lastActiveAt?: string | null;
}

/** Wire shape of the create-user input body. */
export interface CreateUserInputWire {
  email: string;
  name: string;
  password?: string;
  isActive?: boolean;
}

/** Wire shape of a structured error response. */
export interface ErrorResponseWire {
  code: string;
  message: string;
  statusCode: number;
}

/** Wire shape of a login identifier. */
export interface LoginIdentifierWire {
  id: string;
  userId: string;
  type: 'email' | 'phone' | 'username';
  value: string;
}

/** Empty `{ ok: boolean }` ack. */
export interface OkResponseWire {
  ok: boolean;
}

// ── Component schemas (typed registry) ──────────────────────────────────

const User: FortressSchema<UserWire> = obj(
  {
    id: id('User ID'),
    email: strFormat('email', 'User email'),
    name: str('Display name'),
    isActive: bool('Account active status'),
    emailVerified: bool('Email verification status'),
    createdAt: strFormat('date-time', 'Creation timestamp'),
    updatedAt: strFormat('date-time', 'Last update timestamp'),
  },
  'id',
  'email',
  'name',
  'isActive',
  'createdAt',
  'updatedAt',
) as FortressSchema<UserWire>;

const AuthChallenge: FortressSchema<AuthChallengeWire> = obj(
  {
    reason: enums('two-factor', 'webauthn', 'email-verification', 'magic-link'),
    continuationToken: str('Single-use post-auth continuation token'),
  },
  'reason',
  'continuationToken',
) as FortressSchema<AuthChallengeWire>;

const AuthResult: FortressSchema<AuthResultWire> = oneOf(
  obj(
    {
      status: enums('success'),
      user: User,
      method: enums('password', 'refresh', 'two-factor', 'webauthn', 'magic-link', 'impersonation'),
      accessToken: str('JWT access token'),
      refreshToken: str('Refresh token for rotation'),
      pluginData: record(),
    },
    'status',
    'user',
    'method',
    'accessToken',
    'refreshToken',
  ),
  obj(
    {
      status: enums('pending'),
      user: User,
      pending: AuthChallenge,
      pluginData: record(),
    },
    'status',
    'user',
    'pending',
  ),
  obj(
    {
      status: enums('impersonation'),
      user: User,
      accessToken: str('JWT access token'),
      refreshToken: nullType(),
      pluginData: record(),
    },
    'status',
    'user',
    'accessToken',
    'refreshToken',
  ),
) as FortressSchema<AuthResultWire>;

const AuthTokenPair: FortressSchema<AuthTokenPairWire> = obj(
  {
    accessToken: str('JWT access token'),
    refreshToken: str('New refresh token'),
  },
  'accessToken',
  'refreshToken',
) as FortressSchema<AuthTokenPairWire>;

const SessionInfo: FortressSchema<SessionInfoWire> = obj(
  {
    id: id('Token ID'),
    ipAddress: nullable(str('Client IP address')),
    userAgent: nullable(str('Client user agent')),
    deviceName: nullable(str('Device name')),
    createdAt: strFormat('date-time', 'Session creation time'),
    lastActiveAt: nullable(strFormat('date-time', 'Last activity time')),
  },
  'id',
  'createdAt',
) as FortressSchema<SessionInfoWire>;

const CreateUserInput: FortressSchema<CreateUserInputWire> = obj(
  {
    email: email('User email'), // enforced format (ReDoS-safe pattern), not annotation-only
    name: str('Display name'),
    password: str('User password'),
    isActive: bool('Set active status (default true)'),
  },
  'email',
  'name',
) as FortressSchema<CreateUserInputWire>;

const ErrorResponse: FortressSchema<ErrorResponseWire> = obj(
  {
    code: str('Error code (e.g. UNAUTHORIZED)'),
    message: str('Human-readable message'),
    statusCode: int('HTTP status code'),
  },
  'code',
  'message',
  'statusCode',
) as FortressSchema<ErrorResponseWire>;

const LoginIdentifier: FortressSchema<LoginIdentifierWire> = obj(
  {
    id: id('Identifier ID'),
    userId: id('User ID'),
    type: enums('email', 'phone', 'username'),
    value: str('Identifier value'),
  },
  'id',
  'userId',
  'type',
  'value',
) as FortressSchema<LoginIdentifierWire>;

/** Explicit registry type so JSR's fast-check doesn't walk into the deeply-inferred `defineComponents` return. */
interface AuthComponents {
  readonly components: {
    readonly User: FortressSchema<UserWire>;
    readonly AuthChallenge: FortressSchema<AuthChallengeWire>;
    readonly AuthResult: FortressSchema<AuthResultWire>;
    readonly AuthTokenPair: FortressSchema<AuthTokenPairWire>;
    readonly SessionInfo: FortressSchema<SessionInfoWire>;
    readonly CreateUserInput: FortressSchema<CreateUserInputWire>;
    readonly ErrorResponse: FortressSchema<ErrorResponseWire>;
    readonly LoginIdentifier: FortressSchema<LoginIdentifierWire>;
  };
  readonly ref: <K extends keyof AuthComponents['components']>(
    name: K,
  ) => FortressSchema<AuthComponents['components'][K] extends FortressSchema<infer U> ? U : never>;
}

const authComponents: AuthComponents = defineComponents({
  User,
  AuthChallenge,
  AuthResult,
  AuthTokenPair,
  SessionInfo,
  CreateUserInput,
  ErrorResponse,
  LoginIdentifier,
}) as AuthComponents;

/** Reusable OpenAPI component schemas referenced by the core auth endpoints. */
export const authComponentSchemas: AuthComponents['components'] = authComponents.components;

/** Typed `$ref` helper bound to {@link authComponentSchemas}. */
export const authRef: AuthComponents['ref'] = authComponents.ref;

// ── Auth endpoint definitions (keyed by handler name) ───────────────────

/**
 * Typed record of every core auth endpoint. Declared explicitly (not
 * inferred from the builder) so JSR's fast-check passes without
 * `--allow-slow-types`, while `InferEndpointCallInput<typeof authEndpoints.login>`
 * and friends still resolve to the precise per-endpoint shapes.
 */
export interface AuthEndpointsMap {
  login: EndpointDefinition<
    { identifier: string; password: string; trustedDeviceToken?: string },
    EmptyInput,
    EmptyInput,
    { 200: AuthResultWire; 401: ErrorResponseWire }
  >;
  verifyTwoFactor: EndpointDefinition<
    { continuationToken: string; code: string; rememberDevice?: boolean },
    EmptyInput,
    EmptyInput,
    { 200: AuthResultWire; 400: ErrorResponseWire; 401: ErrorResponseWire }
  >;
  verifyMagicLink: EndpointDefinition<
    { token: string },
    EmptyInput,
    EmptyInput,
    { 200: AuthResultWire; 400: ErrorResponseWire; 404: ErrorResponseWire }
  >;
  createUser: EndpointDefinition<
    CreateUserInputWire,
    EmptyInput,
    EmptyInput,
    { 201: UserWire; 409: ErrorResponseWire }
  >;
  refresh: EndpointDefinition<
    { refreshToken: string },
    EmptyInput,
    EmptyInput,
    { 200: AuthTokenPairWire; 401: ErrorResponseWire }
  >;
  logout: EndpointDefinition<
    { refreshToken: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire }
  >;
  me: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    EmptyInput,
    { 200: UserWire; 401: ErrorResponseWire }
  >;
  listSessions: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    EmptyInput,
    { 200: SessionInfoWire[]; 401: ErrorResponseWire }
  >;
  revokeSession: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  revokeAllOtherSessions: EndpointDefinition<
    { currentTokenId: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  addLoginIdentifier: EndpointDefinition<
    { type: 'email' | 'phone' | 'username'; value: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  removeLoginIdentifier: EndpointDefinition<
    { type: 'email' | 'phone' | 'username'; value: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  getLoginIdentifiers: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    EmptyInput,
    { 200: LoginIdentifierWire[]; 401: ErrorResponseWire }
  >;
  impersonate: EndpointDefinition<
    { targetUserId: string; reason?: string; expirySeconds?: number },
    EmptyInput,
    EmptyInput,
    { 200: AuthResultWire; 401: ErrorResponseWire; 404: ErrorResponseWire }
  >;
}

/**
 * Declarative endpoint definitions for fortress's built-in auth routes
 * (sign in, refresh, sessions, impersonation).
 *
 * The explicit `AuthEndpointsMap` annotation is what keeps JSR fast-check
 * happy — each entry's `EndpointDefinition<TBody, TQuery, TParams, TResponses>`
 * generics are stated declaratively, not inferred from the builder chain.
 * `fortress.call.*` type inference still resolves because `typeof
 * authEndpoints.login` picks up the exact generics declared on the map.
 */
export const authEndpoints: AuthEndpointsMap = defineEndpoints({
  login: endpoint('POST', '/auth/login')
    .summary('Login with credentials')
    .tags('Auth')
    .security('none')
    .body(obj(
      {
        identifier: str('Email, username, or phone'),
        password: str('User password'),
        trustedDeviceToken: str('Opaque trusted-device token previously returned after two-factor verification'),
      },
      'identifier',
      'password',
    ))
    .response(200, 'Login successful', authRef('AuthResult'))
    .response(401, 'Invalid credentials', authRef('ErrorResponse'))
    .handler('login')
    .build() as AuthEndpointsMap['login'],

  verifyTwoFactor: endpoint('POST', '/auth/2fa/verify')
    .summary('Complete a pending two-factor challenge')
    .tags('Auth', 'Two-Factor')
    .security('none')
    .body(obj(
      {
        continuationToken: str('Single-use auth continuation token'),
        code: str('TOTP or backup code'),
        rememberDevice: bool('Issue an opaque trusted-device token after successful verification'),
      },
      'continuationToken',
      'code',
    ))
    .response(200, 'Authentication result', authRef('AuthResult'))
    .response(400, 'Two-factor plugin unavailable', authRef('ErrorResponse'))
    .response(401, 'Invalid continuation or verification code', authRef('ErrorResponse'))
    .handler('verifyTwoFactor')
    .build() as AuthEndpointsMap['verifyTwoFactor'],

  verifyMagicLink: endpoint('POST', '/auth/magic-link/verify')
    .summary('Verify a magic-link token')
    .tags('Auth', 'Magic Link')
    .security('none')
    .body(obj({ token: str('Raw magic-link token') }, 'token'))
    .response(200, 'Authentication result', authRef('AuthResult'))
    .response(400, 'Magic-link plugin unavailable', authRef('ErrorResponse'))
    .response(404, 'Invalid or expired magic link', authRef('ErrorResponse'))
    .handler('verifyMagicLink')
    .build() as AuthEndpointsMap['verifyMagicLink'],

  createUser: endpoint('POST', '/auth/register')
    .summary('Create a new user')
    .tags('Auth')
    .security('none')
    .body(CreateUserInput)
    .response(201, 'User created', authRef('User'))
    .response(409, 'Email already exists', authRef('ErrorResponse'))
    .handler('createUser')
    .build() as AuthEndpointsMap['createUser'],

  refresh: endpoint('POST', '/auth/refresh')
    .summary('Refresh access token')
    .tags('Auth')
    .security('none')
    .body(obj({ refreshToken: str('Current refresh token') }, 'refreshToken'))
    .response(200, 'Tokens refreshed', authRef('AuthTokenPair'))
    .response(401, 'Invalid or expired refresh token', authRef('ErrorResponse'))
    .handler('refresh')
    .build() as AuthEndpointsMap['refresh'],

  logout: endpoint('POST', '/auth/logout')
    .summary('Logout and revoke refresh token')
    .tags('Auth')
    .security('none')
    .body(obj({ refreshToken: str('Refresh token to revoke') }, 'refreshToken'))
    .response(200, 'Logged out', obj({ ok: bool() }, 'ok'))
    .handler('logout')
    .build() as AuthEndpointsMap['logout'],

  me: endpoint('GET', '/auth/me')
    .summary('Get current user profile')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Current user', authRef('User'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('me')
    .build() as AuthEndpointsMap['me'],

  listSessions: endpoint('GET', '/auth/sessions')
    .summary('List active sessions')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Active sessions', arr(authRef('SessionInfo')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('listSessions')
    .build() as AuthEndpointsMap['listSessions'],

  revokeSession: endpoint('DELETE', '/auth/sessions/:id')
    .summary('Revoke a specific session')
    .tags('Auth')
    .security('bearer')
    .params(obj({ id: id('Session/token ID') }, 'id'))
    .response(200, 'Session revoked', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('revokeSession')
    .build() as AuthEndpointsMap['revokeSession'],

  revokeAllOtherSessions: endpoint('DELETE', '/auth/sessions')
    .summary('Revoke all other sessions')
    .description('Revokes all active sessions except the current one. Requires the current token ID.')
    .tags('Auth')
    .security('bearer')
    .body(obj({ currentTokenId: id('Current token ID to keep') }, 'currentTokenId'))
    .response(200, 'Other sessions revoked', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('revokeAllOtherSessions')
    .build() as AuthEndpointsMap['revokeAllOtherSessions'],

  addLoginIdentifier: endpoint('POST', '/auth/identifiers')
    .summary('Add a login identifier')
    .tags('Auth')
    .security('bearer')
    .body(obj(
      {
        type: enums('email', 'phone', 'username'),
        value: str('Identifier value'),
      },
      'type',
      'value',
    ))
    .response(200, 'Identifier added', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('addLoginIdentifier')
    .build() as AuthEndpointsMap['addLoginIdentifier'],

  removeLoginIdentifier: endpoint('DELETE', '/auth/identifiers')
    .summary('Remove a login identifier')
    .tags('Auth')
    .security('bearer')
    .body(obj(
      {
        type: enums('email', 'phone', 'username'),
        value: str('Identifier value'),
      },
      'type',
      'value',
    ))
    .response(200, 'Identifier removed', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('removeLoginIdentifier')
    .build() as AuthEndpointsMap['removeLoginIdentifier'],

  getLoginIdentifiers: endpoint('GET', '/auth/identifiers')
    .summary('List login identifiers')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Login identifiers', arr(authRef('LoginIdentifier')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getLoginIdentifiers')
    .build() as AuthEndpointsMap['getLoginIdentifiers'],

  impersonate: endpoint('POST', '/auth/impersonate')
    .summary('Impersonate a user')
    .description('Issue a short-lived, non-renewable token to act as another user. Requires fortress:impersonate permission.')
    .tags('Auth')
    .security('bearer')
    .permission('fortress', 'impersonate')
    .body(obj(
      {
        targetUserId: id('User to impersonate'),
        reason: str('Reason for impersonation'),
        expirySeconds: int('Token expiry in seconds (default 3600)'),
      },
      'targetUserId',
    ))
    .response(200, 'Impersonation token issued', authRef('AuthResult'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .response(404, 'Target user not found', authRef('ErrorResponse'))
    .handler('impersonate')
    .build() as AuthEndpointsMap['impersonate'],
});
