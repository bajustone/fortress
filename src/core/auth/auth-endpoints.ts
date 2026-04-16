import { arr, bool, defineComponents, endpoint, enums, int, nullable, nullType, obj, oneOf, record, str, strFormat } from '../schema-builder';

// ── Component schemas (typed registry) ──────────────────────────────
//
// Each component is declared as a local `const` so TypeScript can infer its
// type. Self-references inside composite components (e.g. `user` inside
// `AuthResponse`) use the 2-arg `ref(name, schema)` overload — the name is
// what ends up in the OpenAPI `$ref`, the schema argument only carries the
// TS type and is never read at runtime.

const User = obj(
  {
    id: int('User ID'),
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
);

const AuthResponse = oneOf(
  obj(
    {
      status: enums('success'),
      user: User,
      accessToken: str('JWT access token'),
      refreshToken: str('Refresh token for rotation'),
      pluginData: record(),
    },
    'status',
    'user',
    'accessToken',
    'refreshToken',
  ),
  obj(
    {
      status: enums('pending'),
      user: User,
      accessToken: nullType(),
      refreshToken: nullType(),
      pluginData: record(),
    },
    'status',
    'user',
    'accessToken',
    'refreshToken',
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
);

const AuthTokenPair = obj(
  {
    accessToken: str('JWT access token'),
    refreshToken: str('New refresh token'),
  },
  'accessToken',
  'refreshToken',
);

const SessionInfo = obj(
  {
    id: int('Token ID'),
    ipAddress: nullable(str('Client IP address')),
    userAgent: nullable(str('Client user agent')),
    deviceName: nullable(str('Device name')),
    createdAt: strFormat('date-time', 'Session creation time'),
    lastActiveAt: nullable(strFormat('date-time', 'Last activity time')),
  },
  'id',
  'createdAt',
);

const CreateUserInput = obj(
  {
    email: strFormat('email', 'User email'),
    name: str('Display name'),
    password: str('User password'),
    isActive: bool('Set active status (default true)'),
  },
  'email',
  'name',
);

const ErrorResponse = obj(
  {
    code: str('Error code (e.g. UNAUTHORIZED)'),
    message: str('Human-readable message'),
    statusCode: int('HTTP status code'),
  },
  'code',
  'message',
  'statusCode',
);

const LoginIdentifier = obj(
  {
    id: int('Identifier ID'),
    userId: int('User ID'),
    type: enums('email', 'phone', 'username'),
    value: str('Identifier value'),
  },
  'id',
  'userId',
  'type',
  'value',
);

const authComponents = defineComponents({
  User,
  AuthResponse,
  AuthTokenPair,
  SessionInfo,
  CreateUserInput,
  ErrorResponse,
  LoginIdentifier,
});

/** Reusable OpenAPI component schemas referenced by the core auth endpoints. */
export const authComponentSchemas = authComponents.components;

/** Typed `$ref` helper bound to {@link authComponentSchemas}. */
export const authRef = authComponents.ref;

// ── Auth endpoint definitions (keyed by handler name) ───────────────

/**
 * Declarative endpoint definitions for fortress's built-in auth routes
 * (sign in, refresh, sessions, impersonation).
 *
 * Declared as a keyed record (not an array) so each entry's full
 * `EndpointDefinition<TBody, TQuery, TParams, TResponses>` type is
 * preserved for `fortress.call.*` inference. The runtime array used by
 * route matching is materialized via `Object.values(authEndpoints)`.
 */
export const authEndpoints = {
  login: endpoint('POST', '/auth/login')
    .summary('Login with credentials')
    .tags('Auth')
    .security('none')
    .body(obj(
      { identifier: str('Email, username, or phone'), password: str('User password') },
      'identifier',
      'password',
    ))
    .response(200, 'Login successful', authRef('AuthResponse'))
    .response(401, 'Invalid credentials', authRef('ErrorResponse'))
    .handler('login')
    .build(),

  createUser: endpoint('POST', '/auth/register')
    .summary('Create a new user')
    .tags('Auth')
    .security('none')
    .body(CreateUserInput)
    .response(201, 'User created', authRef('User'))
    .response(409, 'Email already exists', authRef('ErrorResponse'))
    .handler('createUser')
    .build(),

  refresh: endpoint('POST', '/auth/refresh')
    .summary('Refresh access token')
    .tags('Auth')
    .security('none')
    .body(obj({ refreshToken: str('Current refresh token') }, 'refreshToken'))
    .response(200, 'Tokens refreshed', authRef('AuthTokenPair'))
    .response(401, 'Invalid or expired refresh token', authRef('ErrorResponse'))
    .handler('refresh')
    .build(),

  logout: endpoint('POST', '/auth/logout')
    .summary('Logout and revoke refresh token')
    .tags('Auth')
    .security('none')
    .body(obj({ refreshToken: str('Refresh token to revoke') }, 'refreshToken'))
    .response(200, 'Logged out', obj({ ok: bool() }, 'ok'))
    .handler('logout')
    .build(),

  me: endpoint('GET', '/auth/me')
    .summary('Get current user profile')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Current user', authRef('User'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('me')
    .build(),

  listSessions: endpoint('GET', '/auth/sessions')
    .summary('List active sessions')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Active sessions', arr(authRef('SessionInfo')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('listSessions')
    .build(),

  revokeSession: endpoint('DELETE', '/auth/sessions/:id')
    .summary('Revoke a specific session')
    .tags('Auth')
    .security('bearer')
    .params(obj({ id: int('Session/token ID') }, 'id'))
    .response(200, 'Session revoked', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('revokeSession')
    .build(),

  revokeAllOtherSessions: endpoint('DELETE', '/auth/sessions')
    .summary('Revoke all other sessions')
    .description('Revokes all active sessions except the current one. Requires the current token ID.')
    .tags('Auth')
    .security('bearer')
    .body(obj({ currentTokenId: int('Current token ID to keep') }, 'currentTokenId'))
    .response(200, 'Other sessions revoked', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('revokeAllOtherSessions')
    .build(),

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
    .build(),

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
    .build(),

  getLoginIdentifiers: endpoint('GET', '/auth/identifiers')
    .summary('List login identifiers')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Login identifiers', arr(authRef('LoginIdentifier')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getLoginIdentifiers')
    .build(),

  impersonate: endpoint('POST', '/auth/impersonate')
    .summary('Impersonate a user')
    .description('Issue a short-lived, non-renewable token to act as another user. Requires fortress:impersonate permission.')
    .tags('Auth')
    .security('bearer')
    .body(obj(
      {
        targetUserId: int('User to impersonate'),
        reason: str('Reason for impersonation'),
        expirySeconds: int('Token expiry in seconds (default 3600)'),
      },
      'targetUserId',
    ))
    .response(200, 'Impersonation token issued', authRef('AuthResponse'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .response(404, 'Target user not found', authRef('ErrorResponse'))
    .handler('impersonate')
    .build(),
} as const;
