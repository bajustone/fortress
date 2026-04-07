import type { ComponentSchemas, EndpointDefinition } from '../endpoint';
import { arr, bool, endpoint, enums, int, nullable, nullType, obj, oneOf, record, ref, str, strFormat } from '../schema-builder';

// ── Component Schemas (reusable via $ref) ───────────────────────────

export const authComponentSchemas: ComponentSchemas = {
  User: obj(
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
  ),

  AuthResponse: oneOf(
    obj(
      {
        status: enums('success'),
        user: ref('User'),
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
        user: ref('User'),
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
        user: ref('User'),
        accessToken: str('JWT access token'),
        refreshToken: nullType(),
        pluginData: record(),
      },
      'status',
      'user',
      'accessToken',
      'refreshToken',
    ),
  ),

  AuthTokenPair: obj(
    {
      accessToken: str('JWT access token'),
      refreshToken: str('New refresh token'),
    },
    'accessToken',
    'refreshToken',
  ),

  SessionInfo: obj(
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
  ),

  CreateUserInput: obj(
    {
      email: strFormat('email', 'User email'),
      name: str('Display name'),
      password: str('User password'),
      isActive: bool('Set active status (default true)'),
    },
    'email',
    'name',
  ),

  ErrorResponse: obj(
    {
      code: str('Error code (e.g. UNAUTHORIZED)'),
      message: str('Human-readable message'),
      statusCode: int('HTTP status code'),
    },
    'code',
    'message',
    'statusCode',
  ),

  LoginIdentifier: obj(
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
  ),
};

// ── Auth Endpoint Definitions ───────────────────────────────────────

export const authEndpoints: EndpointDefinition[] = [
  endpoint('POST', '/auth/login')
    .summary('Login with credentials')
    .tags('Auth')
    .security('none')
    .body(obj(
      { identifier: str('Email, username, or phone'), password: str('User password') },
      'identifier',
      'password',
    ))
    .response(200, 'Login successful', ref('AuthResponse'))
    .response(401, 'Invalid credentials', ref('ErrorResponse'))
    .handler('login')
    .build(),

  endpoint('POST', '/auth/register')
    .summary('Create a new user')
    .tags('Auth')
    .security('none')
    .body(ref('CreateUserInput'))
    .response(201, 'User created', ref('User'))
    .response(409, 'Email already exists', ref('ErrorResponse'))
    .handler('createUser')
    .build(),

  endpoint('POST', '/auth/refresh')
    .summary('Refresh access token')
    .tags('Auth')
    .security('none')
    .body(obj({ refreshToken: str('Current refresh token') }, 'refreshToken'))
    .response(200, 'Tokens refreshed', ref('AuthTokenPair'))
    .response(401, 'Invalid or expired refresh token', ref('ErrorResponse'))
    .handler('refresh')
    .build(),

  endpoint('POST', '/auth/logout')
    .summary('Logout and revoke refresh token')
    .tags('Auth')
    .security('none')
    .body(obj({ refreshToken: str('Refresh token to revoke') }, 'refreshToken'))
    .response(200, 'Logged out', obj({ ok: bool() }))
    .handler('logout')
    .build(),

  endpoint('GET', '/auth/me')
    .summary('Get current user profile')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Current user', ref('User'))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('me')
    .build(),

  endpoint('GET', '/auth/sessions')
    .summary('List active sessions')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Active sessions', arr(ref('SessionInfo')))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('listSessions')
    .build(),

  endpoint('DELETE', '/auth/sessions/:id')
    .summary('Revoke a specific session')
    .tags('Auth')
    .security('bearer')
    .params(obj({ id: int('Session/token ID') }, 'id'))
    .response(200, 'Session revoked', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('revokeSession')
    .build(),

  endpoint('DELETE', '/auth/sessions')
    .summary('Revoke all other sessions')
    .description('Revokes all active sessions except the current one. Requires the current token ID.')
    .tags('Auth')
    .security('bearer')
    .body(obj({ currentTokenId: int('Current token ID to keep') }, 'currentTokenId'))
    .response(200, 'Other sessions revoked', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('revokeAllOtherSessions')
    .build(),

  endpoint('POST', '/auth/identifiers')
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
    .response(200, 'Identifier added', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('addLoginIdentifier')
    .build(),

  endpoint('DELETE', '/auth/identifiers')
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
    .response(200, 'Identifier removed', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('removeLoginIdentifier')
    .build(),

  endpoint('GET', '/auth/identifiers')
    .summary('List login identifiers')
    .tags('Auth')
    .security('bearer')
    .response(200, 'Login identifiers', arr(ref('LoginIdentifier')))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('getLoginIdentifiers')
    .build(),

  endpoint('POST', '/auth/impersonate')
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
    .response(200, 'Impersonation token issued', ref('AuthResponse'))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .response(404, 'Target user not found', ref('ErrorResponse'))
    .handler('impersonate')
    .build(),
];
