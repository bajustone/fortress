/** Discriminated string union of every error code fortress can throw. Maps 1:1 to an HTTP status. */
export type FortressErrorCode
  = | 'UNAUTHORIZED'
    | 'TOKEN_REUSE'
    | 'SESSION_IDLE_TIMEOUT'
    | 'SESSION_ABSOLUTE_TIMEOUT'
    | 'FORBIDDEN'
    | 'BAD_REQUEST'
    | 'NOT_FOUND'
    | 'CONFLICT'
    | 'UNPROCESSABLE_ENTITY'
    | 'RATE_LIMITED'
    | 'DATABASE_ERROR'
    | 'VALIDATION_ERROR'
    | 'SERVICE_UNAVAILABLE';

/**
 * Machine-readable error codes defined by RFC 6749 §5.2 (token endpoint) and
 * §4.1.2.1 (authorization endpoint). The OAuth plugin uses these as the
 * `error` field in token-endpoint failure responses; the HTTP error mapper
 * detects {@link FortressError.oauthError} and emits the
 * `{ error, error_description }` shape required by the spec.
 */
export type OAuthErrorCode
  = | 'invalid_request'
    | 'invalid_client'
    | 'invalid_grant'
    | 'unauthorized_client'
    | 'unsupported_grant_type'
    | 'invalid_scope'
    | 'access_denied'
    | 'unsupported_response_type'
    | 'server_error'
    | 'temporarily_unavailable';

/** The single error class fortress throws. Carries an error code, HTTP status, and structured details. */
export class FortressError extends Error {
  readonly code: FortressErrorCode;
  readonly statusCode: number;
  readonly retryAfter?: number;
  readonly details?: unknown;
  /** RFC 6749 §5.2 / §4.1.2.1 machine code. Set by `Errors.oauth()`. */
  readonly oauthError?: OAuthErrorCode;
  /** Human-readable description for the OAuth `error_description` field. */
  readonly oauthDescription?: string;
  /** Optional URI for the OAuth `error_uri` field (§5.2). */
  readonly oauthErrorUri?: string;

  constructor(
    code: FortressErrorCode,
    message: string,
    statusCode: number,
    options?: {
      cause?: unknown;
      retryAfter?: number;
      details?: unknown;
      oauthError?: OAuthErrorCode;
      oauthDescription?: string;
      oauthErrorUri?: string;
    },
  ) {
    super(message, { cause: options?.cause });
    this.code = code;
    this.statusCode = statusCode;
    this.retryAfter = options?.retryAfter;
    this.details = options?.details;
    this.oauthError = options?.oauthError;
    this.oauthDescription = options?.oauthDescription;
    this.oauthErrorUri = options?.oauthErrorUri;
  }

  toJSON(): { code: FortressErrorCode; message: string; statusCode: number; details?: unknown } {
    return {
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      ...(this.details !== undefined && { details: this.details }),
    };
  }
}

/** Typed factory of {@link FortressError} constructors — one helper per error code. */
export const Errors = {
  unauthorized: (message = 'Unauthorized'): FortressError =>
    new FortressError('UNAUTHORIZED', message, 401),
  tokenReuse: (): FortressError =>
    new FortressError('TOKEN_REUSE', 'Token reuse detected', 401),
  sessionIdleTimeout: (): FortressError =>
    new FortressError('SESSION_IDLE_TIMEOUT', 'Session idle timeout exceeded', 401),
  sessionAbsoluteTimeout: (): FortressError =>
    new FortressError('SESSION_ABSOLUTE_TIMEOUT', 'Session absolute timeout exceeded', 401),
  forbidden: (message = 'Forbidden', options?: { cause?: unknown; details?: unknown }): FortressError =>
    new FortressError('FORBIDDEN', message, 403, options),
  badRequest: (message = 'Bad request', options?: { cause?: unknown; details?: unknown }): FortressError =>
    new FortressError('BAD_REQUEST', message, 400, options),
  notFound: (message = 'Not found'): FortressError =>
    new FortressError('NOT_FOUND', message, 404),
  conflict: (message = 'Conflict', options?: { cause?: unknown; details?: unknown }): FortressError =>
    new FortressError('CONFLICT', message, 409, options),
  unprocessable: (message = 'Unprocessable entity', options?: { cause?: unknown; details?: unknown }): FortressError =>
    new FortressError('UNPROCESSABLE_ENTITY', message, 422, options),
  rateLimited: (retryAfter: number): FortressError =>
    new FortressError('RATE_LIMITED', 'Too many requests', 429, { retryAfter }),
  database: (message = 'Database error', cause?: unknown): FortressError =>
    new FortressError('DATABASE_ERROR', message, 500, { cause }),
  serviceUnavailable: (message = 'Service unavailable', options?: { cause?: unknown; retryAfter?: number }): FortressError =>
    new FortressError('SERVICE_UNAVAILABLE', message, 503, options),
  validationError: (issues: Array<{ path?: unknown; message: string }>): FortressError =>
    new FortressError('VALIDATION_ERROR', 'Validation failed', 422, { details: issues }),

  /**
   * RFC 6749 §5.2 / §4.1.2.1 OAuth error.
   *
   * The HTTP error mapper detects `oauthError` and emits the OAuth-spec
   * JSON body `{ error, error_description, error_uri? }` instead of the
   * default fortress `{ code, message }` shape, so strict OAuth clients
   * (Moodle, openid-client, Spring Security, etc.) can switch behaviour
   * on the machine-readable `error` field.
   *
   * Status is inferred from the OAuth code per the spec table:
   * - `invalid_client` → 401
   * - everything else → 400
   */
  oauth: (
    error: OAuthErrorCode,
    description?: string,
    options?: { status?: number; errorUri?: string; cause?: unknown },
  ): FortressError => {
    const status = options?.status ?? (error === 'invalid_client' ? 401 : 400);
    const code: FortressErrorCode = status === 401 ? 'UNAUTHORIZED' : 'BAD_REQUEST';
    return new FortressError(code, description ?? error, status, {
      oauthError: error,
      oauthDescription: description,
      oauthErrorUri: options?.errorUri,
      cause: options?.cause,
    });
  },

  /**
   * Reconstruct a {@link FortressError} from a JSON error body emitted by
   * `errorToResponse`. Used by the in-process `fortress.call.*` client to
   * convert non-2xx responses into typed throws that mirror what a direct
   * service-method call would produce.
   *
   * Maps by HTTP status when the body doesn't carry a recognizable
   * `{ code, message }` payload, so network errors and opaque upstream
   * failures still become structured `FortressError`s.
   */
  fromHttpResponse: (status: number, body: unknown): FortressError => {
    const payload = (body && typeof body === 'object' ? body : {}) as {
      code?: string;
      message?: string;
      details?: unknown;
    };
    const message = typeof payload.message === 'string' ? payload.message : `HTTP ${status}`;
    const code = typeof payload.code === 'string' && isFortressErrorCode(payload.code)
      ? payload.code
      : statusToErrorCode(status);
    return new FortressError(code, message, status, { details: payload.details });
  },
} as const;

function isFortressErrorCode(code: string): code is FortressErrorCode {
  return (
    code === 'UNAUTHORIZED'
    || code === 'TOKEN_REUSE'
    || code === 'SESSION_IDLE_TIMEOUT'
    || code === 'SESSION_ABSOLUTE_TIMEOUT'
    || code === 'FORBIDDEN'
    || code === 'BAD_REQUEST'
    || code === 'NOT_FOUND'
    || code === 'CONFLICT'
    || code === 'UNPROCESSABLE_ENTITY'
    || code === 'RATE_LIMITED'
    || code === 'DATABASE_ERROR'
    || code === 'VALIDATION_ERROR'
    || code === 'SERVICE_UNAVAILABLE'
  );
}

function statusToErrorCode(status: number): FortressErrorCode {
  if (status === 401)
    return 'UNAUTHORIZED';
  if (status === 403)
    return 'FORBIDDEN';
  if (status === 404)
    return 'NOT_FOUND';
  if (status === 409)
    return 'CONFLICT';
  if (status === 422)
    return 'UNPROCESSABLE_ENTITY';
  if (status === 429)
    return 'RATE_LIMITED';
  if (status === 503)
    return 'SERVICE_UNAVAILABLE';
  if (status >= 500)
    return 'DATABASE_ERROR';
  return 'BAD_REQUEST';
}
