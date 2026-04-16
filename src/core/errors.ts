/** Discriminated string union of every error code fortress can throw. Maps 1:1 to an HTTP status. */
export type FortressErrorCode
  = | 'UNAUTHORIZED'
    | 'TOKEN_REUSE'
    | 'FORBIDDEN'
    | 'BAD_REQUEST'
    | 'NOT_FOUND'
    | 'CONFLICT'
    | 'RATE_LIMITED'
    | 'DATABASE_ERROR'
    | 'VALIDATION_ERROR';

/** The single error class fortress throws. Carries an error code, HTTP status, and structured details. */
export class FortressError extends Error {
  readonly code: FortressErrorCode;
  readonly statusCode: number;
  readonly retryAfter?: number;
  readonly details?: unknown;

  constructor(
    code: FortressErrorCode,
    message: string,
    statusCode: number,
    options?: { cause?: unknown; retryAfter?: number; details?: unknown },
  ) {
    super(message, { cause: options?.cause });
    this.code = code;
    this.statusCode = statusCode;
    this.retryAfter = options?.retryAfter;
    this.details = options?.details;
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
  forbidden: (message = 'Forbidden'): FortressError =>
    new FortressError('FORBIDDEN', message, 403),
  badRequest: (message = 'Bad request'): FortressError =>
    new FortressError('BAD_REQUEST', message, 400),
  notFound: (message = 'Not found'): FortressError =>
    new FortressError('NOT_FOUND', message, 404),
  conflict: (message = 'Conflict'): FortressError =>
    new FortressError('CONFLICT', message, 409),
  rateLimited: (retryAfter: number): FortressError =>
    new FortressError('RATE_LIMITED', 'Too many requests', 429, { retryAfter }),
  database: (message = 'Database error', cause?: unknown): FortressError =>
    new FortressError('DATABASE_ERROR', message, 500, { cause }),
  validationError: (issues: Array<{ path?: unknown; message: string }>): FortressError =>
    new FortressError('VALIDATION_ERROR', 'Validation failed', 422, { details: issues }),

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
    || code === 'FORBIDDEN'
    || code === 'BAD_REQUEST'
    || code === 'NOT_FOUND'
    || code === 'CONFLICT'
    || code === 'RATE_LIMITED'
    || code === 'DATABASE_ERROR'
    || code === 'VALIDATION_ERROR'
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
    return 'VALIDATION_ERROR';
  if (status === 429)
    return 'RATE_LIMITED';
  if (status >= 500)
    return 'DATABASE_ERROR';
  return 'BAD_REQUEST';
}
