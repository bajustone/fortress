export type FortressErrorCode
  = | 'UNAUTHORIZED'
    | 'TOKEN_REUSE'
    | 'FORBIDDEN'
    | 'BAD_REQUEST'
    | 'NOT_FOUND'
    | 'RATE_LIMITED'
    | 'DATABASE_ERROR';

export class FortressError extends Error {
  readonly code: FortressErrorCode;
  readonly statusCode: number;
  readonly retryAfter?: number;

  constructor(
    code: FortressErrorCode,
    message: string,
    statusCode: number,
    options?: { cause?: unknown; retryAfter?: number },
  ) {
    super(message, { cause: options?.cause });
    this.code = code;
    this.statusCode = statusCode;
    this.retryAfter = options?.retryAfter;
  }

  toJSON(): { code: FortressErrorCode; message: string; statusCode: number } {
    return { code: this.code, message: this.message, statusCode: this.statusCode };
  }
}

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
  rateLimited: (retryAfter: number): FortressError =>
    new FortressError('RATE_LIMITED', 'Too many requests', 429, { retryAfter }),
  database: (message = 'Database error', cause?: unknown): FortressError =>
    new FortressError('DATABASE_ERROR', message, 500, { cause }),
} as const;
