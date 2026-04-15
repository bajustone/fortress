/**
 * Structural logger contract. Shaped to be assignment-compatible with pino's
 * `BaseLogger` and Fastify's `FastifyBaseLogger`, so consumers can drop a
 * `pino()` instance or `fastify.log` in directly with zero adapter code.
 *
 * The default is {@link SILENT_LOGGER} — libraries that log to stderr by
 * default are universally hated. Opt-in logging only.
 */

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

export interface LogFn {
  (msg: string): void;
  (obj: Record<string, unknown>, msg?: string): void;
  (msg: string, ...args: unknown[]): void;
}

export interface FortressLogger {
  level: LogLevel | 'silent' | string;
  fatal: LogFn;
  error: LogFn;
  warn: LogFn;
  info: LogFn;
  debug: LogFn;
  trace: LogFn;
  silent: LogFn;
  /** Optional on pino/Fastify; Fortress calls it defensively. */
  child?: (bindings: Record<string, unknown>) => FortressLogger;
  /** Optional guard for lazy evaluation of expensive log metadata. */
  isLevelEnabled?: (level: LogLevel) => boolean;
}

const NOOP: LogFn = () => {};

/**
 * No-op logger used when {@link FortressConfig.logger} is unset. Every method
 * is a shared arrow function — zero allocation per call.
 */
export const SILENT_LOGGER: FortressLogger = {
  level: 'silent',
  fatal: NOOP,
  error: NOOP,
  warn: NOOP,
  info: NOOP,
  debug: NOOP,
  trace: NOOP,
  silent: NOOP,
  isLevelEnabled: () => false,
};
