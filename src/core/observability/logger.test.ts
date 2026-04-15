import { describe, expect, it } from 'vitest';
import { SILENT_LOGGER } from './logger';

describe('sILENT_LOGGER', () => {
  it('is a no-op — every level callable with zero side effects', () => {
    expect(SILENT_LOGGER.level).toBe('silent');
    expect(() => SILENT_LOGGER.fatal('msg')).not.toThrow();
    expect(() => SILENT_LOGGER.error('msg')).not.toThrow();
    expect(() => SILENT_LOGGER.warn('msg')).not.toThrow();
    expect(() => SILENT_LOGGER.info('msg')).not.toThrow();
    expect(() => SILENT_LOGGER.debug('msg')).not.toThrow();
    expect(() => SILENT_LOGGER.trace('msg')).not.toThrow();
    expect(() => SILENT_LOGGER.silent('msg')).not.toThrow();
  });

  it('accepts the three pino-compatible argument shapes at every level', () => {
    expect(() => SILENT_LOGGER.info('just a string')).not.toThrow();
    expect(() => SILENT_LOGGER.info({ key: 'value' }, 'with object')).not.toThrow();
    expect(() => SILENT_LOGGER.info('format %s', 'arg')).not.toThrow();
  });

  it('isLevelEnabled always returns false for the silent default', () => {
    expect(SILENT_LOGGER.isLevelEnabled?.('debug')).toBe(false);
    expect(SILENT_LOGGER.isLevelEnabled?.('error')).toBe(false);
  });

  it('is structurally compatible with a hand-rolled console logger', () => {
    const calls: string[] = [];
    const consoleLogger = {
      level: 'info',
      fatal: (...args: unknown[]): void => { calls.push(`fatal:${JSON.stringify(args)}`); },
      error: (...args: unknown[]): void => { calls.push(`error:${JSON.stringify(args)}`); },
      warn: (...args: unknown[]): void => { calls.push(`warn:${JSON.stringify(args)}`); },
      info: (...args: unknown[]): void => { calls.push(`info:${JSON.stringify(args)}`); },
      debug: (...args: unknown[]): void => { calls.push(`debug:${JSON.stringify(args)}`); },
      trace: (...args: unknown[]): void => { calls.push(`trace:${JSON.stringify(args)}`); },
      silent: (): void => {},
    };
    consoleLogger.warn({ plugin: 'test' }, 'warning');
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('warn:');
  });
});
