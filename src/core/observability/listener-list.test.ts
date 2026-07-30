import type { FortressLogger } from './logger';
import { describe, expect, it, vi } from 'vitest';
import { createListenerList } from './listener-list';
import { SILENT_LOGGER } from './logger';

function mockLogger(): FortressLogger & { errorSpy: ReturnType<typeof vi.fn> } {
  const errorSpy = vi.fn();
  return {
    ...SILENT_LOGGER,
    error: errorSpy,
    errorSpy,
  };
}

describe('createListenerList (sync)', () => {
  it('invokes listeners in registration order and returns an unsubscribe fn', () => {
    const logger = mockLogger();
    const list = createListenerList<number>({
      kind: 'sync',
      eventLabel: 'test',
      logger: () => logger,
    });

    const calls: string[] = [];
    const off1 = list.add((n) => {
      calls.push(`a:${n}`);
    });
    const off2 = list.add((n) => {
      calls.push(`b:${n}`);
    });
    expect(list.size()).toBe(2);

    list.emit(1);
    expect(calls).toEqual(['a:1', 'b:1']);

    off1();
    list.emit(2);
    expect(calls).toEqual(['a:1', 'b:1', 'b:2']);

    off2();
    expect(list.size()).toBe(0);
    list.emit(3);
    expect(calls).toEqual(['a:1', 'b:1', 'b:2']);
  });

  it('catches thrown errors and routes them to the logger', () => {
    const logger = mockLogger();
    const list = createListenerList<{ id: string }>({
      kind: 'sync',
      eventLabel: 'boom',
      logger: () => logger,
    });

    list.add(() => {
      throw new Error('listener bug');
    });
    list.add(() => {
      // healthy listener
    });

    // Emit should NOT throw — error is routed to logger.error.
    expect(() => list.emit({ id: '1' })).not.toThrow();
    expect(logger.errorSpy).toHaveBeenCalledTimes(1);
    expect(requireAt(logger.errorSpy.mock.calls, 0, 'first listener call')[0]).toMatchObject({
      event: 'boom',
    });
  });

  it('remaining listeners still fire after one throws', () => {
    const logger = mockLogger();
    const list = createListenerList<number>({
      kind: 'sync',
      eventLabel: 'test',
      logger: () => logger,
    });
    const after = vi.fn();
    list.add(() => {
      throw new Error('first listener');
    });
    list.add(after);
    list.emit(42);
    expect(after).toHaveBeenCalledWith(42);
  });
});

describe('createListenerList (async)', () => {
  it('fires listeners without awaiting their resolution', async () => {
    const logger = mockLogger();
    const list = createListenerList<string>({
      kind: 'async',
      eventLabel: 'async',
      logger: () => logger,
    });

    let resolved = false;
    list.add(async (v) => {
      await new Promise(r => setTimeout(r, 10));
      resolved = true;
      expect(v).toBe('hello');
    });

    list.emit('hello');
    // Listener hasn't finished yet — emit is non-blocking.
    expect(resolved).toBe(false);
    await new Promise(r => setTimeout(r, 30));
    expect(resolved).toBe(true);
  });

  it('routes rejected promises to logger.error', async () => {
    const logger = mockLogger();
    const list = createListenerList<number>({
      kind: 'async',
      eventLabel: 'async',
      logger: () => logger,
    });
    list.add(async () => {
      throw new Error('async boom');
    });

    list.emit(1);
    await new Promise(r => setTimeout(r, 10));
    expect(logger.errorSpy).toHaveBeenCalledTimes(1);
  });
});

function requireAt<T>(values: readonly T[], index: number, description: string): T {
  const value = values[index];
  if (value === undefined)
    throw new Error(`Expected ${description}`);
  return value;
}
