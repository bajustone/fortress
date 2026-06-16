import { describe, expect, it } from 'vitest';
import { BUILTIN_EVENT_NAMES, builtinEvents } from './builtin-events';
import { assertEventRegistry, createEventRegistry } from './registry';

describe('webhook event registry', () => {
  it('builtinEvents returns the five auth events in order', () => {
    expect(builtinEvents().map(e => e.name)).toEqual([
      'auth.login.success',
      'auth.login.failure',
      'auth.logout',
      'auth.user.registered',
      'auth.token.refreshed',
    ]);
    expect(BUILTIN_EVENT_NAMES.has('auth.login.success')).toBe(true);
  });

  it('builtinEvents({ exclude }) drops only the excluded events', () => {
    const events = builtinEvents({ exclude: ['auth.logout'] });
    expect(events).toHaveLength(4);
    expect(events.find(e => e.name === 'auth.logout')).toBeUndefined();
  });

  it('assertEventRegistry rejects duplicate names', () => {
    expect(() => assertEventRegistry([{ name: 'order.paid' }, { name: 'order.paid' }])).toThrow(/Duplicate/);
  });

  it('assertEventRegistry rejects an empty name', () => {
    expect(() => assertEventRegistry([{ name: '' }])).toThrow();
  });

  it('assertEventRegistry rejects an unknown source', () => {
    expect(() => assertEventRegistry([{ name: 'x', source: 'nope' as never }])).toThrow(/source/);
  });

  it('createEventRegistry exposes lookup + the source→name map', () => {
    const reg = createEventRegistry([
      ...builtinEvents({ exclude: ['auth.logout'] }),
      { name: 'order.paid' },
    ]);
    expect(reg.has('order.paid')).toBe(true);
    expect(reg.get('auth.login.success')?.source).toBe('afterLogin');
    expect(reg.names()).toContain('order.paid');

    const sources = reg.sources();
    expect(sources.get('afterLogin')).toBe('auth.login.success');
    expect(sources.has('beforeLogout')).toBe(false); // excluded above
  });
});
