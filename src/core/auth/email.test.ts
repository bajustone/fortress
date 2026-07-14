import { describe, expect, it } from 'vitest';
import { normalizeEmail } from './email';

describe('normalizeEmail', () => {
  it('lowercases the complete address', () => {
    expect(normalizeEmail('User.Name@EXAMPLE.COM')).toBe('user.name@example.com');
  });

  it('collapses canonically equivalent Unicode spellings with NFC', () => {
    expect(normalizeEmail('E\u0301@Example.COM')).toBe('é@example.com');
    expect(normalizeEmail('É@example.com')).toBe('é@example.com');
  });

  it('does not silently trim invalid surrounding whitespace', () => {
    expect(normalizeEmail(' User@Example.COM ')).toBe(' user@example.com ');
  });
});
