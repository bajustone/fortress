import { describe, expect, it } from 'vitest';

import { deriveRefreshTokenSuccessor, generateRefreshToken, generateTokenFamily, hashRefreshFingerprint, hashToken } from './refresh-token';

describe('refresh-token', () => {
  describe('generateRefreshToken', () => {
    it('generates a raw token and its hash', async () => {
      const { raw, hash } = await generateRefreshToken();
      expect(raw).toBeTruthy();
      expect(hash).toBeTruthy();
      expect(raw).not.toBe(hash);
    });

    it('generates unique tokens each time', async () => {
      const t1 = await generateRefreshToken();
      const t2 = await generateRefreshToken();
      expect(t1.raw).not.toBe(t2.raw);
      expect(t1.hash).not.toBe(t2.hash);
    });

    it('raw token is base64url encoded (no +, /, =)', async () => {
      const { raw } = await generateRefreshToken();
      expect(raw).not.toMatch(/[+/=]/);
    });

    it('hash is a hex string', async () => {
      const { hash } = await generateRefreshToken();
      expect(hash).toMatch(/^[0-9a-f]{64}$/); // SHA256 = 64 hex chars
    });
  });

  describe('hashToken', () => {
    it('produces consistent hash for the same input', async () => {
      const hash1 = await hashToken('same-token');
      const hash2 = await hashToken('same-token');
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different input', async () => {
      const hash1 = await hashToken('token-a');
      const hash2 = await hashToken('token-b');
      expect(hash1).not.toBe(hash2);
    });

    it('hash of generated token matches the returned hash', async () => {
      const { raw, hash } = await generateRefreshToken();
      const recomputed = await hashToken(raw);
      expect(recomputed).toBe(hash);
    });
  });

  describe('deriveRefreshTokenSuccessor', () => {
    it('recomputes the same successor without storing its raw value', async () => {
      const first = await deriveRefreshTokenSuccessor('old-token', 'secret-a');
      const retry = await deriveRefreshTokenSuccessor('old-token', 'secret-a');
      const otherKey = await deriveRefreshTokenSuccessor('old-token', 'secret-b');

      expect(retry).toEqual(first);
      expect(otherKey.raw).not.toBe(first.raw);
      expect(await hashToken(first.raw)).toBe(first.hash);
    });
  });

  describe('hashRefreshFingerprint', () => {
    it('is keyed and binds both User-Agent and source IP', async () => {
      const first = await hashRefreshFingerprint('Browser/1', '203.0.113.1', 'secret-a');
      expect(await hashRefreshFingerprint('Browser/1', '203.0.113.1', 'secret-a')).toBe(first);
      expect(await hashRefreshFingerprint('Browser/1', '203.0.113.2', 'secret-a')).not.toBe(first);
      expect(await hashRefreshFingerprint('Browser/1', '203.0.113.1', 'secret-b')).not.toBe(first);
      expect(first).not.toBe(await hashToken('Browser/1'));
    });
  });

  describe('generateTokenFamily', () => {
    it('generates a non-empty string', () => {
      const family = generateTokenFamily();
      expect(family).toBeTruthy();
    });

    it('generates unique families', () => {
      const f1 = generateTokenFamily();
      const f2 = generateTokenFamily();
      expect(f1).not.toBe(f2);
    });
  });
});
