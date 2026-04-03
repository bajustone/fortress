import { describe, expect, it } from 'vitest';

import { generateRefreshToken, generateTokenFamily, hashToken } from './refresh-token';

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
