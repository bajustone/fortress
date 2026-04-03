import { describe, expect, it } from 'vitest';

import { signAccessToken, verifyAccessToken } from './jwt';

describe('jwt', () => {
  const secret = 'test-secret-at-least-32-chars-long!';
  const claims = {
    sub: 42,
    name: 'Test User',
    groups: ['admin', 'editor'],
    iss: 'fortress-test',
  };

  describe('signAccessToken', () => {
    it('signs a token and returns a string', async () => {
      const token = await signAccessToken(claims, secret, 900);
      expect(token).toBeTruthy();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });
  });

  describe('verifyAccessToken', () => {
    it('verifies a valid token and returns claims', async () => {
      const token = await signAccessToken(claims, secret, 900);
      const decoded = await verifyAccessToken(token, secret);

      expect(decoded.sub).toBe(42);
      expect(decoded.name).toBe('Test User');
      expect(decoded.groups).toEqual(['admin', 'editor']);
      expect(decoded.iss).toBe('fortress-test');
      expect(decoded.iat).toBeGreaterThan(0);
      expect(decoded.exp).toBeGreaterThan(decoded.iat);
    });

    it('rejects a token signed with a different secret', async () => {
      const token = await signAccessToken(claims, secret, 900);
      await expect(verifyAccessToken(token, 'wrong-secret')).rejects.toThrow('Invalid or expired token');
    });

    it('rejects an expired token', async () => {
      const token = await signAccessToken(claims, secret, 0); // expires immediately
      // Small delay to ensure expiration
      await new Promise(resolve => setTimeout(resolve, 1100));
      await expect(verifyAccessToken(token, secret)).rejects.toThrow('Invalid or expired token');
    }, 5000);
  });

  describe('secret rotation', () => {
    const oldSecret = 'old-secret-for-rotation-testing!!';
    const newSecret = 'new-secret-for-rotation-testing!!';

    it('verifies a token signed with old secret using [new, old] array', async () => {
      const token = await signAccessToken(claims, oldSecret, 900);
      const decoded = await verifyAccessToken(token, [newSecret, oldSecret]);
      expect(decoded.sub).toBe(42);
    });

    it('signs with first secret in array', async () => {
      const token = await signAccessToken(claims, [newSecret, oldSecret], 900);
      // Should verify with newSecret alone
      const decoded = await verifyAccessToken(token, newSecret);
      expect(decoded.sub).toBe(42);
    });

    it('fails if token was signed with a secret not in the array', async () => {
      const token = await signAccessToken(claims, 'unknown-secret-not-in-array!!', 900);
      await expect(verifyAccessToken(token, [newSecret, oldSecret])).rejects.toThrow();
    });
  });

  describe('custom claims', () => {
    it('includes custom claims in the token', async () => {
      const claimsWithCustom = {
        ...claims,
        customClaims: { tenantId: 5, tenantCode: 'acme' },
      };
      const token = await signAccessToken(claimsWithCustom, secret, 900);
      const decoded = await verifyAccessToken(token, secret);

      expect(decoded.customClaims?.tenantId).toBe(5);
      expect(decoded.customClaims?.tenantCode).toBe('acme');
    });
  });
});
