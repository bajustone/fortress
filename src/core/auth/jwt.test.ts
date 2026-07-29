import { generateKeyPair, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { signAccessToken, verifyAccessToken } from './jwt';

describe('jwt', () => {
  const secret = 'test-secret-at-least-32-chars-long!';
  const claims = {
    sub: '42',
    subjectType: 'USER' as const,
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

      expect(decoded.sub).toBe('42');
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
      expect(decoded.sub).toBe('42');
    });

    it('signs with first secret in array', async () => {
      const token = await signAccessToken(claims, [newSecret, oldSecret], 900);
      // Should verify with newSecret alone
      const decoded = await verifyAccessToken(token, newSecret);
      expect(decoded.sub).toBe('42');
    });

    it('fails if token was signed with a secret not in the array', async () => {
      const token = await signAccessToken(claims, 'unknown-secret-not-in-array!!', 900);
      await expect(verifyAccessToken(token, [newSecret, oldSecret])).rejects.toThrow();
    });

    it('rejects an empty key ring instead of choosing a fallback key', async () => {
      const token = await signAccessToken(claims, secret, 900);

      await expect(signAccessToken(claims, [], 900)).rejects.toThrow(
        'JWT key material must contain at least one key',
      );
      await expect(verifyAccessToken(token, [])).rejects.toThrow(
        'JWT key material must contain at least one key',
      );
    });
  });

  describe('custom claims', () => {
    it('includes custom claims in the token', async () => {
      const claimsWithCustom = {
        ...claims,
        customClaims: { tenantId: '5', tenantCode: 'acme' },
      };
      const token = await signAccessToken(claimsWithCustom, secret, 900);
      const decoded = await verifyAccessToken(token, secret);

      expect(decoded.customClaims?.tenantId).toBe('5');
      expect(decoded.customClaims?.tenantCode).toBe('acme');
    });

    // M2 regression: a caller (or a plugin contributing via
    // enrichTokenClaims) MUST NOT be able to forge `act`, `sub`, `groups`,
    // `subjectType`, etc. through customClaims.
    it('drops reserved keys from customClaims (no forged impersonation)', async () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production'; // silent drop in prod
      try {
        const sneaky = {
          ...claims,
          customClaims: {
            // attacker tries to overwrite trusted claims
            sub: '9999',
            act: { sub: '1', subjectType: 'USER' },
            groups: ['admin'],
            subjectType: 'SERVICE_ACCOUNT',
            tenantId: 'real-tenant',
          },
        };
        const token = await signAccessToken(sneaky, secret, 900);
        const decoded = await verifyAccessToken(token, secret);

        // Real sub/groups/subjectType prevail; forged act dropped.
        expect(decoded.sub).toBe('42');
        expect(decoded.subjectType).toBe('USER');
        expect(decoded.groups).toEqual(['admin', 'editor']);
        expect(decoded.act).toBeUndefined();
        // Non-reserved custom claims survive.
        expect(decoded.customClaims?.tenantId).toBe('real-tenant');
      }
      finally {
        if (originalNodeEnv === undefined)
          delete process.env.NODE_ENV;
        else process.env.NODE_ENV = originalNodeEnv;
      }
    });
  });

  describe('remediation: alg + issuer pinning (M5 / P2.5)', () => {
    it('verifies with the expected issuer', async () => {
      const token = await signAccessToken(claims, secret, 900);
      const decoded = await verifyAccessToken(token, secret, { issuer: 'fortress-test' });
      expect(decoded.iss).toBe('fortress-test');
    });

    it('rejects a token whose iss does not match', async () => {
      const token = await signAccessToken(claims, secret, 900);
      await expect(
        verifyAccessToken(token, secret, { issuer: 'someone-else' }),
      ).rejects.toThrow();
    });

    it('rejects unsigned and asymmetric-algorithm confusion tokens', async () => {
      const encoded = (value: unknown): string => btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
      const unsigned = `${encoded({ alg: 'none' })}.${encoded({ ...claims, iat: 1, exp: 4_102_444_800 })}.`;
      await expect(verifyAccessToken(unsigned, secret)).rejects.toThrow('Invalid or expired token');

      const { privateKey } = await generateKeyPair('RS256');
      const asymmetric = await new SignJWT({ ...claims, sub: claims.sub })
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuedAt()
        .setExpirationTime('900s')
        .sign(privateKey);
      await expect(verifyAccessToken(asymmetric, secret)).rejects.toThrow('Invalid or expired token');
    });

    it('rejects tokens missing Fortress-required claims instead of fabricating defaults', async () => {
      const token = await new SignJWT({ subjectType: 'USER', groups: [] })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('900s')
        .setIssuer('fortress-test')
        .setSubject('42')
        .sign(new TextEncoder().encode(secret));

      await expect(verifyAccessToken(token, secret)).rejects.toThrow('Invalid or expired token');
    });

    it('signs and verifies audience end-to-end', async () => {
      const token = await signAccessToken(
        { ...claims, customClaims: { tenantId: 'acme' } },
        secret,
        900,
        { audience: 'fortress-api' },
      );

      const decoded = await verifyAccessToken(token, secret, {
        audience: 'fortress-api',
        requiredClaims: ['tenantId'],
      });
      expect(decoded.aud).toBe('fortress-api');
      expect(decoded.customClaims?.tenantId).toBe('acme');

      await expect(
        verifyAccessToken(token, secret, { audience: 'other-api' }),
      ).rejects.toThrow('Invalid or expired token');
    });
  });
});
