import type { Fortress } from '../../core/fortress';
import type { WebAuthnMethods } from './index';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { webauthn } from './index';

const SECRET = 'webauthn-test-secret-at-least-32chars';
const MOCK_CHALLENGE = 'dGVzdC1jaGFsbGVuZ2U'; // base64url of "test-challenge"
const MOCK_CREDENTIAL_ID = 'Y3JlZGVudGlhbC1pZA'; // base64url
const MOCK_PUBLIC_KEY = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

// Mock @simplewebauthn/server
vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: vi.fn(async () => ({
    challenge: MOCK_CHALLENGE,
    rp: { name: 'Test', id: 'localhost' },
    user: { id: 'MQ', name: 'alice@example.com', displayName: 'Alice' },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
    timeout: 60000,
    attestation: 'none',
    excludeCredentials: [],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  })),
  verifyRegistrationResponse: vi.fn(async () => ({
    verified: true,
    registrationInfo: {
      fmt: 'none',
      aaguid: '00000000-0000-0000-0000-000000000000',
      credential: {
        id: MOCK_CREDENTIAL_ID,
        publicKey: MOCK_PUBLIC_KEY,
        counter: 0,
        transports: ['internal'],
      },
      credentialType: 'public-key',
      credentialDeviceType: 'multiDevice',
      credentialBackedUp: true,
      userVerified: true,
      origin: 'http://localhost:3000',
    },
  })),
  generateAuthenticationOptions: vi.fn(async () => ({
    challenge: MOCK_CHALLENGE,
    rpId: 'localhost',
    timeout: 60000,
    userVerification: 'preferred',
    allowCredentials: [],
  })),
  verifyAuthenticationResponse: vi.fn(async () => ({
    verified: true,
    authenticationInfo: {
      credentialID: MOCK_CREDENTIAL_ID,
      newCounter: 1,
      userVerified: true,
      credentialDeviceType: 'multiDevice',
      credentialBackedUp: true,
      origin: 'http://localhost:3000',
      rpID: 'localhost',
    },
  })),
}));

const simplewebauthn = await import('@simplewebauthn/server') as unknown as {
  [K in keyof Awaited<typeof import('@simplewebauthn/server')>]:
  import('vitest').Mock;
};

describe('webauthn plugin', () => {
  let fortress: Fortress<any>;
  let methods: WebAuthnMethods;
  let userId: number;

  beforeEach(async () => {
    vi.clearAllMocks();

    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [webauthn({ rpName: 'Test', rpID: 'localhost', origin: 'http://localhost:3000' })],
    });

    methods = fortress.plugins.webauthn as unknown as WebAuthnMethods;

    const user = await fortress.auth.createUser({
      email: 'alice@example.com',
      name: 'Alice',
      password: 'password-123',
    });
    userId = user.id;
  });

  describe('generateRegistrationOptions', () => {
    it('returns registration options', async () => {
      const result = await methods.generateRegistrationOptions({ userId });

      expect(result.options).toBeDefined();
      expect(result.options.challenge).toBe(MOCK_CHALLENGE);
      expect(simplewebauthn.generateRegistrationOptions).toHaveBeenCalledOnce();
    });

    it('throws if user not found', async () => {
      await expect(methods.generateRegistrationOptions({ userId: 9999 }))
        .rejects
        .toThrow('User not found');
    });

    it('passes excludeCredentials for existing credentials', async () => {
      // Register a credential first
      await methods.generateRegistrationOptions({ userId });
      await methods.verifyRegistration({
        userId,
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      });

      // Generate options again - should exclude the existing credential
      (simplewebauthn.generateRegistrationOptions).mockClear();
      await methods.generateRegistrationOptions({ userId });

      const call = (simplewebauthn.generateRegistrationOptions).mock.calls[0][0];
      expect(call.excludeCredentials).toHaveLength(1);
      expect(call.excludeCredentials![0].id).toBe(MOCK_CREDENTIAL_ID);
    });
  });

  describe('verifyRegistration', () => {
    it('stores credential on successful verification', async () => {
      await methods.generateRegistrationOptions({ userId });

      const result = await methods.verifyRegistration({
        userId,
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      });

      expect(result.verified).toBe(true);
      expect(result.credentialId).toBe(MOCK_CREDENTIAL_ID);
      expect(result.credentialDeviceType).toBe('multiDevice');
      expect(result.credentialBackedUp).toBe(true);
    });

    it('throws when no pending challenge', async () => {
      await expect(methods.verifyRegistration({
        userId,
        response: {} as any,
      })).rejects.toThrow('No pending registration challenge');
    });

    it('throws on failed verification', async () => {
      await methods.generateRegistrationOptions({ userId });

      (simplewebauthn.verifyRegistrationResponse).mockResolvedValueOnce({
        verified: false,
      });

      await expect(methods.verifyRegistration({
        userId,
        response: {} as any,
      })).rejects.toThrow('Registration verification failed');
    });
  });

  describe('generateAuthenticationOptions', () => {
    it('returns options with allowCredentials when userId provided', async () => {
      // Register a credential first
      await methods.generateRegistrationOptions({ userId });
      await methods.verifyRegistration({
        userId,
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      });

      (simplewebauthn.generateAuthenticationOptions).mockClear();
      await methods.generateAuthenticationOptions({ userId });

      const call = (simplewebauthn.generateAuthenticationOptions).mock.calls[0][0];
      expect(call.allowCredentials).toHaveLength(1);
      expect(call.allowCredentials![0].id).toBe(MOCK_CREDENTIAL_ID);
    });

    it('returns options without allowCredentials when no userId (discoverable)', async () => {
      (simplewebauthn.generateAuthenticationOptions).mockClear();
      await methods.generateAuthenticationOptions({});

      const call = (simplewebauthn.generateAuthenticationOptions).mock.calls[0][0];
      expect(call.allowCredentials).toBeUndefined();
    });
  });

  describe('verifyAuthentication', () => {
    async function registerAndPrepareAuth(): Promise<void> {
      // Register credential
      await methods.generateRegistrationOptions({ userId });
      await methods.verifyRegistration({
        userId,
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      });

      // Generate auth options
      await methods.generateAuthenticationOptions({ userId });
    }

    it('verifies and returns userId', async () => {
      await registerAndPrepareAuth();

      const result = await methods.verifyAuthentication({
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      });

      expect(result.verified).toBe(true);
      expect(result.userId).toBe(userId);
    });

    it('issues access token when passwordless', async () => {
      await registerAndPrepareAuth();

      const result = await methods.verifyAuthentication({
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      });

      expect(result.accessToken).toBeTruthy();
    });

    it('throws on unknown credential', async () => {
      await methods.generateAuthenticationOptions({});

      await expect(methods.verifyAuthentication({
        response: { id: 'unknown-id', rawId: 'unknown-id', response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      })).rejects.toThrow('Unknown credential');
    });

    it('throws on failed verification', async () => {
      await registerAndPrepareAuth();

      (simplewebauthn.verifyAuthenticationResponse).mockResolvedValueOnce({
        verified: false,
        authenticationInfo: {
          credentialID: MOCK_CREDENTIAL_ID,
          newCounter: 1,
          userVerified: false,
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
          origin: 'http://localhost:3000',
          rpID: 'localhost',
        },
      });

      await expect(methods.verifyAuthentication({
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      })).rejects.toThrow('Authentication verification failed');
    });

    it('detects counter rollback (clone detection)', async () => {
      await registerAndPrepareAuth();

      // First authentication: counter goes to 5
      (simplewebauthn.verifyAuthenticationResponse).mockResolvedValueOnce({
        verified: true,
        authenticationInfo: {
          credentialID: MOCK_CREDENTIAL_ID,
          newCounter: 5,
          userVerified: true,
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
          origin: 'http://localhost:3000',
          rpID: 'localhost',
        },
      });

      await methods.verifyAuthentication({
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      });

      // Second auth: counter rolls back to 3 (clone!)
      await methods.generateAuthenticationOptions({ userId });

      (simplewebauthn.verifyAuthenticationResponse).mockResolvedValueOnce({
        verified: true,
        authenticationInfo: {
          credentialID: MOCK_CREDENTIAL_ID,
          newCounter: 3,
          userVerified: true,
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
          origin: 'http://localhost:3000',
          rpID: 'localhost',
        },
      });

      await expect(methods.verifyAuthentication({
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      })).rejects.toThrow('counter validation failed');
    });
  });

  describe('afterLogin hook (second-factor mode)', () => {
    it('returns requiresWebAuthn when supportPasswordless is false', async () => {
      const f = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [webauthn({ rpName: 'Test', rpID: 'localhost', origin: 'http://localhost:3000', supportPasswordless: false })],
      });

      const m = f.plugins.webauthn as unknown as WebAuthnMethods;

      const user = await f.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      // Register a credential
      await m.generateRegistrationOptions({ userId: user.id });
      await m.verifyRegistration({
        userId: user.id,
        response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      });

      // Login should be intercepted
      const result = await f.auth.login('bob@example.com', 'password-123');
      expect(result.accessToken).toBeNull();
      expect(result.pluginData?.requiresWebAuthn).toBe(true);
    });

    it('allows normal login when no credentials registered', async () => {
      const f = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [webauthn({ rpName: 'Test', rpID: 'localhost', origin: 'http://localhost:3000', supportPasswordless: false })],
      });

      await f.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      const result = await f.auth.login('bob@example.com', 'password-123');
      expect(result.accessToken).toBeTruthy();
    });
  });
});
