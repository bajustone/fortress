import type { Fortress } from '../../core/fortress';
import type { PluginRouteContext } from '../../core/plugin';
import type { WebAuthnMethods } from './index';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { webauthn } from './index';

// Minimal PluginRouteContext for tests that invoke plugin methods directly.
// The dispatcher constructs the real ctx for HTTP calls; unit tests stub
// just the userId (and a placeholder Request) since the handlers only read
// routeCtx.userId.
function httpCtx(uid: string | undefined): PluginRouteContext {
  return {
    userId: uid,
    claims: undefined,
    meta: undefined,
    request: new Request('http://localhost/webauthn/register'),
  };
}

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
  let userId: string;

  beforeEach(async () => {
    vi.clearAllMocks();

    fortress = createFortress({
      jwt: { key: SECRET },
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
      const result = await methods.generateRegistrationOptions({}, httpCtx(userId));

      expect(result.options).toBeDefined();
      expect(result.options.challenge).toBe(MOCK_CHALLENGE);
      expect(simplewebauthn.generateRegistrationOptions).toHaveBeenCalledOnce();
    });

    it('throws if user not found', async () => {
      await expect(methods.generateRegistrationOptions({}, httpCtx('9999')))
        .rejects
        .toThrow('User not found');
    });

    it('throws UNAUTHORIZED when ctx.userId is missing', async () => {
      await expect(methods.generateRegistrationOptions({}, httpCtx(undefined)))
        .rejects
        .toThrow('User not authenticated');
    });

    it('passes excludeCredentials for existing credentials', async () => {
      // Register a credential first
      await methods.generateRegistrationOptions({}, httpCtx(userId));
      await methods.verifyRegistration(
        { response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any },
        httpCtx(userId),
      );

      // Generate options again - should exclude the existing credential
      (simplewebauthn.generateRegistrationOptions).mockClear();
      await methods.generateRegistrationOptions({}, httpCtx(userId));

      const call = (simplewebauthn.generateRegistrationOptions).mock.calls[0][0];
      expect(call.excludeCredentials).toHaveLength(1);
      expect(call.excludeCredentials![0].id).toBe(MOCK_CREDENTIAL_ID);
    });
  });

  describe('verifyRegistration', () => {
    it('stores credential on successful verification', async () => {
      await methods.generateRegistrationOptions({}, httpCtx(userId));

      const result = await methods.verifyRegistration(
        { response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any },
        httpCtx(userId),
      );

      expect(result.verified).toBe(true);
      expect(result.credentialId).toBe(MOCK_CREDENTIAL_ID);
      expect(result.credentialDeviceType).toBe('multiDevice');
      expect(result.credentialBackedUp).toBe(true);
    });

    it('throws when no pending challenge', async () => {
      await expect(methods.verifyRegistration(
        { response: {} as any },
        httpCtx(userId),
      )).rejects.toThrow('No pending registration challenge');
    });

    it('throws UNAUTHORIZED when ctx.userId is missing', async () => {
      await expect(methods.verifyRegistration(
        { response: {} as any },
        httpCtx(undefined),
      )).rejects.toThrow('User not authenticated');
    });

    it('throws on failed verification', async () => {
      await methods.generateRegistrationOptions({}, httpCtx(userId));

      (simplewebauthn.verifyRegistrationResponse).mockResolvedValueOnce({
        verified: false,
      });

      await expect(methods.verifyRegistration(
        { response: {} as any },
        httpCtx(userId),
      )).rejects.toThrow('Registration verification failed');
    });
  });

  describe('generateAuthenticationOptions', () => {
    it('returns options with allowCredentials when userId provided', async () => {
      // Register a credential first
      await methods.generateRegistrationOptions({}, httpCtx(userId));
      await methods.verifyRegistration(
        { response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any },
        httpCtx(userId),
      );

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
      await methods.generateRegistrationOptions({}, httpCtx(userId));
      await methods.verifyRegistration(
        { response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any },
        httpCtx(userId),
      );

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
        jwt: { key: SECRET },
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
      await m.generateRegistrationOptions({}, httpCtx(user.id));
      await m.verifyRegistration(
        { response: { id: MOCK_CREDENTIAL_ID, rawId: MOCK_CREDENTIAL_ID, response: {}, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any },
        httpCtx(user.id),
      );

      // Login should be intercepted
      const result = await f.auth.login('bob@example.com', 'password-123');
      expect(result.accessToken).toBeNull();
      expect(result.pluginData?.requiresWebAuthn).toBe(true);
    });

    it('allows normal login when no credentials registered', async () => {
      const f = createFortress({
        jwt: { key: SECRET },
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

  describe('http dispatch (privilege-escalation regression)', () => {
    // Sanity guard: a caller hitting POST /webauthn/register/options with a
    // valid bearer token for user A must register a credential against user A,
    // even if the request body tries to smuggle user B's id. Verified by
    // inspecting which userId ends up stamped on the stored challenge row.
    it('uses the authenticated caller id, ignoring any body userId', async () => {
      // Create two users; alice is the attacker, bob is the victim.
      const alice = await fortress.auth.createUser({
        email: 'attacker@example.com',
        name: 'Alice',
        password: 'password-123',
      });
      const bob = await fortress.auth.createUser({
        email: 'victim@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      const login = await fortress.auth.login('attacker@example.com', 'password-123');
      if (login.status !== 'success')
        throw new Error('expected login success');

      // Attempt: call /webauthn/register/options with alice's bearer token but
      // a body claiming to register for bob. The dispatcher should ignore the
      // body field entirely (it's not even in the schema now) and stamp the
      // challenge against alice.
      const res = await fortress.handleRequest(new Request('http://localhost/webauthn/register/options', {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${login.accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ userId: bob.id }),
      }));
      expect(res.status).toBe(200);

      // The stored challenge row must belong to alice, never bob.
      const adapter = fortress.config.database;
      const aliceChallenge = await adapter.findOne<{ userId: string | null }>({
        model: 'webauthn_challenge',
        where: [{ field: 'userId', operator: '=', value: alice.id }],
      });
      const bobChallenge = await adapter.findOne<{ userId: string | null }>({
        model: 'webauthn_challenge',
        where: [{ field: 'userId', operator: '=', value: bob.id }],
      });
      expect(aliceChallenge).not.toBeNull();
      expect(bobChallenge).toBeNull();
    });
  });
});
