/**
 * WebAuthn / Passkeys plugin for fortress.
 *
 * Implements passkey registration, passwordless authentication, and a
 * second-factor mode using `@simplewebauthn/server`. Persists credentials
 * and challenges via the fortress database adapter and exposes the standard
 * begin/finish endpoints when mounted on a framework adapter.
 *
 * @module
 */

import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { FortressPlugin } from '../../core/plugin';
import type { FortressUser } from '../../core/types';
import {
  generateAuthenticationOptions as generateAuthOptions,
  generateRegistrationOptions as generateRegOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { Errors } from '../../core/errors';
import { bool, endpoint, int, obj, record, str } from '../../core/schema-builder';

// ── Config ──────────────────────────────────────────────────────────

export interface WebAuthnConfig {
  /** Human-readable relying party name shown to users (e.g., "My App") */
  rpName: string;
  /** Relying party identifier -- typically the domain (e.g., "example.com") */
  rpID: string;
  /** Expected origin(s) for the credential (e.g., "https://example.com") */
  origin: string | string[];
  /** Attestation preference. Default: 'none'. */
  attestation?: 'none' | 'indirect' | 'direct' | 'enterprise';
  /** Authenticator selection criteria */
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    residentKey?: 'discouraged' | 'preferred' | 'required';
    userVerification?: 'discouraged' | 'preferred' | 'required';
  };
  /** Timeout for WebAuthn ceremonies in milliseconds. Default: 60000. */
  timeout?: number;
  /** Challenge TTL in seconds. Default: 300 (5 minutes). */
  challengeTTLSeconds?: number;
  /** Issue tokens on authentication verify (passwordless). Default: true. */
  supportPasswordless?: boolean;
}

// ── Method Types ────────────────────────────────────────────────────

export interface WebAuthnMethods {
  generateRegistrationOptions: (input: { userId: number }) => Promise<{ options: PublicKeyCredentialCreationOptionsJSON }>;
  verifyRegistration: (input: { userId: number; response: RegistrationResponseJSON }) => Promise<{
    verified: boolean;
    credentialId: string;
    credentialDeviceType: string;
    credentialBackedUp: boolean;
  }>;
  generateAuthenticationOptions: (input: { userId?: number }) => Promise<{ options: PublicKeyCredentialRequestOptionsJSON }>;
  verifyAuthentication: (input: { response: AuthenticationResponseJSON }) => Promise<{
    verified: boolean;
    userId: number;
    accessToken?: string;
    refreshToken?: string;
  }>;
}

// ── Internal Record Types ───────────────────────────────────────────

interface CredentialRecord {
  id: number;
  userId: number;
  credentialId: string;
  publicKey: string; // base64url-encoded
  counter: number;
  deviceType: string;
  backedUp: boolean;
  transports: string | null; // JSON array
  createdAt: Date;
}

interface ChallengeRecord {
  id: number;
  challenge: string;
  userId: number | null;
  expiresAt: Date;
  createdAt: Date;
}

// ── Helpers ─────────────────────────────────────────────────────────

const RE_PLUS = /\+/g;
const RE_SLASH = /\//g;
const RE_TRAILING_EQ = /=+$/;

function base64urlToUint8Array(base64url: string): Uint8Array<ArrayBuffer> {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function uint8ArrayToBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(RE_PLUS, '-').replace(RE_SLASH, '_').replace(RE_TRAILING_EQ, '');
}

// ── Routes ──────────────────────────────────────────────────────────

const webauthnRoutes = [
  endpoint('POST', '/webauthn/register/options')
    .summary('Generate WebAuthn registration options')
    .description('Generate public key credential creation options for registering a new passkey. Requires authentication.')
    .tags('WebAuthn')
    .security('bearer')
    .body(obj({ userId: int('User ID to register the credential for') }, 'userId'))
    .response(200, 'Registration options', obj({
      options: record('PublicKeyCredentialCreationOptions JSON'),
    }, 'options'))
    .response(400, 'Bad request')
    .response(404, 'User not found')
    .handler('generateRegistrationOptions')
    .build(),

  endpoint('POST', '/webauthn/register/verify')
    .summary('Verify WebAuthn registration')
    .description('Verify the registration response from the authenticator and store the new credential.')
    .tags('WebAuthn')
    .security('bearer')
    .body(obj({
      userId: int('User ID'),
      response: record('RegistrationResponseJSON from navigator.credentials.create()'),
    }, 'userId', 'response'))
    .response(200, 'Registration verified', obj({
      verified: bool('Whether registration was successful'),
      credentialId: str('Base64url-encoded credential ID'),
      credentialDeviceType: str('singleDevice or multiDevice'),
      credentialBackedUp: bool('Whether credential is backed up (synced passkey)'),
    }, 'verified'))
    .response(400, 'Verification failed')
    .handler('verifyRegistration')
    .build(),

  endpoint('POST', '/webauthn/authenticate/options')
    .summary('Generate WebAuthn authentication options')
    .description('Generate public key credential request options. Optionally pass userId for non-discoverable credential flow.')
    .tags('WebAuthn')
    .security('none')
    .body(obj({ userId: int('Optional user ID') }))
    .response(200, 'Authentication options', obj({
      options: record('PublicKeyCredentialRequestOptions JSON'),
    }, 'options'))
    .handler('generateAuthenticationOptions')
    .build(),

  endpoint('POST', '/webauthn/authenticate/verify')
    .summary('Verify WebAuthn authentication')
    .description('Verify the authentication assertion. Returns tokens if passwordless mode is enabled.')
    .tags('WebAuthn')
    .security('none')
    .body(obj({
      response: record('AuthenticationResponseJSON from navigator.credentials.get()'),
    }, 'response'))
    .response(200, 'Authentication verified', obj({
      verified: bool('Whether authentication was successful'),
      userId: int('Authenticated user ID'),
      accessToken: str('JWT access token (if passwordless)'),
      refreshToken: str('Refresh token (if passwordless)'),
    }, 'verified', 'userId'))
    .response(401, 'Authentication failed')
    .handler('verifyAuthentication')
    .build(),
];

// ── Plugin Factory ──────────────────────────────────────────────────

export function webauthn(config: WebAuthnConfig): FortressPlugin & { readonly name: 'webauthn' } {
  const rpName = config.rpName;
  const rpID = config.rpID;
  const origin = config.origin;
  const attestation = config.attestation ?? 'none';
  const timeout = config.timeout ?? 60_000;
  const challengeTTLSeconds = config.challengeTTLSeconds ?? 300;
  const supportPasswordless = config.supportPasswordless ?? true;
  const authenticatorSelection = {
    residentKey: config.authenticatorSelection?.residentKey ?? 'preferred' as const,
    userVerification: config.authenticatorSelection?.userVerification ?? 'preferred' as const,
    ...(config.authenticatorSelection?.authenticatorAttachment
      ? { authenticatorAttachment: config.authenticatorSelection.authenticatorAttachment }
      : {}),
  };

  return {
    name: 'webauthn',

    models: [
      {
        name: 'webauthn_credential',
        fields: {
          id: { type: 'number', required: true },
          userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
          credentialId: { type: 'string', required: true, unique: true },
          publicKey: { type: 'string', required: true },
          counter: { type: 'number', required: true },
          deviceType: { type: 'string', required: true },
          backedUp: { type: 'boolean', required: true },
          transports: { type: 'string' },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        name: 'webauthn_challenge',
        fields: {
          id: { type: 'number', required: true },
          challenge: { type: 'string', required: true, unique: true },
          userId: { type: 'number' },
          expiresAt: { type: 'date', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
    ],

    routes: webauthnRoutes,

    hooks: supportPasswordless
      ? undefined
      : {
          async afterLogin(ctx, result) {
            if (!result.user)
              return result;

            const credential = await ctx.db.findOne<CredentialRecord>({
              model: 'webauthn_credential',
              where: [{ field: 'userId', operator: '=', value: result.user.id }],
            });

            if (!credential)
              return result;

            return {
              ...result,
              status: 'pending' as const,
              accessToken: null,
              refreshToken: null,
              pluginData: { ...result.pluginData, requiresWebAuthn: true },
            };
          },
        },

    methods: ctx => ({
      async generateRegistrationOptions(input: { userId: number }): Promise<{ options: PublicKeyCredentialCreationOptionsJSON }> {
        const { userId } = input;

        const user = await ctx.db.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: userId }],
        });
        if (!user)
          throw Errors.notFound('User not found');

        // Find existing credentials for excludeCredentials
        const existing = await ctx.db.findMany<CredentialRecord>({
          model: 'webauthn_credential',
          where: [{ field: 'userId', operator: '=', value: userId }],
        });

        // Clean up expired challenges for this user
        await ctx.db.delete({
          model: 'webauthn_challenge',
          where: [{ field: 'userId', operator: '=', value: userId }],
        });

        const options = await generateRegOptions({
          rpName,
          rpID,
          userName: user.email,
          userDisplayName: user.name,
          userID: new TextEncoder().encode(String(userId)),
          attestationType: attestation === 'indirect' ? 'none' : attestation as 'none' | 'direct' | 'enterprise',
          excludeCredentials: existing.map(cred => ({
            id: cred.credentialId,
            transports: cred.transports
              ? JSON.parse(cred.transports) as AuthenticatorTransportFuture[]
              : undefined,
          })),
          authenticatorSelection,
          timeout,
        });

        // Store challenge
        await ctx.db.create({
          model: 'webauthn_challenge',
          data: {
            challenge: options.challenge,
            userId,
            expiresAt: new Date(Date.now() + challengeTTLSeconds * 1000),
            createdAt: new Date(),
          },
        });

        return { options };
      },

      async verifyRegistration(input: { userId: number; response: RegistrationResponseJSON }): Promise<{
        verified: boolean;
        credentialId: string;
        credentialDeviceType: string;
        credentialBackedUp: boolean;
      }> {
        const { userId, response } = input;

        // Find the pending challenge
        const challengeRecord = await ctx.db.findOne<ChallengeRecord>({
          model: 'webauthn_challenge',
          where: [{ field: 'userId', operator: '=', value: userId }],
        });
        if (!challengeRecord)
          throw Errors.badRequest('No pending registration challenge');

        if (new Date(challengeRecord.expiresAt) < new Date()) {
          await ctx.db.delete({
            model: 'webauthn_challenge',
            where: [{ field: 'id', operator: '=', value: challengeRecord.id }],
          });
          throw Errors.badRequest('Challenge expired');
        }

        const verification = await verifyRegistrationResponse({
          response,
          expectedChallenge: challengeRecord.challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
        });

        if (!verification.verified || !verification.registrationInfo) {
          throw Errors.badRequest('Registration verification failed');
        }

        const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

        // Store the credential
        await ctx.db.create({
          model: 'webauthn_credential',
          data: {
            userId,
            credentialId: credential.id,
            publicKey: uint8ArrayToBase64url(credential.publicKey),
            counter: credential.counter,
            deviceType: credentialDeviceType,
            backedUp: credentialBackedUp,
            transports: credential.transports ? JSON.stringify(credential.transports) : null,
            createdAt: new Date(),
          },
        });

        // Delete used challenge
        await ctx.db.delete({
          model: 'webauthn_challenge',
          where: [{ field: 'id', operator: '=', value: challengeRecord.id }],
        });

        return {
          verified: true,
          credentialId: credential.id,
          credentialDeviceType,
          credentialBackedUp,
        };
      },

      async generateAuthenticationOptions(input: { userId?: number }): Promise<{ options: PublicKeyCredentialRequestOptionsJSON }> {
        const { userId } = input;

        let allowCredentials: { id: string; transports?: AuthenticatorTransportFuture[] }[] | undefined;

        if (userId) {
          // Clean up old challenges for this user
          await ctx.db.delete({
            model: 'webauthn_challenge',
            where: [{ field: 'userId', operator: '=', value: userId }],
          });

          const credentials = await ctx.db.findMany<CredentialRecord>({
            model: 'webauthn_credential',
            where: [{ field: 'userId', operator: '=', value: userId }],
          });

          allowCredentials = credentials.map(cred => ({
            id: cred.credentialId,
            transports: cred.transports
              ? JSON.parse(cred.transports) as AuthenticatorTransportFuture[]
              : undefined,
          }));
        }

        const options = await generateAuthOptions({
          rpID,
          allowCredentials,
          userVerification: authenticatorSelection.userVerification,
          timeout,
        });

        // Store challenge
        await ctx.db.create({
          model: 'webauthn_challenge',
          data: {
            challenge: options.challenge,
            userId: userId ?? null,
            expiresAt: new Date(Date.now() + challengeTTLSeconds * 1000),
            createdAt: new Date(),
          },
        });

        return { options };
      },

      async verifyAuthentication(input: { response: AuthenticationResponseJSON }): Promise<{
        verified: boolean;
        userId: number;
        accessToken?: string;
        refreshToken?: string;
      }> {
        const { response } = input;

        // Look up the credential by its ID
        const credentialRecord = await ctx.db.findOne<CredentialRecord>({
          model: 'webauthn_credential',
          where: [{ field: 'credentialId', operator: '=', value: response.id }],
        });
        if (!credentialRecord)
          throw Errors.unauthorized('Unknown credential');

        // Find matching challenge
        const challengeRecord = await ctx.db.findOne<ChallengeRecord>({
          model: 'webauthn_challenge',
          where: [{ field: 'userId', operator: '=', value: credentialRecord.userId }],
        });

        // Also try null-userId challenges (discoverable credential flow)
        const discoverableChallenge = challengeRecord
          ? null
          : await ctx.db.findOne<ChallengeRecord>({
              model: 'webauthn_challenge',
              where: [{ field: 'userId', operator: '=', value: null }],
            });

        const challenge = challengeRecord ?? discoverableChallenge;
        if (!challenge)
          throw Errors.badRequest('No pending authentication challenge');

        if (new Date(challenge.expiresAt) < new Date()) {
          await ctx.db.delete({
            model: 'webauthn_challenge',
            where: [{ field: 'id', operator: '=', value: challenge.id }],
          });
          throw Errors.badRequest('Challenge expired');
        }

        const verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge: challenge.challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          credential: {
            id: credentialRecord.credentialId,
            publicKey: base64urlToUint8Array(credentialRecord.publicKey),
            counter: credentialRecord.counter,
            transports: credentialRecord.transports
              ? JSON.parse(credentialRecord.transports) as AuthenticatorTransportFuture[]
              : undefined,
          },
        });

        if (!verification.verified) {
          throw Errors.unauthorized('Authentication verification failed');
        }

        const { newCounter } = verification.authenticationInfo;

        // Counter validation: detect cloning (skip if either is 0 for synced passkeys)
        if (newCounter > 0 && credentialRecord.counter > 0 && newCounter <= credentialRecord.counter) {
          throw Errors.unauthorized('Authenticator counter validation failed');
        }

        // Update counter
        await ctx.db.update({
          model: 'webauthn_credential',
          where: [{ field: 'id', operator: '=', value: credentialRecord.id }],
          data: { counter: newCounter },
        });

        // Delete used challenge
        await ctx.db.delete({
          model: 'webauthn_challenge',
          where: [{ field: 'id', operator: '=', value: challenge.id }],
        });

        // Issue tokens for passwordless flow
        let accessToken: string | undefined;
        if (supportPasswordless && ctx.auth) {
          const user = await ctx.db.findOne<FortressUser>({
            model: 'user',
            where: [{ field: 'id', operator: '=', value: credentialRecord.userId }],
          });

          if (user) {
            accessToken = await ctx.auth.signToken({
              sub: user.id,
              name: user.name,
              groups: [],
              iss: 'fortress',
            }) as string;
          }
        }

        return {
          verified: true,
          userId: credentialRecord.userId,
          ...(accessToken ? { accessToken } : {}),
        };
      },
    }),
  };
}
