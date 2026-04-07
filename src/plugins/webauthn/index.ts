import type { FortressPlugin } from '../../core/plugin';
import { Errors } from '../../core/errors';

export interface WebAuthnMethods {
  generateRegistrationOptions: (userId: number) => Promise<never>;
  verifyRegistration: (userId: number, response: unknown) => Promise<never>;
  generateAuthenticationOptions: (userId?: number) => Promise<never>;
  verifyAuthentication: (response: unknown) => Promise<never>;
}
export function webauthn(): FortressPlugin & { readonly name: 'webauthn' } {
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

    routes: [
      {
        method: 'POST',
        path: '/webauthn/register/options',
        handler: 'generateRegistrationOptions',
        meta: { summary: 'Generate WebAuthn registration options', tags: ['WebAuthn'], security: ['bearer'] },
        input: { body: { type: 'object', properties: { userId: { type: 'integer' } }, required: ['userId'] } },
        responses: { 200: { description: 'Registration options' }, 400: { description: 'Not yet implemented' } },
      },
      {
        method: 'POST',
        path: '/webauthn/register/verify',
        handler: 'verifyRegistration',
        meta: { summary: 'Verify WebAuthn registration', tags: ['WebAuthn'], security: ['bearer'] },
        responses: { 200: { description: 'Registration verified' }, 400: { description: 'Not yet implemented' } },
      },
      {
        method: 'POST',
        path: '/webauthn/authenticate/options',
        handler: 'generateAuthenticationOptions',
        meta: { summary: 'Generate WebAuthn authentication options', tags: ['WebAuthn'], security: ['none'] },
        responses: { 200: { description: 'Authentication options' }, 400: { description: 'Not yet implemented' } },
      },
      {
        method: 'POST',
        path: '/webauthn/authenticate/verify',
        handler: 'verifyAuthentication',
        meta: { summary: 'Verify WebAuthn authentication', tags: ['WebAuthn'], security: ['none'] },
        responses: { 200: { description: 'Authentication verified' }, 400: { description: 'Not yet implemented' } },
      },
    ],

    methods: _ctx => ({
      async generateRegistrationOptions(_userId: number): Promise<never> {
        throw Errors.badRequest('WebAuthn not yet implemented');
      },

      async verifyRegistration(_userId: number, _response: unknown): Promise<never> {
        throw Errors.badRequest('WebAuthn not yet implemented');
      },

      async generateAuthenticationOptions(_userId?: number): Promise<never> {
        throw Errors.badRequest('WebAuthn not yet implemented');
      },

      async verifyAuthentication(_response: unknown): Promise<never> {
        throw Errors.badRequest('WebAuthn not yet implemented');
      },
    }),
  };
}
