import type { FortressPlugin } from '../../core/plugin';
import { Errors } from '../../core/errors';

export function webauthn(): FortressPlugin {
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
      { method: 'POST', path: '/webauthn/register/options', handler: 'generateRegistrationOptions' },
      { method: 'POST', path: '/webauthn/register/verify', handler: 'verifyRegistration' },
      { method: 'POST', path: '/webauthn/authenticate/options', handler: 'generateAuthenticationOptions' },
      { method: 'POST', path: '/webauthn/authenticate/verify', handler: 'verifyAuthentication' },
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
