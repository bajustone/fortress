import type { ProviderDefinition, ProviderProfile } from '../types';

export const googleProvider: ProviderDefinition = {
  name: 'google',
  discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
  defaultScopes: ['openid', 'profile', 'email'],
  mapProfile(raw: Record<string, unknown>): ProviderProfile {
    return {
      id: String(raw.sub ?? ''),
      email: String(raw.email ?? ''),
      name: String(raw.name ?? ''),
      displayName: String(raw.name ?? ''),
      avatar: raw.picture ? String(raw.picture) : undefined,
      raw,
    };
  },
};
