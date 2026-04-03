import type { ProviderDefinition, ProviderProfile } from '../types';

/**
 * Apple Sign In — user info comes from the ID token only.
 * Apple sends the user's name only on the first authorization (in the POST callback body).
 * Subsequent logins only provide sub and email in the ID token.
 */
export const appleProvider: ProviderDefinition = {
  name: 'apple',
  discoveryUrl: 'https://appleid.apple.com/.well-known/openid-configuration',
  authorizationUrl: 'https://appleid.apple.com/auth/authorize',
  tokenUrl: 'https://appleid.apple.com/auth/token',
  userInfoUrl: undefined, // No userinfo endpoint — profile from ID token
  defaultScopes: ['name', 'email'],
  mapProfile(raw: Record<string, unknown>): ProviderProfile {
    // Apple ID token claims + optional first-auth name object
    const nameObj = raw.name as { firstName?: string; lastName?: string } | undefined;
    const fullName = nameObj
      ? [nameObj.firstName, nameObj.lastName].filter(Boolean).join(' ')
      : undefined;

    return {
      id: String(raw.sub ?? ''),
      email: String(raw.email ?? ''),
      name: fullName || undefined,
      displayName: fullName || undefined,
      avatar: undefined, // Apple does not provide avatars
      raw,
    };
  },
};
