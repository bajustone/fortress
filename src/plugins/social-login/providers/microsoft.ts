import type { ProviderDefinition, ProviderProfile } from '../types';

export function createMicrosoftProvider(options?: { tenant?: string }): ProviderDefinition {
  const tenant = options?.tenant ?? 'common';
  const base = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0`;

  return {
    name: 'microsoft',
    discoveryUrl: `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`,
    authorizationUrl: `${base}/authorize`,
    tokenUrl: `${base}/token`,
    userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
    defaultScopes: ['openid', 'profile', 'email', 'User.Read'],
    mapProfile(raw: Record<string, unknown>): ProviderProfile {
      return {
        id: String(raw.id ?? raw.sub ?? ''),
        email: String(raw.mail ?? raw.userPrincipalName ?? raw.email ?? ''),
        name: raw.givenName && raw.surname
          ? `${raw.givenName} ${raw.surname}`
          : String(raw.name ?? raw.displayName ?? ''),
        displayName: String(raw.displayName ?? raw.name ?? ''),
        avatar: undefined, // Microsoft Graph requires separate photo endpoint
        raw,
      };
    },
  };
}
