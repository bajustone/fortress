import type { ProviderDefinition, ProviderProfile } from '../types';

export function createMicrosoftProvider(options?: { tenant?: string }): ProviderDefinition {
  const tenant = options?.tenant ?? 'common';
  const base = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0`;

  return {
    name: 'microsoft',
    discoveryUrl: `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`,
    issuer: `https://login.microsoftonline.com/${tenant}/v2.0`,
    authorizationUrl: `${base}/authorize`,
    tokenUrl: `${base}/token`,
    userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
    defaultScopes: ['openid', 'profile', 'email', 'User.Read'],
    mapProfile(raw: Record<string, unknown>): ProviderProfile {
      return {
        id: String(raw.id ?? raw.sub ?? ''),
        email: String(raw.mail ?? raw.userPrincipalName ?? raw.email ?? ''),
        // Fail closed on an absent `email_verified` claim. Microsoft Graph `/me`
        // and many Entra id_tokens omit it; treating "absent" as verified would
        // let a Microsoft login auto-link by email to an existing account
        // (takeover). Match the other providers — absent ⇒ unverified ⇒ no
        // by-email auto-link. Tenants that trust their directory can opt back in
        // with a custom `mapProfile`.
        emailVerified: raw.email_verified === true || raw.email_verified === 'true',
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
