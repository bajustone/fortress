import type { ProviderDefinition, ProviderProfile } from '../types';

const TRAILING_SLASHES = /\/+$/;

/**
 * Factory for generic OIDC-compliant providers.
 * Uses standard OIDC discovery to resolve endpoints at runtime.
 */
export function createOidcProvider(
  name: string,
  issuerUrl: string,
): ProviderDefinition {
  // Strip trailing slash for consistent URL construction
  const issuer = issuerUrl.replace(TRAILING_SLASHES, '');

  return {
    name,
    discoveryUrl: `${issuer}/.well-known/openid-configuration`,
    // These are placeholders — the plugin should resolve actual URLs from discovery at runtime
    authorizationUrl: `${issuer}/authorize`,
    tokenUrl: `${issuer}/token`,
    userInfoUrl: `${issuer}/userinfo`,
    defaultScopes: ['openid', 'profile', 'email'],
    mapProfile(raw: Record<string, unknown>): ProviderProfile {
      return {
        id: String(raw.sub ?? ''),
        email: String(raw.email ?? ''),
        name: String(raw.name ?? ''),
        displayName: String(raw.preferred_username ?? raw.name ?? ''),
        avatar: raw.picture ? String(raw.picture) : undefined,
        raw,
      };
    },
  };
}
