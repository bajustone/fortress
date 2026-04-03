// --- Social Login Provider Types ---

/** Normalized user profile returned by all providers */
export interface ProviderProfile {
  /** Provider's unique user ID */
  id: string;
  email: string;
  name?: string;
  displayName?: string;
  avatar?: string;
  /** Full raw response from the provider (for custom mapping) */
  raw: Record<string, unknown>;
}

/** Pre-configured provider definition with OAuth/OIDC endpoints and profile mapping */
export interface ProviderDefinition {
  name: string;
  /** OIDC discovery URL (.well-known/openid-configuration). Undefined for non-OIDC providers (e.g., GitHub). */
  discoveryUrl?: string;
  authorizationUrl: string;
  tokenUrl: string;
  /** User info endpoint. Undefined for Apple (profile comes from ID token only). */
  userInfoUrl?: string;
  defaultScopes: string[];
  /** Maps the raw provider response to a normalized ProviderProfile */
  mapProfile: (raw: Record<string, unknown>) => ProviderProfile;
}

/** User-facing config for a single provider (passed to socialLogin plugin) */
export interface ProviderConfig {
  name: string;
  clientId: string;
  clientSecret: string;
  scopes?: string[];
  /** Microsoft: tenant ID, 'common', or 'organizations' */
  tenant?: string;
  /** Restrict registration to specific email domains */
  allowedDomains?: string[];
  /** Generic OIDC: issuer URL for discovery */
  issuer?: string;
}

/** Plugin-level config for the social login plugin */
export interface SocialLoginConfig {
  providers: ProviderConfig[];
  /** Auto-create user on first social login (default: true) */
  autoRegister?: boolean;
  /** Link social identity to existing user by email (default: true) */
  linkAccounts?: boolean;
  /** Map provider profile fields to Fortress user fields */
  mapProfile?: (provider: string, profile: ProviderProfile) => { email: string; name: string };
  /** Called on first-ever login for a social user */
  onFirstLogin?: (user: { id: number }, provider: string, profile: ProviderProfile) => Promise<void>;
}
