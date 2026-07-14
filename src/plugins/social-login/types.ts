// --- Social Login Provider Types ---

/** Normalized user profile returned by all providers */
export interface ProviderProfile {
  /** Provider's unique user ID */
  id: string;
  email: string;
  /** Whether the provider has verified ownership of `email`. */
  emailVerified: boolean;
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
  /** Expected issuer for ID tokens. Resolved from discovery when omitted. */
  issuer?: string;
  /** JWKS URI for ID token verification. Resolved from discovery when omitted. */
  jwksUri?: string;
  defaultScopes: string[];
  /** Maps the raw provider response to a normalized ProviderProfile */
  mapProfile: (raw: Record<string, unknown>) => ProviderProfile;
  /** Optional provider-specific profile fetcher (e.g. GitHub verified primary email). */
  fetchProfile?: (accessToken: string) => Promise<Record<string, unknown>>;
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
  /** Override discovered authorization endpoint for custom OIDC providers. */
  authorizationUrl?: string;
  /** Override discovered token endpoint for custom OIDC providers. */
  tokenUrl?: string;
  /** Override discovered userinfo endpoint for custom OIDC providers. */
  userInfoUrl?: string;
  /** Override discovered JWKS endpoint for custom OIDC providers. */
  jwksUri?: string;
  /** Apple Sign In: team ID used to generate the ES256 client-secret JWT. */
  teamId?: string;
  /** Apple Sign In: key ID used to generate the ES256 client-secret JWT. */
  keyId?: string;
  /** Apple Sign In: PKCS#8 private key used to generate the ES256 client-secret JWT. */
  privateKey?: string;
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
  onFirstLogin?: (user: { id: string }, provider: string, profile: ProviderProfile) => Promise<void>;
  /** Persist encrypted provider access/refresh tokens. Default: false (explicit opt-in). */
  persistTokens?: boolean;
  /** 32-byte AES-256-GCM key (raw bytes as base64/base64url/hex, or a UTF-8 string of at least 32 bytes). */
  tokenEncryptionKey?: string;
}
