import type { FortressPlugin } from '../../core/plugin';
import type { FortressUser } from '../../core/types';
import type { ProviderConfig, ProviderDefinition, ProviderProfile, SocialLoginConfig } from './types';
import { generateRefreshToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';
import { builtInProviders, createMicrosoftProvider } from './providers';
import { createOidcProvider } from './providers/oidc';

interface SocialAccountRecord {
  id: number;
  userId: number;
  provider: string;
  providerAccountId: string;
  email: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  tokenExpiresAt: string | null;
  profile: string | null;
  createdAt: string;
  updatedAt: string;
}

interface OAuthState {
  provider: string;
  codeVerifier: string;
  nonce: string;
}

/** Resolve built-in or custom OIDC provider definition from config */
function resolveProviderDefinition(providerConfig: ProviderConfig): ProviderDefinition {
  if (providerConfig.name === 'microsoft' && providerConfig.tenant) {
    return createMicrosoftProvider({ tenant: providerConfig.tenant });
  }

  if (providerConfig.issuer) {
    return createOidcProvider(providerConfig.name, providerConfig.issuer);
  }

  const builtIn = builtInProviders[providerConfig.name];
  if (builtIn)
    return builtIn;

  throw Errors.badRequest(`Unknown social login provider: ${providerConfig.name}. Provide an 'issuer' URL for custom OIDC providers.`);
}

/** Generate PKCE code verifier and S256 challenge */
async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const codeVerifier = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return { codeVerifier, codeChallenge };
}

export function socialLogin(config: SocialLoginConfig): FortressPlugin {
  const autoRegister = config.autoRegister ?? true;
  const linkAccounts = config.linkAccounts ?? true;

  // Pre-resolve all provider definitions
  const providerMap = new Map<string, { definition: ProviderDefinition; config: ProviderConfig }>();
  for (const pc of config.providers) {
    providerMap.set(pc.name, { definition: resolveProviderDefinition(pc), config: pc });
  }

  return {
    name: 'social-login',

    models: [{
      name: 'social_account',
      fields: {
        id: { type: 'number', required: true },
        userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
        provider: { type: 'string', required: true },
        providerAccountId: { type: 'string', required: true },
        email: { type: 'string' },
        accessToken: { type: 'string' },
        refreshToken: { type: 'string' },
        tokenExpiresAt: { type: 'date' },
        profile: { type: 'string' },
        createdAt: { type: 'date', required: true },
        updatedAt: { type: 'date', required: true },
      },
    }],

    methods: ctx => ({
      /**
       * Get the authorization URL to redirect the user to for a given provider.
       * Returns the URL and state that must be stored (e.g., in session) for callback verification.
       */
      async getAuthorizationUrl(
        providerName: string,
        redirectUri: string,
      ): Promise<{ url: string; state: OAuthState }> {
        const entry = providerMap.get(providerName);
        if (!entry)
          throw Errors.badRequest(`Provider '${providerName}' is not configured`);

        const { definition, config: pc } = entry;
        const { codeVerifier, codeChallenge } = await generatePKCE();
        const { raw: nonce } = await generateRefreshToken();

        const scopes = pc.scopes ?? definition.defaultScopes;

        const params = new URLSearchParams({
          client_id: pc.clientId,
          redirect_uri: redirectUri,
          response_type: 'code',
          scope: scopes.join(' '),
          state: nonce,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
        });

        const url = `${definition.authorizationUrl}?${params.toString()}`;
        const state: OAuthState = { provider: providerName, codeVerifier, nonce };

        return { url, state };
      },

      /**
       * Handle the OAuth callback. Exchanges the authorization code for tokens,
       * fetches the user profile, and performs JIT provisioning / account linking.
       *
       * Returns the Fortress user (existing or newly created) and the provider profile.
       */
      async handleCallback(
        providerName: string,
        code: string,
        redirectUri: string,
        codeVerifier: string,
      ): Promise<{ user: FortressUser; profile: ProviderProfile; isNewUser: boolean }> {
        const entry = providerMap.get(providerName);
        if (!entry)
          throw Errors.badRequest(`Provider '${providerName}' is not configured`);

        const { definition, config: pc } = entry;

        // Exchange code for tokens
        const tokenResponse = await fetch(definition.tokenUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            client_id: pc.clientId,
            client_secret: pc.clientSecret,
            code_verifier: codeVerifier,
          }),
        });

        if (!tokenResponse.ok) {
          throw Errors.unauthorized(`Failed to exchange authorization code with ${providerName}`);
        }

        const tokens = await tokenResponse.json() as {
          access_token: string;
          refresh_token?: string;
          expires_in?: number;
          id_token?: string;
        };

        // Fetch user profile
        let rawProfile: Record<string, unknown>;

        if (definition.userInfoUrl) {
          const profileResponse = await fetch(definition.userInfoUrl, {
            headers: { Authorization: `Bearer ${tokens.access_token}` },
          });

          if (!profileResponse.ok) {
            throw Errors.unauthorized(`Failed to fetch profile from ${providerName}`);
          }

          rawProfile = await profileResponse.json() as Record<string, unknown>;
        }
        else {
          // Apple-style: profile comes from ID token claims
          // For now, decode JWT payload without verification (consumer should verify)
          if (tokens.id_token) {
            const [, payload] = tokens.id_token.split('.');
            rawProfile = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
          }
          else {
            throw Errors.unauthorized(`Provider ${providerName} returned no profile data`);
          }
        }

        const profile = definition.mapProfile(rawProfile);

        // Validate email domain restriction
        if (pc.allowedDomains && pc.allowedDomains.length > 0) {
          const domain = profile.email.split('@')[1];
          if (!pc.allowedDomains.includes(domain)) {
            throw Errors.unauthorized(`Email domain '${domain}' is not allowed for ${providerName}`);
          }
        }

        // Look up existing social account
        const socialAccount = await ctx.db.findOne<SocialAccountRecord>({
          model: 'social_account',
          where: [
            { field: 'provider', operator: '=', value: providerName },
            { field: 'providerAccountId', operator: '=', value: profile.id },
          ],
        });

        let user: FortressUser | null = null;
        let isNewUser = false;

        if (socialAccount) {
          // Existing social account — update tokens and profile
          user = await ctx.db.findOne<FortressUser>({
            model: 'user',
            where: [{ field: 'id', operator: '=', value: socialAccount.userId }],
          });

          await ctx.db.update({
            model: 'social_account',
            where: [{ field: 'id', operator: '=', value: socialAccount.id }],
            data: {
              accessToken: tokens.access_token,
              refreshToken: tokens.refresh_token ?? socialAccount.refreshToken,
              tokenExpiresAt: tokens.expires_in
                ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
                : null,
              profile: JSON.stringify(profile.raw),
              email: profile.email,
              updatedAt: new Date().toISOString(),
            },
          });
        }
        else {
          // No social account — try linking by email
          if (linkAccounts && profile.email) {
            user = await ctx.db.findOne<FortressUser>({
              model: 'user',
              where: [{ field: 'email', operator: '=', value: profile.email }],
            });
          }

          if (!user) {
            // JIT provisioning
            if (!autoRegister) {
              throw Errors.unauthorized('Auto-registration is disabled');
            }

            const mapped = config.mapProfile
              ? config.mapProfile(providerName, profile)
              : null;
            const email = mapped?.email ?? profile.email;
            const name = mapped?.name ?? profile.name ?? profile.email;

            user = await ctx.db.create<FortressUser>({
              model: 'user',
              data: {
                email,
                name,
                passwordHash: null, // Social-only user
                isActive: true,
              },
            });

            isNewUser = true;

            if (config.onFirstLogin) {
              await config.onFirstLogin({ id: user.id }, providerName, profile);
            }
          }

          // Link social account to user
          await ctx.db.create({
            model: 'social_account',
            data: {
              userId: user.id,
              provider: providerName,
              providerAccountId: profile.id,
              email: profile.email,
              accessToken: tokens.access_token,
              refreshToken: tokens.refresh_token ?? null,
              tokenExpiresAt: tokens.expires_in
                ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
                : null,
              profile: JSON.stringify(profile.raw),
            },
          });
        }

        if (!user) {
          throw Errors.unauthorized('User account not found');
        }

        return { user, profile, isNewUser };
      },

      /**
       * List social accounts linked to a user.
       */
      async getLinkedAccounts(userId: number): Promise<{ provider: string; providerAccountId: string; email: string | null }[]> {
        const accounts = await ctx.db.findMany<SocialAccountRecord>({
          model: 'social_account',
          where: [{ field: 'userId', operator: '=', value: userId }],
        });

        return accounts.map(a => ({
          provider: a.provider,
          providerAccountId: a.providerAccountId,
          email: a.email,
        }));
      },

      /**
       * Unlink a social account from a user.
       */
      async unlinkAccount(userId: number, provider: string): Promise<void> {
        await ctx.db.delete({
          model: 'social_account',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'provider', operator: '=', value: provider },
          ],
        });
      },

      /** Get list of configured provider names */
      getProviders(): string[] {
        return Array.from(providerMap.keys());
      },
    }),
  };
}

export type { ProviderConfig, ProviderProfile, SocialLoginConfig } from './types';
