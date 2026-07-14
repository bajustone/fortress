/**
 * Social login (OAuth/OIDC consumer) plugin for fortress.
 *
 * Supports Microsoft, Google, GitHub, Discord, Apple, and any generic OIDC
 * provider. Handles the authorization-code flow, exchanges tokens, links
 * provider accounts to fortress users, and issues fortress refresh tokens
 * on success.
 *
 * @module
 */

import type { JWTPayload } from 'jose';
import type { FortressPlugin } from '../../core/plugin';
import type { FortressUser } from '../../core/types';
import type { ProviderConfig, ProviderDefinition, ProviderProfile, SocialLoginConfig } from './types';
import { object, string } from '@bajustone/fetcher/schema';
import { createRemoteJWKSet, importPKCS8, jwtVerify, SignJWT } from 'jose';
import { normalizeEmail } from '../../core/auth/email';
import { Errors } from '../../core/errors';
import { outboundClient } from '../../core/http/outbound';
import { builtInProviders, createMicrosoftProvider } from './providers';
import { createOidcProvider } from './providers/oidc';

/** Response shape guard — the upstream returned a JSON object (not array/null/scalar). */
const jsonObjectSchema = object({});
/** OAuth token response: `access_token` must be a present string; other fields pass through. */
const tokenResponseSchema = object({ access_token: string() });

interface SocialAccountRecord {
  id: string;
  userId: string;
  provider: string;
  providerAccountId: string;
  email: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  tokenExpiresAt: Date | null;
  profile: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface ResolvedProviderDefinition extends ProviderDefinition {
  issuer?: string;
  jwksUri?: string;
}

const encoder = new TextEncoder();
const HEX_32_BYTE_KEY = /^[0-9a-f]+$/i;
const discoveryCache = new Map<string, Promise<ResolvedProviderDefinition>>();
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
const appleSecretCache = new Map<string, { value: string; expiresAt: number }>();

function randomBase64Url(bytes = 32): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function timingSafeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const len = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < len; i++)
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}

function decodeKeyMaterial(key: string): Uint8Array {
  const trimmed = key.trim();
  if (HEX_32_BYTE_KEY.test(trimmed) && trimmed.length === 64) {
    return new Uint8Array(trimmed.match(/.{2}/g)!.map(byte => Number.parseInt(byte, 16)));
  }
  try {
    const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const raw = atob(padded);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++)
      bytes[i] = raw.charCodeAt(i);
    if (bytes.length >= 32)
      return bytes;
  }
  catch {
    // Fall through to UTF-8.
  }
  return encoder.encode(key);
}

async function importTokenEncryptionKey(key: string): Promise<CryptoKey> {
  const bytes = decodeKeyMaterial(key);
  if (bytes.length !== 32) {
    throw Errors.badRequest('socialLogin tokenEncryptionKey must decode to exactly 32 bytes for AES-256-GCM');
  }
  const raw = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encryptToken(keyPromise: Promise<CryptoKey> | null, value: string | undefined | null): Promise<string | null> {
  if (!value)
    return null;
  if (!keyPromise)
    throw Errors.badRequest('socialLogin token persistence requires tokenEncryptionKey');
  const key = await keyPromise;
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(value)));
  return `v1.${base64UrlFromBytes(iv)}.${base64UrlFromBytes(ciphertext)}`;
}

async function decryptToken(keyPromise: Promise<CryptoKey> | null, value: string | undefined | null): Promise<string | null> {
  if (!value)
    return null;
  if (!keyPromise)
    throw Errors.badRequest('socialLogin token persistence requires tokenEncryptionKey');
  const [version, ivEncoded, ciphertextEncoded] = value.split('.');
  if (version !== 'v1' || !ivEncoded || !ciphertextEncoded)
    throw Errors.badRequest('Invalid encrypted social-login token format');
  const key = await keyPromise;
  const iv = base64UrlToBytes(ivEncoded);
  const ciphertext = base64UrlToBytes(ciphertextEncoded);
  const ivBuffer = iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer;
  const ciphertextBuffer = ciphertext.buffer.slice(ciphertext.byteOffset, ciphertext.byteOffset + ciphertext.byteLength) as ArrayBuffer;
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBuffer }, key, ciphertextBuffer);
  return new TextDecoder().decode(plaintext);
}

function base64UrlFromBytes(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++)
    bytes[i] = raw.charCodeAt(i);
  return bytes;
}

/** Resolve built-in or custom OIDC provider definition from config */
function resolveProviderDefinition(providerConfig: ProviderConfig): ProviderDefinition {
  if (providerConfig.name === 'microsoft' && providerConfig.tenant) {
    return createMicrosoftProvider({ tenant: providerConfig.tenant });
  }

  if (providerConfig.issuer) {
    const base = createOidcProvider(providerConfig.name, providerConfig.issuer);
    return {
      ...base,
      authorizationUrl: providerConfig.authorizationUrl ?? base.authorizationUrl,
      tokenUrl: providerConfig.tokenUrl ?? base.tokenUrl,
      userInfoUrl: providerConfig.userInfoUrl ?? base.userInfoUrl,
      jwksUri: providerConfig.jwksUri,
    };
  }

  const builtIn = builtInProviders[providerConfig.name];
  if (builtIn)
    return builtIn;

  throw Errors.badRequest(`Unknown social login provider: ${providerConfig.name}. Provide an 'issuer' URL for custom OIDC providers.`);
}

async function resolveDiscoveredDefinition(definition: ProviderDefinition, providerConfig: ProviderConfig): Promise<ResolvedProviderDefinition> {
  if (!definition.discoveryUrl || (definition.issuer && definition.jwksUri && !providerConfig.issuer)) {
    return definition;
  }

  const cacheKey = `${providerConfig.name}:${definition.discoveryUrl}`;
  let cached = discoveryCache.get(cacheKey);
  if (!cached) {
    cached = (async () => {
      const res = await outboundClient.get(definition.discoveryUrl!, { responseSchema: jsonObjectSchema }).result();
      // Degrade to the static definition on non-2xx, timeout, network failure,
      // or a non-object body — same fallback the bare fetch had, now also
      // covering hangs (native fetch had no timeout).
      if (!res.ok)
        return definition;
      const discovered = res.data as Record<string, unknown>;
      return {
        ...definition,
        issuer: String(discovered.issuer ?? definition.issuer ?? providerConfig.issuer ?? ''),
        authorizationUrl: providerConfig.authorizationUrl ?? String(discovered.authorization_endpoint ?? definition.authorizationUrl),
        tokenUrl: providerConfig.tokenUrl ?? String(discovered.token_endpoint ?? definition.tokenUrl),
        userInfoUrl: providerConfig.userInfoUrl ?? (discovered.userinfo_endpoint ? String(discovered.userinfo_endpoint) : definition.userInfoUrl),
        jwksUri: providerConfig.jwksUri ?? String(discovered.jwks_uri ?? definition.jwksUri ?? ''),
      };
    })();
    discoveryCache.set(cacheKey, cached);
  }
  return cached;
}

async function verifyIdToken(
  definition: ResolvedProviderDefinition,
  providerConfig: ProviderConfig,
  idToken: string | undefined,
  nonce: string,
): Promise<JWTPayload | null> {
  const shouldVerify = Boolean(definition.discoveryUrl || definition.jwksUri || idToken);
  if (!shouldVerify)
    return null;
  if (!idToken)
    throw Errors.unauthorized(`Provider ${providerConfig.name} did not return an ID token`);
  if (!definition.jwksUri)
    throw Errors.unauthorized(`Provider ${providerConfig.name} has no JWKS URI for ID token verification`);
  if (!definition.issuer)
    throw Errors.unauthorized(`Provider ${providerConfig.name} has no issuer for ID token verification`);
  if (!nonce)
    throw Errors.unauthorized(`Missing stored OIDC nonce for ${providerConfig.name}`);

  let jwks = jwksCache.get(definition.jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(definition.jwksUri));
    jwksCache.set(definition.jwksUri, jwks);
  }

  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: definition.issuer,
    audience: providerConfig.clientId,
  }).catch(() => {
    throw Errors.unauthorized(`Invalid ID token from ${providerConfig.name}`);
  });

  if (payload.nonce !== nonce)
    throw Errors.unauthorized(`Invalid ID token nonce from ${providerConfig.name}`);
  return payload;
}

async function buildClientSecret(providerConfig: ProviderConfig, definition: ProviderDefinition): Promise<string> {
  if (providerConfig.name !== 'apple' || !providerConfig.privateKey)
    return providerConfig.clientSecret;
  if (!providerConfig.teamId || !providerConfig.keyId)
    throw Errors.badRequest('Apple social login requires teamId, keyId, and privateKey');

  const cacheKey = `${providerConfig.teamId}:${providerConfig.clientId}:${providerConfig.keyId}`;
  const cached = appleSecretCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60_000)
    return cached.value;

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 60 * 60;
  const key = await importPKCS8(providerConfig.privateKey, 'ES256');
  const issuer = definition.issuer ?? 'https://appleid.apple.com';
  const value = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: providerConfig.keyId })
    .setIssuer(providerConfig.teamId)
    .setSubject(providerConfig.clientId)
    .setAudience(issuer)
    .setIssuedAt(now)
    .setExpirationTime(expiresAt)
    .sign(key);
  appleSecretCache.set(cacheKey, { value, expiresAt: expiresAt * 1000 });
  return value;
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

export interface SocialLoginMethods {
  getAuthorizationUrl: (providerName: string, redirectUri: string) => Promise<{ url: string; state: string; codeVerifier: string; nonce: string }>;
  handleCallback: (providerName: string, code: string, redirectUri: string, codeVerifier: string, returnedState: string, storedState: string, storedNonce: string) => Promise<{ user: FortressUser; profile: ProviderProfile; isNewUser: boolean }>;
  getLinkedAccounts: (userId: string) => Promise<{ provider: string; providerAccountId: string; email: string | null }[]>;
  getProviderTokens: (userId: string, provider: string) => Promise<{ accessToken: string | null; refreshToken: string | null; tokenExpiresAt: Date | null }>;
  unlinkAccount: (userId: string, provider: string) => Promise<void>;
  getProviders: () => string[];
}
/**
 * Social login plugin factory. Returns a {@link FortressPlugin} that handles
 * the OAuth/OIDC authorization-code flow against the configured providers,
 * links provider accounts to fortress users, and issues fortress tokens.
 */
export function socialLogin(config: SocialLoginConfig): FortressPlugin & { readonly name: 'social-login' } {
  const autoRegister = config.autoRegister ?? true;
  const linkAccounts = config.linkAccounts ?? true;
  // Default OFF: persisting provider tokens requires an explicit
  // 32-byte AES-256-GCM key, so we don't silently store them at rest.
  // Consumers that want server-side refresh-token storage opt in by
  // setting `persistTokens: true` and supplying `tokenEncryptionKey`.
  const persistTokens = config.persistTokens ?? false;
  if (persistTokens && !config.tokenEncryptionKey)
    throw Errors.badRequest('socialLogin requires tokenEncryptionKey when persistTokens is enabled');
  if (persistTokens && config.tokenEncryptionKey && decodeKeyMaterial(config.tokenEncryptionKey).length !== 32)
    throw Errors.badRequest('socialLogin tokenEncryptionKey must decode to exactly 32 bytes for AES-256-GCM');
  const tokenEncryptionKey = persistTokens && config.tokenEncryptionKey
    ? importTokenEncryptionKey(config.tokenEncryptionKey)
    : null;

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
      constraints: [
        { type: 'unique', fields: ['userId', 'provider'] },
        { type: 'unique', fields: ['provider', 'providerAccountId'] },
      ],
    }],

    methods: ctx => ({
      /**
       * Get the authorization URL to redirect the user to for a given provider.
       * Returns the URL and state that must be stored (e.g., in session) for callback verification.
       */
      async getAuthorizationUrl(
        providerName: string,
        redirectUri: string,
      ): Promise<{ url: string; state: string; codeVerifier: string; nonce: string }> {
        const entry = providerMap.get(providerName);
        if (!entry)
          throw Errors.badRequest(`Provider '${providerName}' is not configured`);

        const { definition, config: pc } = entry;
        const resolvedDefinition = await resolveDiscoveredDefinition(definition, pc);
        const { codeVerifier, codeChallenge } = await generatePKCE();
        const state = randomBase64Url();
        const nonce = randomBase64Url();

        const scopes = pc.scopes ?? resolvedDefinition.defaultScopes;

        const params = new URLSearchParams({
          client_id: pc.clientId,
          redirect_uri: redirectUri,
          response_type: 'code',
          scope: scopes.join(' '),
          state,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
        });
        if (scopes.includes('openid') || resolvedDefinition.discoveryUrl)
          params.set('nonce', nonce);

        const url = `${resolvedDefinition.authorizationUrl}?${params.toString()}`;

        return { url, state, codeVerifier, nonce };
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
        returnedState: string,
        storedState: string,
        storedNonce: string,
      ): Promise<{ user: FortressUser; profile: ProviderProfile; isNewUser: boolean }> {
        if (!returnedState || !storedState || !timingSafeEqual(returnedState, storedState))
          throw Errors.unauthorized('Invalid OAuth state');

        const entry = providerMap.get(providerName);
        if (!entry)
          throw Errors.badRequest(`Provider '${providerName}' is not configured`);

        const { definition, config: pc } = entry;
        const resolvedDefinition = await resolveDiscoveredDefinition(definition, pc);
        const clientSecret = await buildClientSecret(pc, resolvedDefinition);

        // Exchange code for tokens. POST is never retried (RFC 9110); the
        // shared client adds a timeout and validates `access_token` is present.
        const tokenRes = await outboundClient.post(resolvedDefinition.tokenUrl, {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            client_id: pc.clientId,
            client_secret: clientSecret,
            code_verifier: codeVerifier,
          }),
          responseSchema: tokenResponseSchema,
        }).result();

        if (!tokenRes.ok) {
          throw Errors.unauthorized(`Failed to exchange authorization code with ${providerName}`);
        }

        const tokens = tokenRes.data as {
          access_token: string;
          refresh_token?: string;
          expires_in?: number;
          id_token?: string;
        };

        const idTokenClaims = await verifyIdToken(resolvedDefinition, pc, tokens.id_token, storedNonce);

        // Fetch user profile. OIDC ID-token claims are merged with userinfo so
        // `sub`, `email_verified`, and provider-specific claims are preserved.
        let rawProfile: Record<string, unknown>;

        if (resolvedDefinition.fetchProfile) {
          rawProfile = await resolvedDefinition.fetchProfile(tokens.access_token).catch(() => {
            throw Errors.unauthorized(`Failed to fetch profile from ${providerName}`);
          });
        }
        else if (resolvedDefinition.userInfoUrl) {
          const profileRes = await outboundClient.get(resolvedDefinition.userInfoUrl, {
            headers: { Authorization: `Bearer ${tokens.access_token}` },
            responseSchema: jsonObjectSchema,
          }).result();

          if (!profileRes.ok) {
            throw Errors.unauthorized(`Failed to fetch profile from ${providerName}`);
          }

          rawProfile = profileRes.data as Record<string, unknown>;
        }
        else if (idTokenClaims) {
          rawProfile = { ...idTokenClaims };
        }
        else {
          throw Errors.unauthorized(`Provider ${providerName} returned no profile data`);
        }

        if (idTokenClaims)
          rawProfile = { ...idTokenClaims, ...rawProfile };

        const profile = resolvedDefinition.mapProfile(rawProfile);
        if (!profile.id)
          throw Errors.unauthorized(`Provider ${providerName} returned no subject`);
        const canonicalProfileEmail = normalizeEmail(profile.email);

        // Validate email domain restriction case-insensitively.
        if (pc.allowedDomains && pc.allowedDomains.length > 0) {
          const domain = canonicalProfileEmail.split('@')[1];
          const allowedDomains = pc.allowedDomains.map(value => value.normalize('NFC').toLowerCase());
          if (!domain || !allowedDomains.includes(domain)) {
            throw Errors.unauthorized(`Email domain '${domain ?? ''}' is not allowed for ${providerName}`);
          }
        }

        return ctx.db.transaction(async (tx) => {
          const encryptedAccessToken = persistTokens ? await encryptToken(tokenEncryptionKey, tokens.access_token) : null;
          const encryptedRefreshToken = persistTokens ? await encryptToken(tokenEncryptionKey, tokens.refresh_token) : null;

          // Look up existing social account
          const socialAccount = await tx.findOne<SocialAccountRecord>({
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
            user = await tx.findOne<FortressUser>({
              model: 'user',
              where: [{ field: 'id', operator: '=', value: socialAccount.userId }],
            });
            if (!user || !user.isActive)
              throw Errors.unauthorized('User account not found or disabled');

            await tx.update({
              model: 'social_account',
              where: [{ field: 'id', operator: '=', value: socialAccount.id }],
              data: {
                accessToken: encryptedAccessToken,
                refreshToken: encryptedRefreshToken ?? socialAccount.refreshToken,
                tokenExpiresAt: tokens.expires_in
                  ? new Date(Date.now() + tokens.expires_in * 1000)
                  : null,
                profile: JSON.stringify(profile.raw),
                email: canonicalProfileEmail,
                updatedAt: new Date(),
              },
            });
          }
          else {
            // No social account — try linking by verified email only.
            if (linkAccounts && canonicalProfileEmail && profile.emailVerified) {
              user = await tx.findOne<FortressUser>({
                model: 'user',
                where: [{ field: 'email', operator: '=', value: canonicalProfileEmail }],
              });
              if (user && !user.isActive)
                throw Errors.unauthorized('User account not found or disabled');
            }

            if (!user) {
              // JIT provisioning
              if (!autoRegister) {
                throw Errors.unauthorized('Auto-registration is disabled');
              }

              const mapped = config.mapProfile
                ? config.mapProfile(providerName, profile)
                : null;
              const email = normalizeEmail(mapped?.email ?? canonicalProfileEmail);
              const name = mapped?.name ?? profile.name ?? profile.email;

              user = await tx.create<FortressUser>({
                model: 'user',
                data: {
                  email,
                  name,
                  passwordHash: null, // Social-only user
                  isActive: true,
                  emailVerified: profile.emailVerified,
                },
              });

              isNewUser = true;

              if (config.onFirstLogin) {
                await config.onFirstLogin({ id: user.id }, providerName, profile);
              }
            }

            // Link social account to user
            await tx.create({
              model: 'social_account',
              data: {
                userId: user.id,
                provider: providerName,
                providerAccountId: profile.id,
                email: canonicalProfileEmail,
                accessToken: encryptedAccessToken,
                refreshToken: encryptedRefreshToken,
                tokenExpiresAt: tokens.expires_in
                  ? new Date(Date.now() + tokens.expires_in * 1000)
                  : null,
                profile: JSON.stringify(profile.raw),
              },
            });
          }

          return { user, profile, isNewUser };
        });
      },

      /**
       * List social accounts linked to a user.
       */
      async getLinkedAccounts(userId: string): Promise<{ provider: string; providerAccountId: string; email: string | null }[]> {
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
       * Return decrypted provider tokens for a linked account.
       */
      async getProviderTokens(userId: string, provider: string): Promise<{ accessToken: string | null; refreshToken: string | null; tokenExpiresAt: Date | null }> {
        const account = await ctx.db.findOne<SocialAccountRecord>({
          model: 'social_account',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'provider', operator: '=', value: provider },
          ],
        });
        if (!account)
          throw Errors.notFound('Linked social account not found');
        return {
          accessToken: await decryptToken(tokenEncryptionKey, account.accessToken),
          refreshToken: await decryptToken(tokenEncryptionKey, account.refreshToken),
          tokenExpiresAt: account.tokenExpiresAt,
        };
      },

      /**
       * Unlink a social account from a user.
       */
      async unlinkAccount(userId: string, provider: string): Promise<void> {
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
