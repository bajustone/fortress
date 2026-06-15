import type { ProviderDefinition, ProviderProfile } from '../types';

/** GitHub uses custom OAuth2, not OIDC — no discovery URL */
export const githubProvider: ProviderDefinition = {
  name: 'github',
  authorizationUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userInfoUrl: 'https://api.github.com/user',
  defaultScopes: ['read:user', 'user:email'],
  async fetchProfile(accessToken: string): Promise<Record<string, unknown>> {
    const userResponse = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
    });
    if (!userResponse.ok)
      throw new Error('Failed to fetch GitHub profile');
    const user = await userResponse.json() as Record<string, unknown>;

    if (!user.email) {
      const emailsResponse = await fetch('https://api.github.com/user/emails', {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
      });
      if (emailsResponse.ok) {
        const emails = await emailsResponse.json() as Array<Record<string, unknown>>;
        const primary = emails.find(e => e.primary === true) ?? emails.find(e => e.verified === true);
        if (primary) {
          user.email = primary.email;
          user.email_verified = primary.verified === true;
        }
      }
    }

    return user;
  },
  mapProfile(raw: Record<string, unknown>): ProviderProfile {
    return {
      id: String(raw.id ?? ''),
      email: String(raw.email ?? ''),
      emailVerified: raw.email_verified === true || raw.verified === true,
      name: String(raw.name ?? raw.login ?? ''),
      displayName: String(raw.name ?? raw.login ?? ''),
      avatar: raw.avatar_url ? String(raw.avatar_url) : undefined,
      raw,
    };
  },
};
