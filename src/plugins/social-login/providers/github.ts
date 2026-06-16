import type { ProviderDefinition, ProviderProfile } from '../types';
import { array, object } from '@bajustone/fetcher/schema';
import { outboundClient } from '../../../core/http/outbound';

/** GitHub `/user` must be a JSON object; `/user/emails` an array of objects. */
const userSchema = object({});
const emailsSchema = array(object({}));

/** GitHub uses custom OAuth2, not OIDC — no discovery URL */
export const githubProvider: ProviderDefinition = {
  name: 'github',
  authorizationUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userInfoUrl: 'https://api.github.com/user',
  defaultScopes: ['read:user', 'user:email'],
  async fetchProfile(accessToken: string): Promise<Record<string, unknown>> {
    // Shared outbound client adds a timeout + validates the response shape.
    const userRes = await outboundClient.get('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
      responseSchema: userSchema,
    }).result();
    if (!userRes.ok)
      throw new Error('Failed to fetch GitHub profile');
    const user = userRes.data as Record<string, unknown>;

    if (!user.email) {
      const emailsRes = await outboundClient.get('https://api.github.com/user/emails', {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
        responseSchema: emailsSchema,
      }).result();
      if (emailsRes.ok) {
        const emails = emailsRes.data as Array<Record<string, unknown>>;
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
