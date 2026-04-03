import type { ProviderDefinition, ProviderProfile } from '../types';

export const discordProvider: ProviderDefinition = {
  name: 'discord',
  authorizationUrl: 'https://discord.com/api/oauth2/authorize',
  tokenUrl: 'https://discord.com/api/oauth2/token',
  userInfoUrl: 'https://discord.com/api/users/@me',
  defaultScopes: ['identify', 'email'],
  mapProfile(raw: Record<string, unknown>): ProviderProfile {
    const id = String(raw.id ?? '');
    const avatarHash = raw.avatar ? String(raw.avatar) : null;
    const avatar = avatarHash
      ? `https://cdn.discordapp.com/avatars/${id}/${avatarHash}.png`
      : undefined;

    return {
      id,
      email: String(raw.email ?? ''),
      name: String(raw.username ?? ''),
      displayName: String(raw.global_name ?? raw.username ?? ''),
      avatar,
      raw,
    };
  },
};
