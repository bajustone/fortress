import { describe, expect, it } from 'vitest';
import { appleProvider } from './apple';
import { discordProvider } from './discord';
import { githubProvider } from './github';
import { googleProvider } from './google';
import { builtInProviders } from './index';
import { createMicrosoftProvider } from './microsoft';
import { createOidcProvider } from './oidc';

describe('microsoft provider', () => {
  const provider = createMicrosoftProvider({ tenant: 'my-tenant' });

  it('interpolates tenant into URLs', () => {
    expect(provider.authorizationUrl).toContain('my-tenant');
    expect(provider.tokenUrl).toContain('my-tenant');
    expect(provider.discoveryUrl).toContain('my-tenant');
  });

  it('defaults to common tenant', () => {
    const common = createMicrosoftProvider();
    expect(common.authorizationUrl).toContain('common');
  });

  it('maps Graph API profile', () => {
    const profile = provider.mapProfile({
      id: 'ms-user-123',
      mail: 'alice@contoso.com',
      displayName: 'Alice Smith',
      givenName: 'Alice',
      surname: 'Smith',
    });

    expect(profile.id).toBe('ms-user-123');
    expect(profile.email).toBe('alice@contoso.com');
    expect(profile.name).toBe('Alice Smith');
    expect(profile.displayName).toBe('Alice Smith');
  });

  it('falls back to userPrincipalName for email', () => {
    const profile = provider.mapProfile({
      id: 'ms-user-456',
      userPrincipalName: 'bob@contoso.com',
      displayName: 'Bob',
    });

    expect(profile.email).toBe('bob@contoso.com');
  });
});

describe('google provider', () => {
  it('maps OIDC claims', () => {
    const profile = googleProvider.mapProfile({
      sub: '1234567890',
      email: 'alice@gmail.com',
      name: 'Alice Smith',
      picture: 'https://lh3.googleusercontent.com/photo.jpg',
    });

    expect(profile.id).toBe('1234567890');
    expect(profile.email).toBe('alice@gmail.com');
    expect(profile.name).toBe('Alice Smith');
    expect(profile.avatar).toBe('https://lh3.googleusercontent.com/photo.jpg');
  });

  it('handles missing picture', () => {
    const profile = googleProvider.mapProfile({
      sub: '123',
      email: 'bob@gmail.com',
      name: 'Bob',
    });

    expect(profile.avatar).toBeUndefined();
  });
});

describe('github provider', () => {
  it('has no discovery URL (not OIDC)', () => {
    expect(githubProvider.discoveryUrl).toBeUndefined();
  });

  it('maps GitHub profile with numeric ID', () => {
    const profile = githubProvider.mapProfile({
      id: 12345,
      login: 'octocat',
      name: 'The Octocat',
      email: 'octocat@github.com',
      avatar_url: 'https://avatars.githubusercontent.com/u/12345',
    });

    expect(profile.id).toBe('12345');
    expect(profile.email).toBe('octocat@github.com');
    expect(profile.name).toBe('The Octocat');
    expect(profile.avatar).toBe('https://avatars.githubusercontent.com/u/12345');
  });

  it('falls back to login when name is missing', () => {
    const profile = githubProvider.mapProfile({
      id: 99,
      login: 'anonymous',
      email: 'anon@example.com',
    });

    expect(profile.name).toBe('anonymous');
    expect(profile.displayName).toBe('anonymous');
  });
});

describe('apple provider', () => {
  it('has no userInfoUrl', () => {
    expect(appleProvider.userInfoUrl).toBeUndefined();
  });

  it('maps ID token claims with name object', () => {
    const profile = appleProvider.mapProfile({
      sub: 'apple-user-001',
      email: 'alice@icloud.com',
      name: { firstName: 'Alice', lastName: 'Smith' },
    });

    expect(profile.id).toBe('apple-user-001');
    expect(profile.email).toBe('alice@icloud.com');
    expect(profile.name).toBe('Alice Smith');
    expect(profile.avatar).toBeUndefined();
  });

  it('handles missing name (subsequent logins)', () => {
    const profile = appleProvider.mapProfile({
      sub: 'apple-user-001',
      email: 'alice@icloud.com',
    });

    expect(profile.name).toBeUndefined();
  });
});

describe('discord provider', () => {
  it('constructs avatar CDN URL', () => {
    const profile = discordProvider.mapProfile({
      id: '80351110224678912',
      username: 'Nelly',
      global_name: 'Nelly Rose',
      email: 'nelly@example.com',
      avatar: 'a_d5efa99b3eeaa7dd43acca82f5692432',
    });

    expect(profile.id).toBe('80351110224678912');
    expect(profile.displayName).toBe('Nelly Rose');
    expect(profile.avatar).toBe(
      'https://cdn.discordapp.com/avatars/80351110224678912/a_d5efa99b3eeaa7dd43acca82f5692432.png',
    );
  });

  it('handles missing avatar', () => {
    const profile = discordProvider.mapProfile({
      id: '123',
      username: 'NoAvatar',
      email: 'test@example.com',
    });

    expect(profile.avatar).toBeUndefined();
  });
});

describe('generic OIDC provider', () => {
  const provider = createOidcProvider('corporate-sso', 'https://sso.company.com');

  it('constructs discovery URL from issuer', () => {
    expect(provider.discoveryUrl).toBe('https://sso.company.com/.well-known/openid-configuration');
  });

  it('strips trailing slashes from issuer', () => {
    const p = createOidcProvider('test', 'https://sso.example.com/');
    expect(p.discoveryUrl).toBe('https://sso.example.com/.well-known/openid-configuration');
  });

  it('maps standard OIDC claims', () => {
    const profile = provider.mapProfile({
      sub: 'emp-789',
      email: 'jane@company.com',
      name: 'Jane Doe',
      preferred_username: 'jdoe',
      picture: 'https://sso.company.com/photos/jdoe.jpg',
    });

    expect(profile.id).toBe('emp-789');
    expect(profile.email).toBe('jane@company.com');
    expect(profile.displayName).toBe('jdoe');
    expect(profile.avatar).toBe('https://sso.company.com/photos/jdoe.jpg');
  });
});

describe('builtInProviders registry', () => {
  it('contains all 5 built-in providers', () => {
    expect(Object.keys(builtInProviders)).toEqual(
      expect.arrayContaining(['microsoft', 'google', 'github', 'apple', 'discord']),
    );
    expect(Object.keys(builtInProviders)).toHaveLength(5);
  });
});
