import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressConfig, PasswordHasher } from '../config';
import type {
  AfterHookContext,
  FortressPlugin,
  HookContext,
  HookResult,
} from '../plugin';
import type {
  AuthResponse,
  AuthTokenPair,
  CreateUserInput,
  FortressUser,
  LoginIdentifier,
  LoginIdentifierType,
  RequestMeta,
  TokenClaims,
} from '../types';
import { Errors } from '../errors';
import { signAccessToken, verifyAccessToken } from './jwt';
import { createDefaultHasher } from './password';
import { generateRefreshToken, generateTokenFamily, hashToken } from './refresh-token';

interface ResolvedConfig {
  secret: string | string[];
  issuer: string;
  accessTokenExpiry: number;
  refreshTokenExpiry: number;
}

function resolveConfig(config: FortressConfig): ResolvedConfig {
  return {
    secret: config.jwt.secret,
    issuer: config.jwt.issuer ?? 'fortress',
    accessTokenExpiry: config.jwt.accessTokenExpirySeconds ?? 900,
    refreshTokenExpiry: config.jwt.refreshTokenExpirySeconds ?? 604800,
  };
}

export interface AuthService {
  login: (identifier: string, password: string, meta?: RequestMeta) => Promise<AuthResponse>;
  refresh: (refreshToken: string, meta?: RequestMeta) => Promise<AuthTokenPair>;
  logout: (refreshToken: string) => Promise<void>;
  me: (userId: number) => Promise<FortressUser>;
  createUser: (data: CreateUserInput) => Promise<FortressUser>;
  verifyToken: (token: string) => Promise<TokenClaims>;
  signToken: (claims: Omit<TokenClaims, 'iat' | 'exp'>) => Promise<string>;
  addLoginIdentifier: (userId: number, type: LoginIdentifierType, value: string) => Promise<void>;
  removeLoginIdentifier: (userId: number, type: LoginIdentifierType, value: string) => Promise<void>;
  getLoginIdentifiers: (userId: number) => Promise<LoginIdentifier[]>;
}

export function createAuthService(
  db: DatabaseAdapter,
  config: FortressConfig,
  plugins: FortressPlugin[] = [],
): AuthService {
  const resolved = resolveConfig(config);
  const hasher: PasswordHasher = config.passwordHasher ?? createDefaultHasher();

  async function runBeforeHooks<T extends Record<string, unknown>>(
    hookName: 'beforeLogin' | 'beforeRegister' | 'beforeTokenRefresh' | 'beforeLogout',
    ctx: HookContext & T,
  ): Promise<HookResult | void> {
    for (const plugin of plugins) {
      const hook = plugin.hooks?.[hookName] as ((ctx: HookContext & T) => Promise<HookResult | void>) | undefined;
      if (hook) {
        const result = await hook(ctx);
        if (result?.stop)
          return result;
      }
    }
  }

  async function runAfterLoginHooks(
    ctx: AfterHookContext,
    result: AuthResponse,
  ): Promise<AuthResponse> {
    let current = result;
    for (const plugin of plugins) {
      if (plugin.hooks?.afterLogin) {
        current = await plugin.hooks.afterLogin(ctx, current);
      }
    }
    return current;
  }

  async function runAfterRefreshHooks(
    ctx: AfterHookContext,
    result: AuthTokenPair,
  ): Promise<AuthTokenPair> {
    let current = result;
    for (const plugin of plugins) {
      if (plugin.hooks?.afterTokenRefresh) {
        current = await plugin.hooks.afterTokenRefresh(ctx, current);
      }
    }
    return current;
  }

  async function enrichClaims(userId: number): Promise<Record<string, unknown>> {
    const customClaims: Record<string, unknown> = {};
    for (const plugin of plugins) {
      if (plugin.enrichTokenClaims) {
        const claims = await plugin.enrichTokenClaims(userId, { db, config });
        Object.assign(customClaims, claims);
      }
    }
    return customClaims;
  }

  async function getUserGroups(userId: number): Promise<string[]> {
    const memberships = await db.findMany<{ groupId: number }>({
      model: 'group_user',
      where: [{ field: 'userId', operator: '=', value: userId }],
    });

    if (memberships.length === 0)
      return [];

    const groupIds = memberships.map(m => m.groupId);
    const groups = await db.findMany<{ name: string }>({
      model: 'group',
      where: [{ field: 'id', operator: 'in', value: groupIds }],
    });

    return groups.map(g => g.name);
  }

  async function issueTokens(
    user: FortressUser,
    meta?: RequestMeta,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const groups = await getUserGroups(user.id);
    const customClaims = await enrichClaims(user.id);

    const accessToken = await signAccessToken(
      {
        sub: user.id,
        name: user.name,
        groups,
        iss: resolved.issuer,
        customClaims: Object.keys(customClaims).length > 0 ? customClaims : undefined,
      },
      resolved.secret,
      resolved.accessTokenExpiry,
    );

    const { raw, hash } = await generateRefreshToken();
    const family = generateTokenFamily();

    await db.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: hash,
        tokenFamily: family,
        isRevoked: false,
        expiresAt: new Date(Date.now() + resolved.refreshTokenExpiry * 1000),
        ipAddress: meta?.ipAddress ?? null,
        userAgent: meta?.userAgent ?? null,
      },
    });

    return { accessToken, refreshToken: raw };
  }

  return {
    async login(identifier: string, password: string, meta?: RequestMeta): Promise<AuthResponse> {
      const hookCtx: HookContext & { email: string } = { db, config, meta, email: identifier };
      const beforeResult = await runBeforeHooks('beforeLogin', hookCtx);
      if (beforeResult?.stop) {
        return beforeResult.response as unknown as AuthResponse;
      }

      // Resolve user via login_identifier first, fall back to email on user table
      let user: (FortressUser & { passwordHash: string }) | null = null;

      const loginId = await db.findOne<LoginIdentifier>({
        model: 'login_identifier',
        where: [{ field: 'value', operator: '=', value: identifier }],
      });

      if (loginId) {
        user = await db.findOne<FortressUser & { passwordHash: string }>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: loginId.userId }],
        });
      }
      else {
        // Fallback: direct email lookup (for backwards compat or before identifiers are set up)
        user = await db.findOne<FortressUser & { passwordHash: string }>({
          model: 'user',
          where: [{ field: 'email', operator: '=', value: identifier }],
        });
      }

      if (!user) {
        throw Errors.unauthorized('Invalid credentials');
      }

      if (!user.isActive) {
        throw Errors.unauthorized('Account is disabled');
      }

      if (!user.passwordHash) {
        throw Errors.unauthorized('Invalid credentials');
      }

      const valid = await hasher.verify(user.passwordHash, password);
      if (!valid) {
        throw Errors.unauthorized('Invalid credentials');
      }

      const tokens = await issueTokens(user, meta);

      const { passwordHash: _, ...safeUser } = user;
      let response: AuthResponse = {
        user: safeUser,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };

      const afterCtx: AfterHookContext = { db, config, meta, responseHeaders: new Headers() };
      response = await runAfterLoginHooks(afterCtx, response);

      return response;
    },

    async refresh(refreshToken: string, meta?: RequestMeta): Promise<AuthTokenPair> {
      const hookCtx: HookContext & { token: string } = { db, config, meta, token: refreshToken };
      const beforeResult = await runBeforeHooks('beforeTokenRefresh', hookCtx);
      if (beforeResult?.stop) {
        return beforeResult.response as unknown as AuthTokenPair;
      }

      const tokenHash = await hashToken(refreshToken);

      const stored = await db.findOne<{
        id: number;
        userId: number;
        tokenFamily: string;
        isRevoked: boolean;
        expiresAt: Date;
        ipAddress: string | null;
        userAgent: string | null;
      }>({
        model: 'refresh_token',
        where: [{ field: 'tokenHash', operator: '=', value: tokenHash }],
      });

      if (!stored) {
        throw Errors.unauthorized('Invalid refresh token');
      }

      // Token reuse detection: if already revoked, invalidate entire family
      if (stored.isRevoked) {
        await db.update({
          model: 'refresh_token',
          where: [{ field: 'tokenFamily', operator: '=', value: stored.tokenFamily }],
          data: { isRevoked: true },
        });
        throw Errors.tokenReuse();
      }

      if (new Date(stored.expiresAt) < new Date()) {
        throw Errors.unauthorized('Refresh token expired');
      }

      // Revoke old token
      await db.update({
        model: 'refresh_token',
        where: [{ field: 'id', operator: '=', value: stored.id }],
        data: { isRevoked: true },
      });

      // Get user
      const user = await db.findOne<FortressUser>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: stored.userId }],
      });

      if (!user || !user.isActive) {
        throw Errors.unauthorized('User not found or disabled');
      }

      // Issue new tokens with same family
      const groups = await getUserGroups(user.id);
      const customClaims = await enrichClaims(user.id);

      const accessToken = await signAccessToken(
        {
          sub: user.id,
          name: user.name,
          groups,
          iss: resolved.issuer,
          customClaims: Object.keys(customClaims).length > 0 ? customClaims : undefined,
        },
        resolved.secret,
        resolved.accessTokenExpiry,
      );

      const newToken = await generateRefreshToken();

      await db.create({
        model: 'refresh_token',
        data: {
          userId: stored.userId,
          tokenHash: newToken.hash,
          tokenFamily: stored.tokenFamily, // same family for rotation tracking
          isRevoked: false,
          expiresAt: new Date(Date.now() + resolved.refreshTokenExpiry * 1000),
          ipAddress: meta?.ipAddress ?? stored.ipAddress,
          userAgent: meta?.userAgent ?? stored.userAgent,
        },
      });

      let result: AuthTokenPair = {
        accessToken,
        refreshToken: newToken.raw,
      };

      const afterCtx: AfterHookContext = { db, config, meta, responseHeaders: new Headers() };
      result = await runAfterRefreshHooks(afterCtx, result);

      return result;
    },

    async logout(refreshToken: string): Promise<void> {
      const hookCtx: HookContext & { token: string } = { db, config, token: refreshToken };
      await runBeforeHooks('beforeLogout', hookCtx);

      const tokenHash = await hashToken(refreshToken);

      await db.update({
        model: 'refresh_token',
        where: [{ field: 'tokenHash', operator: '=', value: tokenHash }],
        data: { isRevoked: true },
      });
    },

    async me(userId: number): Promise<FortressUser> {
      const user = await db.findOne<FortressUser>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: userId }],
      });

      if (!user) {
        throw Errors.notFound('User not found');
      }

      return user;
    },

    async createUser(data: CreateUserInput): Promise<FortressUser> {
      const hookCtx: HookContext & { data: CreateUserInput } = { db, config, data };
      const beforeResult = await runBeforeHooks('beforeRegister', hookCtx);
      if (beforeResult?.stop) {
        return beforeResult.response as unknown as FortressUser;
      }

      const passwordHash = data.password ? await hasher.hash(data.password) : null;

      const user = await db.create<FortressUser>({
        model: 'user',
        data: {
          email: data.email,
          name: data.name,
          passwordHash,
          isActive: data.isActive ?? true,
        },
      });

      // Auto-create email login identifier
      if (data.email) {
        await db.create({
          model: 'login_identifier',
          data: { userId: user.id, type: 'email', value: data.email },
        });
      }

      const afterCtx: AfterHookContext = { db, config, responseHeaders: new Headers() };
      for (const plugin of plugins) {
        if (plugin.hooks?.afterRegister) {
          await plugin.hooks.afterRegister(afterCtx, user);
        }
      }

      return user;
    },

    async verifyToken(token: string): Promise<TokenClaims> {
      return verifyAccessToken(token, resolved.secret);
    },

    async signToken(claims: Omit<TokenClaims, 'iat' | 'exp'>): Promise<string> {
      return signAccessToken(claims, resolved.secret, resolved.accessTokenExpiry);
    },

    async addLoginIdentifier(userId: number, type: LoginIdentifierType, value: string): Promise<void> {
      await db.create({
        model: 'login_identifier',
        data: { userId, type, value },
      });
    },

    async removeLoginIdentifier(userId: number, type: LoginIdentifierType, value: string): Promise<void> {
      await db.delete({
        model: 'login_identifier',
        where: [
          { field: 'userId', operator: '=', value: userId },
          { field: 'type', operator: '=', value: type },
          { field: 'value', operator: '=', value },
        ],
      });
    },

    async getLoginIdentifiers(userId: number): Promise<LoginIdentifier[]> {
      return db.findMany<LoginIdentifier>({
        model: 'login_identifier',
        where: [{ field: 'userId', operator: '=', value: userId }],
      });
    },
  };
}
