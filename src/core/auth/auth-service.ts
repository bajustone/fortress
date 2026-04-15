import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressConfig, PasswordHasher } from '../config';
import type { Unsubscribe } from '../observability/listener-list';
import type { FortressLogger } from '../observability/logger';
import type { TelemetryProvider } from '../observability/types';
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
  SessionInfo,
  TokenClaims,
} from '../types';
import { Errors, FortressError } from '../errors';
import { createInternalAdapter } from '../internal-adapter';
import { createListenerList } from '../observability/listener-list';
import { SILENT_LOGGER } from '../observability/logger';
import { signAccessToken, verifyAccessToken } from './jwt';
import { createDefaultHasher } from './password';
import { validatePassword } from './password-policy';
import { generateRefreshToken, generateTokenFamily, hashToken } from './refresh-token';

/**
 * Lifecycle event emitted by the auth service. Mirrors the IAM observer
 * pattern (`addIamObserver`) so consumers — audit log, SIEM webhooks,
 * telemetry plugins, Datadog adapters — can subscribe to auth events
 * without reimplementing every hook individually.
 */
export interface AuthEvent {
  eventType:
    | 'LOGIN_SUCCESS' | 'LOGIN_FAILURE'
    | 'LOGOUT' | 'REGISTER'
    | 'TOKEN_REFRESH' | 'TOKEN_REUSE_DETECTED' | 'TOKEN_FINGERPRINT_MISMATCH';
  actorId?: number;
  identifier?: string;
  method?: 'password' | 'oauth' | 'magic_link' | 'webauthn' | '2fa' | 'api_key';
  ipAddress?: string;
  userAgent?: string;
  outcome?: 'success' | 'failure';
  error?: { message: string; code?: string };
  metadata?: Record<string, unknown>;
}

export type AuthEventListener = (event: AuthEvent) => void | Promise<void>;

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
  listSessions: (userId: number) => Promise<SessionInfo[]>;
  revokeSession: (userId: number, tokenId: number) => Promise<void>;
  revokeAllOtherSessions: (userId: number, currentTokenId: number) => Promise<void>;
  addLoginIdentifier: (userId: number, type: LoginIdentifierType, value: string) => Promise<void>;
  removeLoginIdentifier: (userId: number, type: LoginIdentifierType, value: string) => Promise<void>;
  getLoginIdentifiers: (userId: number) => Promise<LoginIdentifier[]>;
  /**
   * Issue a short-lived, non-renewable access token that lets an admin act as another user.
   * The token carries an RFC 8693 `act` claim identifying the real admin.
   *
   * **Caller must verify the admin has the `fortress:impersonate` permission before calling this method.**
   */
  impersonate: (adminUserId: number, targetUserId: number, options?: { reason?: string; expirySeconds?: number }) => Promise<AuthResponse>;

  // ── Admin user management ──────────────────────────────────────────
  listUsers: (options: { limit?: number; offset?: number; search?: string; sortBy?: string; sortDirection?: 'asc' | 'desc' }) => Promise<{ users: FortressUser[]; total: number }>;
  getUserById: (userId: number) => Promise<FortressUser>;
  updateUser: (userId: number, data: { name?: string; email?: string; isActive?: boolean; password?: string }) => Promise<FortressUser>;
  deleteUser: (userId: number) => Promise<void>;

  /**
   * Register a listener for auth lifecycle events. Multiple listeners are
   * supported — each is invoked in registration order. Listener failures
   * never break auth operations; they are routed to the configured logger
   * at `error` level. Returns an unsubscribe function.
   */
  addAuthObserver: (listener: AuthEventListener) => Unsubscribe;
}

export interface AuthServiceDeps {
  logger: FortressLogger;
  telemetry: TelemetryProvider;
}

export function createAuthService(
  db: DatabaseAdapter,
  config: FortressConfig,
  plugins: readonly FortressPlugin[] = [],
  deps?: AuthServiceDeps,
): AuthService {
  const resolved = resolveConfig(config);
  const hasher: PasswordHasher = config.passwordHasher ?? createDefaultHasher();
  const adapter = createInternalAdapter(db);
  const logger = deps?.logger;

  const authEventListeners = createListenerList<AuthEvent>({
    kind: 'async',
    eventLabel: 'auth',
    logger: () => logger ?? SILENT_LOGGER,
  });

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

  async function runOnLoginFailureHooks(identifier: string, error: Error): Promise<void> {
    for (const plugin of plugins) {
      if (plugin.hooks?.onLoginFailure) {
        await plugin.hooks.onLoginFailure({ db, config, identifier, error });
      }
    }
  }

  async function enrichClaims(userId: number): Promise<Record<string, unknown>> {
    const customClaims: Record<string, unknown> = {};
    for (const plugin of plugins) {
      if (plugin.enrichTokenClaims) {
        const claims = await plugin.enrichTokenClaims(userId, { db, config });
        if (process.env.NODE_ENV !== 'production') {
          for (const key of Object.keys(claims)) {
            if (key in customClaims) {
              logger?.warn(
                { plugin: plugin.name, claim: key },
                `plugin overwrites token claim '${key}'`,
              );
            }
          }
        }
        Object.assign(customClaims, claims);
      }
    }
    return customClaims;
  }

  const getUserGroups = adapter.getUserGroups;

  async function computeFingerprintHash(userAgent: string): Promise<string> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(userAgent));
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
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
        subjectType: 'USER',
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

    const fingerprintHash = meta?.userAgent
      ? await computeFingerprintHash(meta.userAgent)
      : null;

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
        deviceName: meta?.deviceName ?? null,
        lastActiveAt: null,
        fingerprintHash,
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
      let user: (FortressUser & { passwordHash: string | null }) | null;
      try {
        user = await adapter.findUserByIdentifier(identifier);

        if (!user || !user.passwordHash) {
          // Run dummy verify to prevent timing oracle (normalize response time
          // regardless of whether user exists or has a password)
          await hasher.verify(
            '$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$dummy',
            password,
          ).catch(() => {});
          throw Errors.unauthorized('Invalid credentials');
        }

        if (!user.isActive) {
          throw Errors.unauthorized('Account is disabled');
        }

        const valid = await hasher.verify(user.passwordHash, password);
        if (!valid) {
          throw Errors.unauthorized('Invalid credentials');
        }
      }
      catch (error) {
        await runOnLoginFailureHooks(identifier, error as Error);
        if (authEventListeners.size() > 0) {
          const err = error instanceof Error ? error : new Error(String(error));
          authEventListeners.emit({
            eventType: 'LOGIN_FAILURE',
            identifier,
            method: 'password',
            ipAddress: meta?.ipAddress,
            userAgent: meta?.userAgent,
            outcome: 'failure',
            error: {
              message: err.message,
              code: err instanceof FortressError ? err.code : undefined,
            },
          });
        }
        throw error;
      }

      const tokens = await issueTokens(user, meta);

      const { passwordHash: _, ...safeUser } = user;
      let response: AuthResponse = {
        status: 'success',
        user: safeUser,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };

      const afterCtx: AfterHookContext = { db, config, meta, responseHeaders: new Headers() };
      response = await runAfterLoginHooks(afterCtx, response);

      if (authEventListeners.size() > 0) {
        authEventListeners.emit({
          eventType: 'LOGIN_SUCCESS',
          actorId: user.id,
          identifier,
          method: 'password',
          ipAddress: meta?.ipAddress,
          userAgent: meta?.userAgent,
          outcome: 'success',
        });
      }

      return response;
    },

    async refresh(refreshToken: string, meta?: RequestMeta): Promise<AuthTokenPair> {
      const hookCtx: HookContext & { token: string } = { db, config, meta, token: refreshToken };
      const beforeResult = await runBeforeHooks('beforeTokenRefresh', hookCtx);
      if (beforeResult?.stop) {
        return beforeResult.response as unknown as AuthTokenPair;
      }

      const tokenHash = await hashToken(refreshToken);

      const stored = await adapter.findRefreshTokenByHash(tokenHash);

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
        if (authEventListeners.size() > 0) {
          authEventListeners.emit({
            eventType: 'TOKEN_REUSE_DETECTED',
            actorId: stored.userId,
            ipAddress: meta?.ipAddress,
            userAgent: meta?.userAgent,
            metadata: { tokenFamily: stored.tokenFamily },
          });
        }
        throw Errors.tokenReuse();
      }

      if (stored.expiresAt < new Date()) {
        throw Errors.unauthorized('Refresh token expired');
      }

      // Token fingerprint validation
      if (config.jwt.validateRefreshFingerprint && stored.fingerprintHash) {
        const currentFingerprint = meta?.userAgent
          ? await computeFingerprintHash(meta.userAgent)
          : null;

        if (currentFingerprint !== stored.fingerprintHash) {
          if (config.jwt.validateRefreshFingerprint === true) {
            // Hard mode: invalidate entire token family and reject
            await db.update({
              model: 'refresh_token',
              where: [{ field: 'tokenFamily', operator: '=', value: stored.tokenFamily }],
              data: { isRevoked: true },
            });
            throw Errors.unauthorized('Refresh token fingerprint mismatch');
          }
          else {
            // Warn mode: log but allow
            logger?.warn(
              { tokenFamily: stored.tokenFamily },
              'refresh token fingerprint mismatch',
            );
            if (authEventListeners.size() > 0) {
              authEventListeners.emit({
                eventType: 'TOKEN_FINGERPRINT_MISMATCH',
                actorId: stored.userId,
                ipAddress: meta?.ipAddress,
                userAgent: meta?.userAgent,
                metadata: { tokenFamily: stored.tokenFamily },
              });
            }
          }
        }
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
          subjectType: 'USER',
          name: user.name,
          groups,
          iss: resolved.issuer,
          customClaims: Object.keys(customClaims).length > 0 ? customClaims : undefined,
        },
        resolved.secret,
        resolved.accessTokenExpiry,
      );

      const newToken = await generateRefreshToken();

      const newFingerprintHash = meta?.userAgent
        ? await computeFingerprintHash(meta.userAgent)
        : stored.fingerprintHash;

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
          deviceName: meta?.deviceName ?? stored.deviceName,
          lastActiveAt: new Date(),
          fingerprintHash: newFingerprintHash,
        },
      });

      let result: AuthTokenPair = {
        accessToken,
        refreshToken: newToken.raw,
      };

      const afterCtx: AfterHookContext = { db, config, meta, responseHeaders: new Headers() };
      result = await runAfterRefreshHooks(afterCtx, result);

      if (authEventListeners.size() > 0) {
        authEventListeners.emit({
          eventType: 'TOKEN_REFRESH',
          actorId: user.id,
          ipAddress: meta?.ipAddress,
          userAgent: meta?.userAgent,
          outcome: 'success',
        });
      }

      return result;
    },

    async logout(refreshToken: string): Promise<void> {
      const hookCtx: HookContext & { token: string } = { db, config, token: refreshToken };
      await runBeforeHooks('beforeLogout', hookCtx);

      const tokenHash = await hashToken(refreshToken);

      // Look up the user the token belongs to so the LOGOUT event can
      // carry an actorId. If lookup fails (token unknown), emit with
      // actorId undefined — observers still fire.
      let actorId: number | undefined;
      if (authEventListeners.size() > 0) {
        const stored = await adapter.findRefreshTokenByHash(tokenHash);
        if (stored) {
          actorId = stored.userId;
        }
      }

      await db.update({
        model: 'refresh_token',
        where: [{ field: 'tokenHash', operator: '=', value: tokenHash }],
        data: { isRevoked: true },
      });

      if (authEventListeners.size() > 0) {
        authEventListeners.emit({
          eventType: 'LOGOUT',
          actorId,
        });
      }
    },

    async me(userId: number): Promise<FortressUser> {
      const user = await db.findOne<FortressUser>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: userId }],
      });

      if (!user) {
        throw Errors.notFound('User not found');
      }

      const { passwordHash: _, ...safeUser } = user as FortressUser & { passwordHash?: string };
      return safeUser;
    },

    async createUser(data: CreateUserInput): Promise<FortressUser> {
      const hookCtx: HookContext & { data: CreateUserInput } = { db, config, data };
      const beforeResult = await runBeforeHooks('beforeRegister', hookCtx);
      if (beforeResult?.stop) {
        return beforeResult.response as unknown as FortressUser;
      }

      // Check for duplicate email before inserting
      const existing = await db.findOne<{ id: number }>({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: data.email }],
      });
      if (existing) {
        throw Errors.conflict('A user with this email already exists');
      }

      if (data.password) {
        await validatePassword(data.password, config.passwordPolicy);
      }

      const passwordHash = data.password ? await hasher.hash(data.password) : null;

      const user = await db.create<FortressUser>({
        model: 'user',
        data: {
          email: data.email,
          name: data.name,
          passwordHash,
          isActive: data.isActive ?? true,
          emailVerified: false,
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

      if (authEventListeners.size() > 0) {
        authEventListeners.emit({
          eventType: 'REGISTER',
          actorId: user.id,
          identifier: data.email,
          method: 'password',
          outcome: 'success',
        });
      }

      return user;
    },

    async verifyToken(token: string): Promise<TokenClaims> {
      return verifyAccessToken(token, resolved.secret);
    },

    async signToken(claims: Omit<TokenClaims, 'iat' | 'exp'>): Promise<string> {
      return signAccessToken(claims, resolved.secret, resolved.accessTokenExpiry);
    },

    async listSessions(userId: number): Promise<SessionInfo[]> {
      const tokens = await db.findMany<{
        id: number;
        ipAddress: string | null;
        userAgent: string | null;
        deviceName: string | null;
        createdAt: Date;
        lastActiveAt: Date | null;
      }>({
        model: 'refresh_token',
        where: [
          { field: 'userId', operator: '=', value: userId },
          { field: 'isRevoked', operator: '=', value: false },
          { field: 'expiresAt', operator: 'gt', value: new Date() },
        ],
      });

      return tokens.map(t => ({
        id: t.id,
        ipAddress: t.ipAddress,
        userAgent: t.userAgent,
        deviceName: t.deviceName,
        createdAt: t.createdAt,
        lastActiveAt: t.lastActiveAt,
      }));
    },

    async revokeSession(userId: number, tokenId: number): Promise<void> {
      await db.update({
        model: 'refresh_token',
        where: [
          { field: 'id', operator: '=', value: tokenId },
          { field: 'userId', operator: '=', value: userId },
        ],
        data: { isRevoked: true },
      });
    },

    async revokeAllOtherSessions(userId: number, currentTokenId: number): Promise<void> {
      const tokens = await db.findMany<{ id: number }>({
        model: 'refresh_token',
        where: [
          { field: 'userId', operator: '=', value: userId },
          { field: 'isRevoked', operator: '=', value: false },
        ],
      });

      for (const token of tokens) {
        if (token.id !== currentTokenId) {
          await db.update({
            model: 'refresh_token',
            where: [{ field: 'id', operator: '=', value: token.id }],
            data: { isRevoked: true },
          });
        }
      }
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

    async impersonate(
      adminUserId: number,
      targetUserId: number,
      options?: { reason?: string; expirySeconds?: number },
    ): Promise<AuthResponse> {
      const targetUser = await db.findOne<FortressUser>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: targetUserId }],
      });

      if (!targetUser) {
        throw Errors.notFound('Target user not found');
      }

      const expirySeconds = options?.expirySeconds ?? 3600;
      const groups = await getUserGroups(targetUser.id);
      const customClaims = await enrichClaims(targetUser.id);

      const accessToken = await signAccessToken(
        {
          sub: targetUser.id,
          subjectType: 'USER',
          name: targetUser.name,
          groups,
          iss: resolved.issuer,
          act: { sub: adminUserId, subjectType: 'USER' },
          customClaims: Object.keys(customClaims).length > 0 ? customClaims : undefined,
        },
        resolved.secret,
        expirySeconds,
      );

      // Do NOT issue a refresh token for impersonation — non-renewable
      const { passwordHash: _, ...safeUser } = targetUser as FortressUser & { passwordHash?: string };

      return {
        status: 'impersonation' as const,
        user: safeUser,
        accessToken,
        refreshToken: null,
        pluginData: {
          impersonation: {
            adminUserId,
            reason: options?.reason ?? null,
            expiresInSeconds: expirySeconds,
          },
        },
      };
    },

    // ── Admin user management ──────────────────────────────────────

    async listUsers(options: {
      limit?: number;
      offset?: number;
      search?: string;
      sortBy?: string;
      sortDirection?: 'asc' | 'desc';
    }): Promise<{ users: FortressUser[]; total: number }> {
      const where: { field: string; operator: string; value: unknown }[] = [];

      if (options.search) {
        where.push({ field: 'email', operator: 'like', value: `%${options.search}%` });
      }

      const [users, total] = await Promise.all([
        db.findMany<FortressUser & { passwordHash?: string }>({
          model: 'user',
          where: where.length > 0 ? where : undefined,
          limit: options.limit ?? 50,
          offset: options.offset ?? 0,
          sortBy: options.sortBy
            ? { field: options.sortBy, direction: options.sortDirection ?? 'asc' }
            : { field: 'id', direction: 'asc' },
        }),
        db.count({
          model: 'user',
          where: where.length > 0 ? where : undefined,
        }),
      ]);

      return {
        users: users.map(({ passwordHash: _, ...u }) => u),
        total,
      };
    },

    async getUserById(userId: number): Promise<FortressUser> {
      const user = await db.findOne<FortressUser & { passwordHash?: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: userId }],
      });

      if (!user) {
        throw Errors.notFound('User not found');
      }

      const { passwordHash: _, ...safeUser } = user;
      return safeUser;
    },

    async updateUser(
      userId: number,
      data: { name?: string; email?: string; isActive?: boolean; password?: string },
    ): Promise<FortressUser> {
      // Verify user exists
      const existing = await db.findOne<FortressUser>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: userId }],
      });
      if (!existing) {
        throw Errors.notFound('User not found');
      }

      // Check email uniqueness if changing email
      if (data.email && data.email !== existing.email) {
        const duplicate = await db.findOne<{ id: number }>({
          model: 'user',
          where: [{ field: 'email', operator: '=', value: data.email }],
        });
        if (duplicate) {
          throw Errors.conflict('A user with this email already exists');
        }
      }

      const updateData: Record<string, unknown> = {};
      if (data.name !== undefined)
        updateData.name = data.name;
      if (data.email !== undefined)
        updateData.email = data.email;
      if (data.isActive !== undefined)
        updateData.isActive = data.isActive;
      if (data.password !== undefined) {
        if (config.passwordPolicy)
          validatePassword(data.password, config.passwordPolicy);
        updateData.passwordHash = await hasher.hash(data.password);
      }

      const updated = await db.update<FortressUser & { passwordHash?: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: userId }],
        data: updateData,
      });

      if (!updated) {
        throw Errors.notFound('User not found');
      }

      // Update login identifier if email changed
      if (data.email && data.email !== existing.email) {
        await db.update({
          model: 'login_identifier',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'type', operator: '=', value: 'email' },
            { field: 'value', operator: '=', value: existing.email },
          ],
          data: { value: data.email },
        });
      }

      const { passwordHash: _, ...safeUser } = updated;
      return safeUser;
    },

    async deleteUser(userId: number): Promise<void> {
      const existing = await db.findOne<{ id: number }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: userId }],
      });
      if (!existing) {
        throw Errors.notFound('User not found');
      }

      await db.delete({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: userId }],
      });
    },

    addAuthObserver(listener: AuthEventListener): Unsubscribe {
      return authEventListeners.add(listener);
    },
  };
}
