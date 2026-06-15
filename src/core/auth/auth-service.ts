import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressConfig, PasswordHasher } from '../config';
import type { StoredRefreshToken } from '../internal-adapter';
import type { Unsubscribe } from '../observability/listener-list';
import type { FortressLogger } from '../observability/logger';
import type { Histogram, TelemetryProvider } from '../observability/types';
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
import type { JwtKeyMaterial } from './jwt';
import { Errors, FortressError } from '../errors';
import { evaluatePermissions } from '../iam/permission-evaluator';
import { createInternalAdapter } from '../internal-adapter';
import { createListenerList } from '../observability/listener-list';
import { SILENT_LOGGER } from '../observability/logger';
import { signAccessToken, verifyAccessToken } from './jwt';
import { createDefaultHasher, normalizePasswordInput } from './password';
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
    | 'TOKEN_REFRESH' | 'TOKEN_REUSE_DETECTED' | 'TOKEN_FINGERPRINT_MISMATCH'
    | 'IMPERSONATE';
  actorId?: string;
  identifier?: string;
  method?: 'password' | 'oauth' | 'magic_link' | 'webauthn' | '2fa' | 'api_key';
  ipAddress?: string;
  userAgent?: string;
  outcome?: 'success' | 'failure';
  error?: { message: string; code?: string };
  metadata?: Record<string, unknown>;
}

/**
 * Async auth event listener. May return a Promise — if you `return` it, any
 * rejection is routed to `config.logger.error`. Firing work via
 * `void asyncWork()` inside a sync body is an explicit opt-out of that
 * safety net; rejections will escape to the runtime's unhandled-rejection
 * handler instead.
 */
export type AuthEventListener = (event: AuthEvent) => void | Promise<void>;

interface ResolvedConfig {
  key: JwtKeyMaterial;
  issuer: string;
  accessTokenExpiry: number;
  refreshTokenExpiry: number;
}

function resolveConfig(config: FortressConfig): ResolvedConfig {
  return {
    key: config.jwt.key,
    issuer: config.jwt.issuer ?? 'fortress',
    accessTokenExpiry: config.jwt.accessTokenExpirySeconds ?? 900,
    refreshTokenExpiry: config.jwt.refreshTokenExpirySeconds ?? 604800,
  };
}

export interface AuthService {
  login: (identifier: string, password: string, meta?: RequestMeta) => Promise<AuthResponse>;
  refresh: (refreshToken: string, meta?: RequestMeta) => Promise<AuthTokenPair>;
  logout: (refreshToken: string) => Promise<void>;
  me: (userId: string) => Promise<FortressUser>;
  createUser: (data: CreateUserInput) => Promise<FortressUser>;
  verifyToken: (token: string) => Promise<TokenClaims>;
  signToken: (claims: Omit<TokenClaims, 'iat' | 'exp'>) => Promise<string>;
  listSessions: (userId: string) => Promise<SessionInfo[]>;
  revokeSession: (userId: string, tokenId: string) => Promise<void>;
  revokeAllOtherSessions: (userId: string, currentTokenId: string) => Promise<void>;
  addLoginIdentifier: (userId: string, type: LoginIdentifierType, value: string) => Promise<void>;
  removeLoginIdentifier: (userId: string, type: LoginIdentifierType, value: string) => Promise<void>;
  getLoginIdentifiers: (userId: string) => Promise<LoginIdentifier[]>;
  /**
   * Issue a short-lived, non-renewable access token that lets an admin act as another user.
   * The token carries an RFC 8693 `act` claim identifying the real admin.
   *
   * Requires the admin user to hold `fortress:impersonate`. The built-in HTTP route also enforces this via endpoint metadata.
   */
  impersonate: (adminUserId: string, targetUserId: string, options?: { reason?: string; expirySeconds?: number }) => Promise<AuthResponse>;

  // ── Admin user management ──────────────────────────────────────────
  listUsers: (options: { limit?: number; offset?: number; search?: string; sortBy?: string; sortDirection?: 'asc' | 'desc' }) => Promise<{ users: FortressUser[]; total: number }>;
  getUserById: (userId: string) => Promise<FortressUser>;
  updateUser: (userId: string, data: { name?: string; email?: string; isActive?: boolean; password?: string }) => Promise<FortressUser>;
  deleteUser: (userId: string) => Promise<void>;

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
  /**
   * Optional histogram instrument for token-verify latency. Provided by
   * `createFortress` from the resolved telemetry provider — pulled in as a
   * dep rather than built inside `auth-service` so the metric catalog
   * stays centralized in one file.
   */
  tokenVerifyDuration?: Histogram;
}

export function createAuthService(
  db: DatabaseAdapter,
  config: FortressConfig,
  plugins: readonly FortressPlugin[] = [],
  deps?: AuthServiceDeps,
): AuthService {
  const resolved = resolveConfig(config);
  const evaluationMode = config.rbac?.evaluationMode ?? 'allow-only';
  const hasher: PasswordHasher = config.passwordHasher ?? createDefaultHasher();
  // Real, well-formed Argon2 reference hash used as the timing-oracle dummy in
  // the login "user not found / no password" branch. Computing a real hash here
  // (rather than a hard-coded malformed PHC string) guarantees that the
  // verify() call in that branch runs the *full* KDF and matches the cost of
  // verifying a real user's password, so attackers can't distinguish
  // "user exists" from "user not found" via response timing. Lazily computed
  // once on first miss to avoid paying ~100ms at service construction.
  let dummyHashPromise: Promise<string> | null = null;
  const getDummyHash = (): Promise<string> => {
    if (!dummyHashPromise) {
      // Random input -> the hash is never going to verify against any real
      // password the attacker controls, and is never persisted.
      dummyHashPromise = hasher.hash(`fortress-timing-dummy-${crypto.randomUUID()}`);
    }
    return dummyHashPromise;
  };
  const adapter = createInternalAdapter(db);
  const logger = deps?.logger;
  const tokenVerifyDuration = deps?.tokenVerifyDuration;

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

  async function enrichClaims(userId: string): Promise<Record<string, unknown>> {
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
      resolved.key,
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
      const normalizedPassword = normalizePasswordInput(password);
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
          // Run a real Argon2 verify against a well-formed reference hash so
          // this branch takes the same wall-clock time as verifying a real
          // user's password. The previous hard-coded PHC string was malformed
          // (`$...$dummy`), so hash-wasm's parser threw before running the
          // KDF and the branch completed in ~0.3ms instead of ~100ms — a
          // trivial timing oracle for user enumeration.
          await hasher.verify(await getDummyHash(), normalizedPassword).catch(() => {});
          throw Errors.unauthorized('Invalid credentials');
        }

        // Constant-time + constant-message handling for disabled accounts:
        // still run the Argon2 verify so an attacker can't distinguish
        // "account exists but disabled" from "wrong password" via timing
        // *or* via error message. Both paths return the generic
        // `Invalid credentials` (M3).
        const valid = await hasher.verify(user.passwordHash, normalizedPassword);
        if (!user.isActive || !valid) {
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

      const txResult = await db.transaction(async (tx) => {
        const txAdapter = createInternalAdapter(tx);

        // Atomic compare-and-set claim: exactly one concurrent refresh can
        // flip isRevoked=false → true for this token hash. Losers see null
        // and take the replay path below.
        const stored = await tx.update<StoredRefreshToken>({
          model: 'refresh_token',
          where: [
            { field: 'tokenHash', operator: '=', value: tokenHash },
            { field: 'isRevoked', operator: '=', value: false },
          ],
          data: { isRevoked: true },
        });

        if (!stored) {
          const reused = await txAdapter.findRefreshTokenByHash(tokenHash);
          if (reused) {
            await tx.update({
              model: 'refresh_token',
              where: [{ field: 'tokenFamily', operator: '=', value: reused.tokenFamily }],
              data: { isRevoked: true },
            });
            // Do not throw inside the transaction: throwing would roll back
            // the family revocation. Return a sentinel, commit, then throw.
            return {
              replayDetected: true as const,
              userId: reused.userId,
              tokenFamily: reused.tokenFamily,
            };
          }
          throw Errors.unauthorized('Invalid refresh token');
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
              await tx.update({
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

        // Get user
        const user = await tx.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: stored.userId }],
        });

        if (!user || !user.isActive) {
          throw Errors.unauthorized('User not found or disabled');
        }

        // Issue new tokens with same family
        const groups = await txAdapter.getUserGroups(user.id);
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
          resolved.key,
          resolved.accessTokenExpiry,
        );

        const newToken = await generateRefreshToken();

        const newFingerprintHash = meta?.userAgent
          ? await computeFingerprintHash(meta.userAgent)
          : stored.fingerprintHash;

        await tx.create({
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

        return {
          userId: user.id,
          tokens: {
            accessToken,
            refreshToken: newToken.raw,
          } satisfies AuthTokenPair,
        };
      });

      if ('replayDetected' in txResult) {
        if (authEventListeners.size() > 0) {
          authEventListeners.emit({
            eventType: 'TOKEN_REUSE_DETECTED',
            actorId: txResult.userId,
            ipAddress: meta?.ipAddress,
            userAgent: meta?.userAgent,
            metadata: { tokenFamily: txResult.tokenFamily },
          });
        }
        throw Errors.tokenReuse();
      }

      let result: AuthTokenPair = txResult.tokens;

      const afterCtx: AfterHookContext = { db, config, meta, responseHeaders: new Headers() };
      result = await runAfterRefreshHooks(afterCtx, result);

      if (authEventListeners.size() > 0) {
        authEventListeners.emit({
          eventType: 'TOKEN_REFRESH',
          actorId: txResult.userId,
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
      let actorId: string | undefined;
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

    async me(userId: string): Promise<FortressUser> {
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
      const existing = await db.findOne<{ id: string }>({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: data.email }],
      });
      if (existing) {
        throw Errors.conflict('A user with this email already exists');
      }

      const normalizedPassword = data.password && data.password.length > 0
        ? normalizePasswordInput(data.password)
        : undefined;
      if (normalizedPassword !== undefined) {
        await validatePassword(normalizedPassword, config.passwordPolicy);
      }

      const passwordHash = normalizedPassword !== undefined ? await hasher.hash(normalizedPassword) : null;

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
      const start = performance.now();
      try {
        const claims = await verifyAccessToken(token, resolved.key, { issuer: resolved.issuer });
        tokenVerifyDuration?.record(
          (performance.now() - start) / 1000,
          { result: 'ok' },
        );
        return claims;
      }
      catch (err) {
        tokenVerifyDuration?.record(
          (performance.now() - start) / 1000,
          { result: 'invalid' },
        );
        throw err;
      }
    },

    async signToken(claims: Omit<TokenClaims, 'iat' | 'exp'>): Promise<string> {
      return signAccessToken(claims, resolved.key, resolved.accessTokenExpiry);
    },

    async listSessions(userId: string): Promise<SessionInfo[]> {
      const tokens = await db.findMany<{
        id: string;
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

    async revokeSession(userId: string, tokenId: string): Promise<void> {
      await db.update({
        model: 'refresh_token',
        where: [
          { field: 'id', operator: '=', value: tokenId },
          { field: 'userId', operator: '=', value: userId },
        ],
        data: { isRevoked: true },
      });
    },

    async revokeAllOtherSessions(userId: string, currentTokenId: string): Promise<void> {
      // L-tier: replace the read-then-loop with a single conditional UPDATE.
      // The original N+1 path opened a window where new refresh tokens issued
      // during the loop would slip through unrevoked, and added unnecessary
      // adapter round-trips. The adapter performs `AND` of where clauses, so
      // `id != currentTokenId` filters out the keep-token in one statement.
      await db.update({
        model: 'refresh_token',
        where: [
          { field: 'userId', operator: '=', value: userId },
          { field: 'isRevoked', operator: '=', value: false },
          { field: 'id', operator: '!=', value: currentTokenId },
        ],
        data: { isRevoked: true },
      });
    },

    async addLoginIdentifier(userId: string, type: LoginIdentifierType, value: string): Promise<void> {
      await db.create({
        model: 'login_identifier',
        data: { userId, type, value },
      });
    },

    async removeLoginIdentifier(userId: string, type: LoginIdentifierType, value: string): Promise<void> {
      await db.delete({
        model: 'login_identifier',
        where: [
          { field: 'userId', operator: '=', value: userId },
          { field: 'type', operator: '=', value: type },
          { field: 'value', operator: '=', value },
        ],
      });
    },

    async getLoginIdentifiers(userId: string): Promise<LoginIdentifier[]> {
      return db.findMany<LoginIdentifier>({
        model: 'login_identifier',
        where: [{ field: 'userId', operator: '=', value: userId }],
      });
    },

    async impersonate(
      adminUserId: string,
      targetUserId: string,
      options?: { reason?: string; expirySeconds?: number },
    ): Promise<AuthResponse> {
      // Defense in depth for programmatic callers. The HTTP route also
      // enforces this via endpoint metadata before dispatch, but direct
      // service calls must fail closed too.
      const adminPermissions = await adapter.getSubjectPermissions({ type: 'USER', id: adminUserId });
      if (!evaluatePermissions(adminPermissions, 'fortress', 'impersonate', evaluationMode)) {
        throw Errors.forbidden('Insufficient permissions');
      }

      const targetUser = await db.findOne<FortressUser>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: targetUserId }],
      });

      if (!targetUser) {
        throw Errors.notFound('Target user not found');
      }

      // RFC 8693-style act tokens must be short-lived; cap caller-supplied
      // expiry at MAX_IMPERSONATION_TTL_SECONDS (default 3600s, configurable
      // via `config.impersonation.maxTtlSeconds`). An admin with elevated
      // privileges can still cause damage, but not for the next 10 years.
      const requestedExpiry = options?.expirySeconds ?? 3600;
      const maxExpiry = config.impersonation?.maxTtlSeconds ?? 3600;
      const expirySeconds = Math.max(1, Math.min(requestedExpiry, maxExpiry));
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
        resolved.key,
        expirySeconds,
      );

      // Do NOT issue a refresh token for impersonation — non-renewable
      const { passwordHash: _, ...safeUser } = targetUser as FortressUser & { passwordHash?: string };

      // Audit trail for impersonation (P2.4 / L-tier follow-up). Emits
      // through the standard auth observer pipeline so audit-log plugin,
      // SIEM hooks, and metrics counters all see it.
      if (authEventListeners.size() > 0) {
        authEventListeners.emit({
          eventType: 'IMPERSONATE' as AuthEvent['eventType'],
          actorId: adminUserId,
          identifier: String(targetUserId),
          outcome: 'success',
          metadata: {
            targetUserId,
            reason: options?.reason ?? null,
            expirySeconds,
            clamped: expirySeconds !== requestedExpiry,
          },
        });
      }

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

    async getUserById(userId: string): Promise<FortressUser> {
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
      userId: string,
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
        const duplicate = await db.findOne<{ id: string }>({
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
        // Match createUser semantics: validate unconditionally and await.
        // The original code missed the await on a Promise — a breached or
        // weak password would surface as an unhandled rejection while the
        // hash was happily persisted (M1).
        const normalizedPassword = normalizePasswordInput(data.password);
        await validatePassword(normalizedPassword, config.passwordPolicy);
        updateData.passwordHash = await hasher.hash(normalizedPassword);
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

    async deleteUser(userId: string): Promise<void> {
      const existing = await db.findOne<{ id: string }>({
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
