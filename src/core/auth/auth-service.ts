import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressConfig, PasswordHasher } from '../config';
import type { StoredContinuation, StoredRefreshToken } from '../internal-adapter';
import type { Unsubscribe } from '../observability/listener-list';
import type { FortressLogger } from '../observability/logger';
import type { Histogram, TelemetryProvider } from '../observability/types';
import type {
  AfterHookContext,
  HookContext,
  HookResult,
  RuntimeFortressPlugin,
} from '../plugin';
import type {
  AuthMethod,
  AuthResult,
  AuthSuccess,
  AuthTokenPair,
  CreateUserInput,
  FortressUser,
  LoginIdentifier,
  LoginIdentifierType,
  PendingReason,
  RequestMeta,
  SessionInfo,
  TokenClaims,
} from '../types';
import type { JwtKeyMaterial } from './jwt';
import type { PasswordPolicyObserver } from './password-policy';
import { Errors, FortressError } from '../errors';
import { evaluatePermissions } from '../iam/permission-evaluator';
import { createInternalAdapter } from '../internal-adapter';
import { createListenerList } from '../observability/listener-list';
import { SILENT_LOGGER } from '../observability/logger';
import { normalizeEmail } from './email';
import { signAccessToken, verifyAccessToken } from './jwt';
import { createDefaultHasher, normalizePasswordInput } from './password';
import { validatePassword } from './password-policy';
import { consumeAuthContinuation, runPostAuthGates, verifyAuthContinuation } from './post-auth-gate';
import { deriveRefreshTokenSuccessor, generateRefreshToken, generateTokenFamily, hashRefreshFingerprint, hashToken } from './refresh-token';

const NUMERIC_SUBJECT_ID_RE = /^\d+$/;

/**
 * Lifecycle event emitted by the auth service. Mirrors the IAM observer
 * pattern (`addIamObserver`) so consumers — audit log, SIEM webhooks,
 * telemetry plugins, Datadog adapters — can subscribe to auth events
 * without reimplementing every hook individually.
 */
export interface AuthEvent {
  eventType:
    | 'LOGIN_SUCCESS' | 'LOGIN_FAILURE' | 'LOGIN_PENDING'
    | 'LOGOUT' | 'REGISTER'
    | 'TOKEN_REFRESH' | 'TOKEN_REUSE_DETECTED' | 'TOKEN_REUSE_GRACED' | 'TOKEN_FINGERPRINT_MISMATCH'
    | 'MFA_VERIFY_SUCCESS' | 'MFA_VERIFY_FAILURE'
    | 'SESSION_EXPIRED_IDLE' | 'SESSION_EXPIRED_ABSOLUTE'
    | 'PASSWORD_BREACH_CHECK_DEGRADED'
    | 'IMPERSONATE';
  actorId?: string;
  identifier?: string;
  method?: 'password' | 'oauth' | 'magic_link' | 'webauthn' | '2fa' | 'api_key';
  ipAddress?: string;
  userAgent?: string;
  outcome?: 'success' | 'failure' | 'pending';
  /** Set on `LOGIN_PENDING` — which additional step the sign-in is waiting on. */
  pendingReason?: PendingReason;
  /** Free-form sub-action label (e.g. the specific fingerprint/session action that fired the event). */
  action?: string;
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
  audience?: string | string[];
  accessTokenExpiry: number;
  refreshTokenExpiry: number;
}

function resolveConfig(config: FortressConfig): ResolvedConfig {
  return {
    key: config.jwt.key,
    issuer: config.jwt.issuer ?? 'fortress',
    audience: config.jwt.audience,
    accessTokenExpiry: config.jwt.accessTokenExpirySeconds ?? 900,
    refreshTokenExpiry: config.jwt.refreshTokenExpirySeconds ?? 604800,
  };
}

export interface AuthService {
  login: (identifier: string, password: string, meta?: RequestMeta) => Promise<AuthResult>;
  /** Consume a verified factor's continuation, rerun remaining gates, then issue tokens. */
  completePendingAuth: (continuationToken: string, completion: unknown, meta?: RequestMeta) => Promise<AuthResult>;
  /** Finish a trusted plugin-owned primary credential (for example a magic link). */
  completePluginAuth: (
    userId: string,
    method: Exclude<AuthMethod, 'refresh' | 'impersonation'>,
    meta?: RequestMeta,
  ) => Promise<AuthResult>;
  refresh: (refreshToken: string, meta?: RequestMeta) => Promise<AuthTokenPair>;
  logout: (refreshToken: string) => Promise<void>;
  me: (userId: string) => Promise<FortressUser>;
  createUser: (data: CreateUserInput) => Promise<FortressUser>;
  verifyToken: (token: string) => Promise<TokenClaims>;
  signToken: (claims: Omit<TokenClaims, 'iat' | 'exp' | 'aud'>) => Promise<string>;
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
  impersonate: (adminUserId: string, targetUserId: string, options?: { reason?: string; expirySeconds?: number }) => Promise<AuthResult>;

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
  plugins: readonly RuntimeFortressPlugin[] = [],
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

  const passwordPolicyObserver: PasswordPolicyObserver = (event) => {
    logger?.warn(
      { failureMode: event.failureMode, status: event.status, error: event.error },
      'password breach check degraded',
    );
    authEventListeners.emit({
      eventType: 'PASSWORD_BREACH_CHECK_DEGRADED',
      outcome: 'failure',
      metadata: {
        failureMode: event.failureMode,
        ...(event.status !== undefined && { status: event.status }),
        ...(event.error instanceof Error && { error: event.error.message }),
      },
    });
  };

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

  // After-* hooks run once the authentication decision is committed and the
  // session tokens have already been issued/persisted. A failing side-effect
  // hook (audit, webhook, analytics) must not roll back a completed login —
  // doing so would return an error to the caller while leaving a live session
  // behind, and would let any plugin brick authentication by throwing. So a
  // throwing after-hook is logged and skipped (keeping the last good result),
  // mirroring runOnLoginFailureHooks. Plugins that need to *veto* a login must
  // use a pre-issuance hook (beforeLogin / postAuthGate), not afterLogin.
  async function runAfterLoginHooks(
    ctx: AfterHookContext,
    result: AuthSuccess,
  ): Promise<AuthSuccess> {
    let current = result;
    for (const plugin of plugins) {
      if (plugin.hooks?.afterLogin) {
        try {
          current = await plugin.hooks.afterLogin(ctx, current);
        }
        catch (hookError) {
          logger?.error({ plugin: plugin.name, error: hookError }, 'afterLogin hook failed');
        }
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
        try {
          current = await plugin.hooks.afterTokenRefresh(ctx, current);
        }
        catch (hookError) {
          logger?.error({ plugin: plugin.name, error: hookError }, 'afterTokenRefresh hook failed');
        }
      }
    }
    return current;
  }

  async function runOnLoginFailureHooks(identifier: string, error: Error): Promise<void> {
    for (const plugin of plugins) {
      if (!plugin.hooks?.onLoginFailure)
        continue;
      try {
        await plugin.hooks.onLoginFailure({ db, config, identifier, error });
      }
      catch (hookError) {
        logger?.error(
          { plugin: plugin.name, error: hookError },
          'onLoginFailure hook failed',
        );
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

  const jwtSecrets = Array.isArray(resolved.key) ? resolved.key : [resolved.key];
  async function computeFingerprintHash(meta: RequestMeta, secret = jwtSecrets[0]!): Promise<string | null> {
    return meta.userAgent
      ? hashRefreshFingerprint(meta.userAgent, meta.ipAddress, secret)
      : null;
  }
  async function fingerprintMatches(stored: string, meta: RequestMeta): Promise<boolean> {
    if (!meta.userAgent)
      return false;
    for (const secret of jwtSecrets) {
      if (await hashRefreshFingerprint(meta.userAgent, meta.ipAddress, secret) === stored)
        return true;
    }
    return false;
  }

  async function issueAccessToken(
    user: FortressUser,
    resolveGroups: (userId: string) => Promise<string[]>,
  ): Promise<string> {
    const groups = await resolveGroups(user.id);
    const customClaims = await enrichClaims(user.id);
    return signAccessToken(
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
      { audience: resolved.audience },
    );
  }

  async function issueTokens(
    user: FortressUser,
    meta?: RequestMeta,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const accessToken = await issueAccessToken(user, getUserGroups);
    const { raw, hash } = await generateRefreshToken();
    const family = generateTokenFamily();
    const issuedAt = new Date();

    const fingerprintHash = meta ? await computeFingerprintHash(meta) : null;

    const maxSessions = config.jwt.session?.maxSessionsPerUser;
    const persistSession = async (target: DatabaseAdapter): Promise<void> => {
      if (maxSessions != null && maxSessions > 0) {
        // PostgreSQL needs a per-user lock; transaction isolation alone lets
        // concurrent logins both observe spare capacity. A no-op update takes
        // that row lock without bypassing DatabaseAdapter model/table mapping.
        // SQLite's BEGIN IMMEDIATE transaction already serializes writers.
        if (target.dialect === 'pg') {
          const locked = await target.update({
            model: 'user',
            where: [{ field: 'id', operator: '=', value: user.id }],
            // Reassign the immutable primary key to itself: this acquires the
            // row lock without risking stale mutable-field writeback.
            data: { id: user.id },
          });
          if (!locked)
            throw Errors.notFound('User not found');
        }

        const active = (await target.findMany<StoredRefreshToken>({
          model: 'refresh_token',
          where: [
            { field: 'userId', operator: '=', value: user.id },
            { field: 'isRevoked', operator: '=', value: false },
          ],
          sortBy: { field: 'familyCreatedAt', direction: 'asc' },
        })).filter(token => token.expiresAt > issuedAt);
        const overflow = active.length - maxSessions + 1;
        for (const token of active.slice(0, Math.max(0, overflow))) {
          await target.update({
            model: 'refresh_token',
            where: [{ field: 'tokenFamily', operator: '=', value: token.tokenFamily }],
            data: { isRevoked: true },
          });
        }
      }

      await target.create({
        model: 'refresh_token',
        data: {
          userId: user.id,
          tokenHash: hash,
          tokenFamily: family,
          familyCreatedAt: issuedAt,
          successorTokenHash: null,
          rotatedAt: null,
          isRevoked: false,
          expiresAt: new Date(issuedAt.getTime() + resolved.refreshTokenExpiry * 1000),
          ipAddress: meta?.ipAddress ?? null,
          userAgent: meta?.userAgent ?? null,
          deviceName: meta?.deviceName ?? null,
          lastActiveAt: issuedAt,
          fingerprintHash,
        },
      });
    };

    if (maxSessions != null)
      await db.transaction(persistSession);
    else
      await persistSession(db);

    return { accessToken, refreshToken: raw };
  }

  type CompletedAuthMethod = Exclude<AuthMethod, 'refresh' | 'impersonation'>;

  function eventMethodFor(method: CompletedAuthMethod): AuthEvent['method'] {
    switch (method) {
      case 'two-factor':
        return '2fa';
      case 'magic-link':
        return 'magic_link';
      default:
        return method;
    }
  }

  async function finishAuthentication(
    user: FortressUser,
    method: CompletedAuthMethod,
    meta?: RequestMeta,
    identifier?: string,
    completedReasons: readonly PendingReason[] = [],
    pluginData?: Record<string, unknown>,
  ): Promise<AuthResult> {
    const hold = await runPostAuthGates(plugins, db, config, user, meta, completedReasons);
    if (hold) {
      const pending: AuthResult = {
        status: 'pending',
        user,
        pending: hold.challenge,
        pluginData: { ...hold.pluginData, ...pluginData },
      };
      if (authEventListeners.size() > 0) {
        authEventListeners.emit({
          eventType: 'LOGIN_PENDING',
          actorId: user.id,
          identifier,
          method: eventMethodFor(method),
          ipAddress: meta?.ipAddress,
          userAgent: meta?.userAgent,
          outcome: 'pending',
          pendingReason: hold.challenge.reason,
        });
      }
      return pending;
    }

    const tokens = await issueTokens(user, meta);
    let response: AuthSuccess = {
      status: 'success',
      user,
      method,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      ...(pluginData && Object.keys(pluginData).length > 0 ? { pluginData } : {}),
    };

    const afterCtx: AfterHookContext = { db, config, meta, responseHeaders: new Headers(), identifier };
    response = await runAfterLoginHooks(afterCtx, response);

    if (authEventListeners.size() > 0) {
      authEventListeners.emit({
        eventType: 'LOGIN_SUCCESS',
        actorId: user.id,
        identifier,
        method: eventMethodFor(method),
        ipAddress: meta?.ipAddress,
        userAgent: meta?.userAgent,
        outcome: 'success',
      });
    }

    return response;
  }

  return {
    async login(identifier: string, password: string, meta?: RequestMeta): Promise<AuthResult> {
      const normalizedPassword = normalizePasswordInput(password);
      const hookCtx: HookContext & { email: string } = { db, config, meta, email: identifier };
      const beforeResult = await runBeforeHooks('beforeLogin', hookCtx);
      if (beforeResult?.stop) {
        return beforeResult.response as unknown as AuthResult;
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

      const { passwordHash: _, ...safeUser } = user;
      return finishAuthentication(safeUser, 'password', meta, identifier);
    },

    async completePluginAuth(
      userId: string,
      method: CompletedAuthMethod,
      meta?: RequestMeta,
    ): Promise<AuthResult> {
      const storedUser = await db.findOne<FortressUser & { passwordHash?: string | null }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: userId }],
      });
      if (!storedUser || !storedUser.isActive)
        throw Errors.unauthorized('User not found or disabled');
      const { passwordHash: _, ...user } = storedUser;
      return finishAuthentication(user, method, meta);
    },

    async completePendingAuth(continuationToken: string, completion: unknown, meta?: RequestMeta): Promise<AuthResult> {
      let attempted: { reason: PendingReason; userId: string } | undefined;
      let verificationData: Record<string, unknown> | undefined;
      let continuation: StoredContinuation;
      try {
        continuation = await consumeAuthContinuation(db, continuationToken, async (tx, pending) => {
          attempted = { reason: pending.reason, userId: pending.userId };
          const storedUser = await tx.findOne<FortressUser & { passwordHash?: string | null }>({
            model: 'user',
            where: [{ field: 'id', operator: '=', value: pending.userId }],
          });
          if (!storedUser || !storedUser.isActive)
            throw Errors.unauthorized('User not found or disabled');
          const { passwordHash: _, ...user } = storedUser;
          verificationData = (await verifyAuthContinuation(plugins, tx, config, user, pending, completion, meta)) ?? undefined;
        });
      }
      catch (error) {
        if (attempted && (attempted.reason === 'two-factor' || attempted.reason === 'webauthn')) {
          authEventListeners.emit({
            eventType: 'MFA_VERIFY_FAILURE',
            actorId: attempted.userId,
            method: attempted.reason === 'two-factor' ? '2fa' : 'webauthn',
            ipAddress: meta?.ipAddress,
            userAgent: meta?.userAgent,
            outcome: 'failure',
            error: { message: error instanceof Error ? error.message : String(error) },
          });
          // A wrong second factor is a failed authentication attempt: feed it
          // into the onLoginFailure hooks (account-lockout, audit, webhook)
          // keyed by the user's identifier so a brute-forced 2FA/WebAuthn step
          // is throttled and locked out like a password failure, not just
          // capped per continuation. Guarded so a lookup/hook error can never
          // mask the original verification error.
          try {
            const failedUser = await db.findOne<FortressUser>({
              model: 'user',
              where: [{ field: 'id', operator: '=', value: attempted.userId }],
            });
            if (failedUser?.email)
              await runOnLoginFailureHooks(failedUser.email, error as Error);
          }
          catch (lockoutError) {
            logger?.error({ error: lockoutError }, 'failed to record MFA failure for account lockout');
          }
        }
        throw error;
      }

      if (continuation.reason === 'two-factor' || continuation.reason === 'webauthn') {
        authEventListeners.emit({
          eventType: 'MFA_VERIFY_SUCCESS',
          actorId: continuation.userId,
          method: continuation.reason === 'two-factor' ? '2fa' : 'webauthn',
          ipAddress: meta?.ipAddress,
          userAgent: meta?.userAgent,
          outcome: 'success',
        });
      }

      const storedUser = await db.findOne<FortressUser & { passwordHash?: string | null }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: continuation.userId }],
      });
      if (!storedUser || !storedUser.isActive)
        throw Errors.unauthorized('User not found or disabled');
      const { passwordHash: _, ...refreshedUser } = storedUser;

      const method: CompletedAuthMethod = continuation.reason === 'two-factor'
        ? 'two-factor'
        : continuation.reason === 'magic-link'
          ? 'magic-link'
          : continuation.reason === 'webauthn'
            ? 'webauthn'
            : 'password';

      return finishAuthentication(refreshedUser, method, meta, undefined, [continuation.reason], verificationData);
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
          if (!reused)
            throw Errors.unauthorized('Invalid refresh token');

          const graceSeconds = config.jwt.session?.refreshGraceSeconds;
          const now = new Date();
          const withinGrace = graceSeconds != null
            && graceSeconds > 0
            && reused.rotatedAt != null
            && now.getTime() - reused.rotatedAt.getTime() <= graceSeconds * 1000;
          if (withinGrace && reused.successorTokenHash) {
            const fingerprintMismatch = reused.fingerprintHash != null
              && (!meta || !(await fingerprintMatches(reused.fingerprintHash, meta)));
            const fingerprintAllowsGrace = !fingerprintMismatch
              || config.jwt.validateRefreshFingerprint !== true;
            if (fingerprintMismatch && config.jwt.validateRefreshFingerprint === 'warn') {
              logger?.warn(
                { tokenFamily: reused.tokenFamily },
                'refresh token fingerprint mismatch during grace recovery',
              );
              authEventListeners.emit({
                eventType: 'TOKEN_FINGERPRINT_MISMATCH',
                actorId: reused.userId,
                ipAddress: meta?.ipAddress,
                userAgent: meta?.userAgent,
                metadata: { tokenFamily: reused.tokenFamily, action: 'grace-recovery' },
              });
            }
            if (fingerprintAllowsGrace) {
              const secrets = Array.isArray(resolved.key) ? resolved.key : [resolved.key];
              let successorToken: Awaited<ReturnType<typeof deriveRefreshTokenSuccessor>> | null = null;
              for (const secret of secrets) {
                const candidate = await deriveRefreshTokenSuccessor(refreshToken, secret);
                if (candidate.hash === reused.successorTokenHash) {
                  successorToken = candidate;
                  break;
                }
              }
              const successor = successorToken
                ? await tx.findOne<StoredRefreshToken>({
                    model: 'refresh_token',
                    where: [
                      { field: 'tokenHash', operator: '=', value: successorToken.hash },
                      { field: 'isRevoked', operator: '=', value: false },
                      { field: 'expiresAt', operator: 'gt', value: now },
                    ],
                  })
                : null;
              if (successor) {
                const absoluteTimeout = config.jwt.session?.absoluteTimeoutSeconds;
                if (absoluteTimeout != null && absoluteTimeout > 0 && now.getTime() - successor.familyCreatedAt.getTime() > absoluteTimeout * 1000) {
                  await tx.update({
                    model: 'refresh_token',
                    where: [{ field: 'tokenFamily', operator: '=', value: successor.tokenFamily }],
                    data: { isRevoked: true },
                  });
                  return {
                    sessionExpired: 'absolute' as const,
                    userId: successor.userId,
                    tokenFamily: successor.tokenFamily,
                  };
                }

                const idleTimeout = config.jwt.session?.idleTimeoutSeconds;
                const lastActivity = successor.lastActiveAt ?? successor.familyCreatedAt;
                if (idleTimeout != null && idleTimeout > 0 && now.getTime() - lastActivity.getTime() > idleTimeout * 1000) {
                  await tx.update({
                    model: 'refresh_token',
                    where: [{ field: 'tokenFamily', operator: '=', value: successor.tokenFamily }],
                    data: { isRevoked: true },
                  });
                  return {
                    sessionExpired: 'idle' as const,
                    userId: successor.userId,
                    tokenFamily: successor.tokenFamily,
                  };
                }

                const user = await tx.findOne<FortressUser>({
                  model: 'user',
                  where: [{ field: 'id', operator: '=', value: successor.userId }],
                });
                if (user?.isActive) {
                  return {
                    graced: true as const,
                    userId: user.id,
                    tokenFamily: reused.tokenFamily,
                    tokens: {
                      accessToken: await issueAccessToken(user, txAdapter.getUserGroups),
                      refreshToken: successorToken!.raw,
                    } satisfies AuthTokenPair,
                  };
                }
              }
            }
          }

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

        const now = new Date();
        if (stored.expiresAt < now)
          throw Errors.unauthorized('Refresh token expired');

        const absoluteTimeout = config.jwt.session?.absoluteTimeoutSeconds;
        if (absoluteTimeout != null && absoluteTimeout > 0 && now.getTime() - stored.familyCreatedAt.getTime() > absoluteTimeout * 1000) {
          await tx.update({
            model: 'refresh_token',
            where: [{ field: 'tokenFamily', operator: '=', value: stored.tokenFamily }],
            data: { isRevoked: true },
          });
          return {
            sessionExpired: 'absolute' as const,
            userId: stored.userId,
            tokenFamily: stored.tokenFamily,
          };
        }

        const idleTimeout = config.jwt.session?.idleTimeoutSeconds;
        const lastActivity = stored.lastActiveAt ?? stored.familyCreatedAt;
        if (idleTimeout != null && idleTimeout > 0 && now.getTime() - lastActivity.getTime() > idleTimeout * 1000) {
          await tx.update({
            model: 'refresh_token',
            where: [{ field: 'tokenFamily', operator: '=', value: stored.tokenFamily }],
            data: { isRevoked: true },
          });
          return {
            sessionExpired: 'idle' as const,
            userId: stored.userId,
            tokenFamily: stored.tokenFamily,
          };
        }

        // Token fingerprint validation
        if (config.jwt.validateRefreshFingerprint && stored.fingerprintHash) {
          const currentFingerprintMatches = meta
            ? await fingerprintMatches(stored.fingerprintHash, meta)
            : false;

          if (!currentFingerprintMatches) {
            if (config.jwt.validateRefreshFingerprint === true) {
              // Do not throw inside the transaction: the family revocation
              // must commit before the caller receives the rejection.
              await tx.update({
                model: 'refresh_token',
                where: [{ field: 'tokenFamily', operator: '=', value: stored.tokenFamily }],
                data: { isRevoked: true },
              });
              return {
                fingerprintMismatch: true as const,
                userId: stored.userId,
                tokenFamily: stored.tokenFamily,
              };
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

        // Issue new tokens with same family. Grace-enabled rotations derive
        // the successor so a benign retry can recompute the raw token while
        // the database stores only its hash.
        const accessToken = await issueAccessToken(user, txAdapter.getUserGroups);
        const graceSeconds = config.jwt.session?.refreshGraceSeconds;
        const primaryKey = Array.isArray(resolved.key) ? resolved.key[0] : resolved.key;
        if (primaryKey === undefined)
          throw Errors.unauthorized('Invalid refresh token');
        const newToken = graceSeconds != null && graceSeconds > 0
          ? await deriveRefreshTokenSuccessor(refreshToken, primaryKey)
          : await generateRefreshToken();

        const newFingerprintHash = meta
          ? (await computeFingerprintHash(meta) ?? stored.fingerprintHash)
          : stored.fingerprintHash;

        const rotatedAt = new Date();
        await tx.update({
          model: 'refresh_token',
          where: [{ field: 'id', operator: '=', value: stored.id }],
          data: { successorTokenHash: newToken.hash, rotatedAt },
        });

        await tx.create({
          model: 'refresh_token',
          data: {
            userId: stored.userId,
            tokenHash: newToken.hash,
            tokenFamily: stored.tokenFamily, // same family for rotation tracking
            familyCreatedAt: stored.familyCreatedAt,
            successorTokenHash: null,
            rotatedAt: null,
            isRevoked: false,
            expiresAt: new Date(rotatedAt.getTime() + resolved.refreshTokenExpiry * 1000),
            ipAddress: meta?.ipAddress ?? stored.ipAddress,
            userAgent: meta?.userAgent ?? stored.userAgent,
            deviceName: meta?.deviceName ?? stored.deviceName,
            lastActiveAt: rotatedAt,
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

      if ('fingerprintMismatch' in txResult) {
        authEventListeners.emit({
          eventType: 'TOKEN_FINGERPRINT_MISMATCH',
          actorId: txResult.userId,
          ipAddress: meta?.ipAddress,
          userAgent: meta?.userAgent,
          outcome: 'failure',
          metadata: { tokenFamily: txResult.tokenFamily, action: 'family-revoked' },
        });
        throw Errors.unauthorized('Refresh token fingerprint mismatch');
      }

      if ('sessionExpired' in txResult) {
        const eventType = txResult.sessionExpired === 'idle'
          ? 'SESSION_EXPIRED_IDLE' as const
          : 'SESSION_EXPIRED_ABSOLUTE' as const;
        authEventListeners.emit({
          eventType,
          actorId: txResult.userId,
          ipAddress: meta?.ipAddress,
          userAgent: meta?.userAgent,
          outcome: 'failure',
          metadata: { tokenFamily: txResult.tokenFamily },
        });
        throw txResult.sessionExpired === 'idle'
          ? Errors.sessionIdleTimeout()
          : Errors.sessionAbsoluteTimeout();
      }

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

      if ('graced' in txResult) {
        authEventListeners.emit({
          eventType: 'TOKEN_REUSE_GRACED',
          actorId: txResult.userId,
          ipAddress: meta?.ipAddress,
          userAgent: meta?.userAgent,
          outcome: 'success',
          metadata: { tokenFamily: txResult.tokenFamily },
        });
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
      const normalizedData: CreateUserInput = { ...data, email: normalizeEmail(data.email) };
      const hookCtx: HookContext & { data: CreateUserInput } = { db, config, data: normalizedData };
      const beforeResult = await runBeforeHooks('beforeRegister', hookCtx);
      if (beforeResult?.stop) {
        return beforeResult.response as unknown as FortressUser;
      }
      // Hooks may mutate their data object; restore the canonical identity at
      // the final persistence boundary rather than trusting hook discipline.
      normalizedData.email = normalizeEmail(normalizedData.email);

      // Preserve the established friendly duplicate error before spending on
      // password validation/hash; the transaction repeats this check and the
      // database constraints remain authoritative for races and aliases.
      const existing = await db.findOne<{ id: string }>({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: normalizedData.email }],
      });
      if (existing)
        throw Errors.conflict('A user with this email already exists');

      const normalizedPassword = normalizedData.password && normalizedData.password.length > 0
        ? normalizePasswordInput(normalizedData.password)
        : undefined;
      if (normalizedPassword !== undefined) {
        await validatePassword(normalizedPassword, config.passwordPolicy, passwordPolicyObserver);
      }

      const passwordHash = normalizedPassword !== undefined ? await hasher.hash(normalizedPassword) : null;

      const user = await db.transaction(async (tx) => {
        // The user and its canonical login identifier are one identity write:
        // either both persist or neither does.
        const existing = await tx.findOne<{ id: string }>({
          model: 'user',
          where: [{ field: 'email', operator: '=', value: normalizedData.email }],
        });
        if (existing)
          throw Errors.conflict('A user with this email already exists');

        const created = await tx.create<FortressUser>({
          model: 'user',
          data: {
            email: normalizedData.email,
            name: normalizedData.name,
            passwordHash,
            isActive: normalizedData.isActive ?? true,
            emailVerified: false,
          },
        });
        await tx.create({
          model: 'login_identifier',
          data: { userId: created.id, type: 'email', value: normalizedData.email },
        });
        return created;
      });

      const afterCtx: AfterHookContext = { db, config, responseHeaders: new Headers() };
      for (const plugin of plugins) {
        if (plugin.hooks?.afterRegister) {
          // Fail-open: a throwing afterRegister side-effect must not undo a
          // committed user creation (see runAfterLoginHooks).
          try {
            await plugin.hooks.afterRegister(afterCtx, user);
          }
          catch (hookError) {
            logger?.error({ plugin: plugin.name, error: hookError }, 'afterRegister hook failed');
          }
        }
      }

      if (authEventListeners.size() > 0) {
        authEventListeners.emit({
          eventType: 'REGISTER',
          actorId: user.id,
          identifier: normalizedData.email,
          method: 'password',
          outcome: 'success',
        });
      }

      return user;
    },

    async verifyToken(token: string): Promise<TokenClaims> {
      const start = performance.now();
      try {
        const claims = await verifyAccessToken(token, resolved.key, {
          issuer: resolved.issuer,
          ...(resolved.audience !== undefined ? { audience: resolved.audience } : {}),
        });
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

    async signToken(claims: Omit<TokenClaims, 'iat' | 'exp' | 'aud'>): Promise<string> {
      return signAccessToken(claims, resolved.key, resolved.accessTokenExpiry, {
        audience: resolved.audience,
      });
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
        data: { userId, type, value: type === 'email' ? normalizeEmail(value) : value },
      });
    },

    async removeLoginIdentifier(userId: string, type: LoginIdentifierType, value: string): Promise<void> {
      const normalizedValue = type === 'email' ? normalizeEmail(value) : value;
      await db.delete({
        model: 'login_identifier',
        where: [
          { field: 'userId', operator: '=', value: userId },
          { field: 'type', operator: '=', value: type },
          { field: 'value', operator: '=', value: normalizedValue },
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
    ): Promise<AuthResult> {
      // Defense in depth for programmatic callers. The HTTP route also
      // enforces this via endpoint metadata before dispatch, but direct
      // service calls must fail closed too.
      const adminPermissions = await adapter.getSubjectPermissions({ type: 'USER', id: adminUserId });
      if (!evaluatePermissions(adminPermissions, 'fortress', 'impersonate', evaluationMode)) {
        throw Errors.forbidden('Insufficient permissions', {
          details: { requiredPermission: 'fortress:impersonate' },
        });
      }

      const targetUser = await db.findOne<FortressUser>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: targetUserId }],
      });

      if (!targetUser || !targetUser.isActive) {
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
        { audience: resolved.audience },
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
      const normalizedEmail = data.email === undefined ? undefined : normalizeEmail(data.email);

      const updateData: Record<string, unknown> = {};
      if (data.name !== undefined)
        updateData.name = data.name;
      if (normalizedEmail !== undefined)
        updateData.email = normalizedEmail;
      if (data.isActive !== undefined)
        updateData.isActive = data.isActive;
      let credentialChanged = false;
      if (data.password !== undefined) {
        // Match createUser semantics: validate unconditionally and await.
        // The original code missed the await on a Promise — a breached or
        // weak password would surface as an unhandled rejection while the
        // hash was happily persisted (M1).
        const normalizedPassword = normalizePasswordInput(data.password);
        await validatePassword(normalizedPassword, config.passwordPolicy, passwordPolicyObserver);
        updateData.passwordHash = await hasher.hash(normalizedPassword);
        credentialChanged = true;
      }

      const updated = await db.transaction(async (tx) => {
        // Serialize the read/modify/write across PostgreSQL processes. SQLite's
        // adapter transaction chain already serializes writers on its single
        // connection. Re-reading only after the lock prevents a stale old
        // email from missing the identifier row during concurrent updates.
        if (tx.dialect === 'pg' && tx.rawQuery && NUMERIC_SUBJECT_ID_RE.test(userId)) {
          await tx.rawQuery(
            'SELECT pg_advisory_xact_lock(117993, CAST(? AS integer))',
            [userId],
          );
        }
        const existing = await tx.findOne<FortressUser>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: userId }],
        });
        if (!existing)
          throw Errors.notFound('User not found');

        if (normalizedEmail !== undefined && normalizedEmail !== existing.email) {
          const duplicate = await tx.findOne<{ id: string }>({
            model: 'user',
            where: [{ field: 'email', operator: '=', value: normalizedEmail }],
          });
          if (duplicate)
            throw Errors.conflict('A user with this email already exists');
        }

        const persisted = await tx.update<FortressUser & { passwordHash?: string }>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: userId }],
          data: updateData,
        });
        if (!persisted)
          throw Errors.notFound('User not found');

        // Update the primary email identifier atomically with the user row.
        if (normalizedEmail !== undefined && normalizedEmail !== existing.email) {
          await tx.update({
            model: 'login_identifier',
            where: [
              { field: 'userId', operator: '=', value: userId },
              { field: 'type', operator: '=', value: 'email' },
              { field: 'value', operator: '=', value: existing.email },
            ],
            data: { value: normalizedEmail },
          });
        }

        if (credentialChanged) {
          await tx.update({
            model: 'refresh_token',
            where: [
              { field: 'userId', operator: '=', value: userId },
              { field: 'isRevoked', operator: '=', value: false },
            ],
            data: { isRevoked: true },
          });
        }
        return persisted;
      });

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
