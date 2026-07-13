// --- Identity ---

/**
 * A fortress user record as returned by the database adapter.
 *
 * `id` is always a string at the fortress API surface. Adapters backed by
 * numeric primary keys are responsible for stringifying on read and parsing
 * on write at the adapter boundary — consumers of fortress never see the
 * underlying representation. This matches the JWT/OIDC `sub` wire shape
 * (RFC 7519 §4.1.2) and unblocks UUID/ULID/snowflake-keyed adapters.
 */
export interface FortressUser {
  id: string;
  email: string;
  name: string;
  isActive: boolean;
  emailVerified?: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// --- Auth ---

/** JWT claims fortress signs into the access token, plus the optional impersonation actor (`act`) and per-deployment custom claims. */
export interface TokenClaims {
  /** Subject identifier — string per RFC 7519 §4.1.2. */
  sub: string;
  /** Subject kind — defaults to 'USER' on legacy tokens that do not carry the claim. */
  subjectType: SubjectType;
  name: string;
  groups: string[];
  iss: string;
  iat: number;
  exp: number;
  act?: { sub: string; subjectType?: SubjectType }; // RFC 8693 actor claim for impersonation
  customClaims?: Record<string, unknown>;
}

/** A short-lived access token paired with its longer-lived refresh token. */
export interface AuthTokenPair {
  accessToken: string;
  refreshToken: string;
}

/** The credential method that completed authentication. Carried on a successful result. */
export type AuthMethod = 'password' | 'refresh' | 'two-factor' | 'webauthn' | 'magic-link' | 'impersonation';

/** Why a sign-in is pending an additional step before tokens are issued. */
export type PendingReason = 'two-factor' | 'webauthn' | 'email-verification' | 'magic-link';

/**
 * The challenge a pending sign-in must satisfy before tokens are issued.
 * `reason` tells the client which step to run; the single-use `continuationToken`
 * is presented back to `auth.completePendingAuth` to finish the flow.
 */
export interface AuthChallenge {
  reason: PendingReason;
  continuationToken: string;
}

/** Successful sign-in / refresh result — both tokens are issued. */
export interface AuthSuccess {
  status: 'success';
  user: FortressUser;
  method: AuthMethod;
  accessToken: string;
  refreshToken: string;
  pluginData?: Record<string, unknown>;
}

/** Impersonation sign-in result — only an access token is issued (refresh is suppressed for safety). */
export interface AuthImpersonation {
  status: 'impersonation';
  user: FortressUser;
  accessToken: string;
  refreshToken: null;
  pluginData?: Record<string, unknown>;
}

/** Pending sign-in result — the user must complete an additional step (e.g. 2FA, email verification) before tokens are issued. */
export interface AuthPending {
  status: 'pending';
  user: FortressUser;
  /** Present for post-auth-gate holds; required once wire consumers migrate. */
  pending?: AuthChallenge;
  accessToken: null;
  refreshToken: null;
  pluginData?: Record<string, unknown>;
}

/** Discriminated union of every possible auth flow outcome. */
export type AuthResult = AuthSuccess | AuthImpersonation | AuthPending;

/** Narrow an {@link AuthResult} to the successful (tokens-issued) variant. */
export function isSuccess(result: AuthResult): result is AuthSuccess {
  return result.status === 'success';
}

/** Narrow an {@link AuthResult} to the pending (additional-step-required) variant. */
export function isPending(result: AuthResult): result is AuthPending {
  return result.status === 'pending';
}

/** Narrow an {@link AuthResult} to the impersonation variant. */
export function isImpersonation(result: AuthResult): result is AuthImpersonation {
  return result.status === 'impersonation';
}

/**
 * Assert an {@link AuthResult} is successful, throwing otherwise. Use when a
 * caller has already ruled out the pending/impersonation variants and wants the
 * token fields without a manual narrow.
 */
export function assertSuccess(result: AuthResult): asserts result is AuthSuccess {
  if (result.status !== 'success')
    throw new Error(`Expected a successful auth result, but got status '${result.status}'`);
}

/** Per-request metadata fortress threads through hooks for audit logging, lockout, and trusted-device tracking. */
export interface RequestMeta {
  ipAddress?: string;
  userAgent?: string;
  deviceName?: string;
}

/** A persisted refresh-token session as exposed to session-management UIs. */
export interface SessionInfo {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  deviceName: string | null;
  createdAt: Date;
  lastActiveAt: Date | null;
}

/** Input shape accepted by `fortress.createUser` and the admin user-creation endpoint. */
export interface CreateUserInput {
  email: string;
  name: string;
  password?: string;
  isActive?: boolean;
}

// --- IAM ---

/** The kind of subject a role or permission can be bound to. */
export type SubjectType = 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';

/** A subject identity — a discriminated (type, id) pair used by IAM and the auth pipeline. */
export interface Subject {
  type: SubjectType;
  id: string;
}

/** A persisted IAM permission — a (resource, action) pair with optional conditions and an allow/deny effect. */
export interface Permission {
  id: string;
  resource: string;
  action: string;
  effect: 'ALLOW' | 'DENY';
  conditions?: PermissionCondition[];
  description?: string;
}

/** Input shape for creating a new {@link Permission}. */
export interface PermissionInput {
  resource: string;
  action: string;
  effect?: 'ALLOW' | 'DENY';
  conditions?: PermissionCondition[];
}

/** Reference to a value resolved from the {@link PermissionContext} at evaluation time. */
export interface ConditionRef {
  ref: string;
}

/** A literal or {@link ConditionRef}-based value used by a {@link PermissionCondition}. */
export type ConditionValue = string | string[] | ConditionRef | ConditionRef[];

/** A single ABAC-style condition guarding a {@link Permission}. */
export interface PermissionCondition {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'startsWith';
  value: ConditionValue;
}

/** Context object passed into the permission evaluator at check time. */
export interface PermissionContext {
  resource?: Record<string, unknown>;
  request?: Record<string, unknown>;
  user?: Record<string, unknown>;
  tenantId?: string;
  /**
   * Optional narrowing scopes from the credential used for this request
   * (for example an API key). `null`/`undefined` means unscoped/full
   * subject permissions; an empty array means no permissions.
   */
  credentialScopes?: string[] | null;
}

/** A persisted IAM role grouping a set of {@link Permission}s. */
export interface Role {
  id: string;
  name: string;
  description?: string;
  isSystem?: boolean;
}

/** Binding of a {@link Role} to a subject (user, group, or service account), optionally scoped to a tenant. */
export interface RoleBinding {
  id: string;
  roleId: string;
  subjectType: SubjectType;
  subjectId: string;
  tenantId?: string | null;
}

/** The kind of identifier a user can sign in with. */
export type LoginIdentifierType = 'email' | 'phone' | 'username';

/** A persisted login identifier (e.g. email, phone, username) attached to a user. */
export interface LoginIdentifier {
  id: string;
  userId: string;
  type: LoginIdentifierType;
  value: string;
  /** Reserved for future multi-tenant support. Not yet stored in the database. */
  tenantId?: string | null;
}

/** A persisted IAM group used to grant permissions to many users at once. */
export interface Group {
  id: string;
  name: string;
  description?: string;
}

/** A persisted IAM service account — a non-human principal that can hold roles and direct permissions. */
export interface ServiceAccount {
  id: string;
  name: string;
  displayName: string | null;
  description: string | null;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/** Input shape for creating a new {@link ServiceAccount}. `name` is the immutable machine identifier. */
export interface CreateServiceAccountInput {
  name: string;
  displayName?: string;
  description?: string;
}
