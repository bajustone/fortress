// --- Identity ---

/** A fortress user record as returned by the database adapter. */
export interface FortressUser {
  id: number;
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
  sub: number;
  name: string;
  groups: string[];
  iss: string;
  iat: number;
  exp: number;
  act?: { sub: number }; // RFC 8693 actor claim for impersonation
  customClaims?: Record<string, unknown>;
}

/** A short-lived access token paired with its longer-lived refresh token. */
export interface AuthTokenPair {
  accessToken: string;
  refreshToken: string;
}

/** Successful sign-in / refresh result — both tokens are issued. */
export interface AuthResponseSuccess {
  status: 'success';
  user: FortressUser;
  accessToken: string;
  refreshToken: string;
  pluginData?: Record<string, unknown>;
}

/** Impersonation sign-in result — only an access token is issued (refresh is suppressed for safety). */
export interface AuthResponseImpersonation {
  status: 'impersonation';
  user: FortressUser;
  accessToken: string;
  refreshToken: null;
  pluginData?: Record<string, unknown>;
}

/** Pending sign-in result — the user must complete an additional step (e.g. 2FA, email verification) before tokens are issued. */
export interface AuthResponsePending {
  status: 'pending';
  user: FortressUser;
  accessToken: null;
  refreshToken: null;
  pluginData?: Record<string, unknown>;
}

/** Discriminated union of every possible auth flow outcome. */
export type AuthResponse = AuthResponseSuccess | AuthResponseImpersonation | AuthResponsePending;

/** Per-request metadata fortress threads through hooks for audit logging, lockout, and trusted-device tracking. */
export interface RequestMeta {
  ipAddress?: string;
  userAgent?: string;
  deviceName?: string;
}

/** A persisted refresh-token session as exposed to session-management UIs. */
export interface SessionInfo {
  id: number;
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

/** A persisted IAM permission — a (resource, action) pair with optional conditions and an allow/deny effect. */
export interface Permission {
  id: number;
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
}

/** A persisted IAM role grouping a set of {@link Permission}s. */
export interface Role {
  id: number;
  name: string;
  description?: string;
  isSystem?: boolean;
}

/** Binding of a {@link Role} to a subject (user, group, or service account), optionally scoped to a tenant. */
export interface RoleBinding {
  id: number;
  roleId: number;
  subjectType: SubjectType;
  subjectId: number;
  tenantId?: string | null;
}

/** The kind of identifier a user can sign in with. */
export type LoginIdentifierType = 'email' | 'phone' | 'username';

/** A persisted login identifier (e.g. email, phone, username) attached to a user. */
export interface LoginIdentifier {
  id: number;
  userId: number;
  type: LoginIdentifierType;
  value: string;
  /** Reserved for future multi-tenant support. Not yet stored in the database. */
  tenantId?: string | null;
}

/** A persisted IAM group used to grant permissions to many users at once. */
export interface Group {
  id: number;
  name: string;
  description?: string;
}
