// --- Identity ---

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

export interface AuthTokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResponseSuccess {
  status: 'success';
  user: FortressUser;
  accessToken: string;
  refreshToken: string;
  pluginData?: Record<string, unknown>;
}

export interface AuthResponseImpersonation {
  status: 'impersonation';
  user: FortressUser;
  accessToken: string;
  refreshToken: null;
  pluginData?: Record<string, unknown>;
}

export interface AuthResponsePending {
  status: 'pending';
  user: FortressUser;
  accessToken: null;
  refreshToken: null;
  pluginData?: Record<string, unknown>;
}

export type AuthResponse = AuthResponseSuccess | AuthResponseImpersonation | AuthResponsePending;

export interface RequestMeta {
  ipAddress?: string;
  userAgent?: string;
  deviceName?: string;
}

export interface SessionInfo {
  id: number;
  ipAddress: string | null;
  userAgent: string | null;
  deviceName: string | null;
  createdAt: Date;
  lastActiveAt: Date | null;
}

export interface CreateUserInput {
  email: string;
  name: string;
  password?: string;
  isActive?: boolean;
}

// --- IAM ---

export type SubjectType = 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';

export interface Permission {
  id: number;
  resource: string;
  action: string;
  effect: 'ALLOW' | 'DENY';
  conditions?: PermissionCondition[];
  description?: string;
}

export interface PermissionInput {
  resource: string;
  action: string;
  effect?: 'ALLOW' | 'DENY';
  conditions?: PermissionCondition[];
}

export interface ConditionRef {
  ref: string;
}

export type ConditionValue = string | string[] | ConditionRef | ConditionRef[];

export interface PermissionCondition {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'startsWith';
  value: ConditionValue;
}

export interface PermissionContext {
  resource?: Record<string, unknown>;
  request?: Record<string, unknown>;
  user?: Record<string, unknown>;
  tenantId?: string;
}

export interface Role {
  id: number;
  name: string;
  description?: string;
  isSystem?: boolean;
}

export interface RoleBinding {
  id: number;
  roleId: number;
  subjectType: SubjectType;
  subjectId: number;
  tenantId?: string | null;
}

export type LoginIdentifierType = 'email' | 'phone' | 'username';

export interface LoginIdentifier {
  id: number;
  userId: number;
  type: LoginIdentifierType;
  value: string;
  /** Reserved for future multi-tenant support. Not yet stored in the database. */
  tenantId?: string | null;
}

export interface Group {
  id: number;
  name: string;
  description?: string;
}
