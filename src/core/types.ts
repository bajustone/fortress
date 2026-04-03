// --- Identity ---

export interface FortressUser {
  id: number;
  email: string;
  name: string;
  isActive: boolean;
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
  customClaims?: Record<string, unknown>;
}

export interface AuthTokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResponse {
  user: FortressUser;
  accessToken: string | null;
  refreshToken: string | null;
  pluginData?: Record<string, unknown>;
}

export interface RequestMeta {
  ipAddress?: string;
  userAgent?: string;
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

export interface PermissionCondition {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'startsWith';
  value: string | string[];
}

export interface PermissionContext {
  resource?: Record<string, unknown>;
  request?: Record<string, unknown>;
  user?: Record<string, unknown>;
}

export interface Role {
  id: number;
  name: string;
  description?: string;
}

export interface RoleBinding {
  id: number;
  roleId: number;
  subjectType: SubjectType;
  subjectId: number;
}

export interface Group {
  id: number;
  name: string;
  description?: string;
}
