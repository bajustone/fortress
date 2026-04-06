import type { DatabaseAdapter } from '../adapters/database';
import type {
  FortressUser,
  LoginIdentifier,
  Permission,
  PermissionInput,
} from './types';

// --- Stored types for typed queries ---

export interface StoredRefreshToken {
  id: number;
  userId: number;
  tokenFamily: string;
  isRevoked: boolean;
  expiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
  deviceName: string | null;
  lastActiveAt: Date | null;
  fingerprintHash: string | null;
}

// --- Interface ---

export interface InternalAdapter {
  /** Resolve user via login_identifier lookup, falling back to direct email match */
  findUserByIdentifier: (identifier: string) => Promise<(FortressUser & { passwordHash: string | null }) | null>;
  /** Get group names for a user via group_user → group resolution */
  getUserGroups: (userId: number) => Promise<string[]>;
  /** Find a refresh token by its SHA-256 hash */
  findRefreshTokenByHash: (tokenHash: string) => Promise<StoredRefreshToken | null>;
  /** Get all permissions for a user through direct + group role bindings */
  getUserPermissions: (userId: number) => Promise<Permission[]>;
  /** Find an existing permission or create it if missing */
  findOrCreatePermission: (input: PermissionInput) => Promise<Permission>;
  /** Ensure a resource exists (no-op if already present) */
  ensureResource: (name: string) => Promise<void>;
}

// --- Factory ---

export function createInternalAdapter(db: DatabaseAdapter): InternalAdapter {
  return {
    async findUserByIdentifier(identifier: string): Promise<(FortressUser & { passwordHash: string | null }) | null> {
      // Try login_identifier first
      const loginId = await db.findOne<LoginIdentifier>({
        model: 'login_identifier',
        where: [{ field: 'value', operator: '=', value: identifier }],
      });

      if (loginId) {
        return db.findOne<FortressUser & { passwordHash: string | null }>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: loginId.userId }],
        });
      }

      // Fallback: direct email lookup
      return db.findOne<FortressUser & { passwordHash: string | null }>({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: identifier }],
      });
    },

    async getUserGroups(userId: number): Promise<string[]> {
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
    },

    async findRefreshTokenByHash(tokenHash: string): Promise<StoredRefreshToken | null> {
      return db.findOne<StoredRefreshToken>({
        model: 'refresh_token',
        where: [{ field: 'tokenHash', operator: '=', value: tokenHash }],
      });
    },

    async getUserPermissions(userId: number): Promise<Permission[]> {
      // Optimized path: single JOIN query when rawQuery is available
      if (db.rawQuery) {
        const rows = await db.rawQuery<Permission>(
          `SELECT DISTINCT p.id, p.resource, p.action, p.effect, p.conditions, p.description
           FROM fortress_permission p
           WHERE p.id IN (
             -- Role-based permissions
             SELECT rp.permission_id FROM fortress_role_permission rp
             JOIN fortress_role_binding rb ON rb.role_id = rp.role_id
             WHERE (rb.subject_type = 'USER' AND rb.subject_id = ?)
                OR (rb.subject_type = 'GROUP' AND rb.subject_id IN (
                  SELECT gu.group_id FROM fortress_group_user gu WHERE gu.user_id = ?
                ))
             UNION
             -- Direct permission bindings
             SELECT dpb.permission_id FROM fortress_direct_permission_binding dpb
             WHERE (dpb.subject_type = 'USER' AND dpb.subject_id = ?)
                OR (dpb.subject_type = 'GROUP' AND dpb.subject_id IN (
                  SELECT gu.group_id FROM fortress_group_user gu WHERE gu.user_id = ?
                ))
           )`,
          [userId, userId, userId, userId],
        );
        return rows.map(r => ({
          ...r,
          conditions: typeof r.conditions === 'string' ? JSON.parse(r.conditions) : r.conditions,
        }));
      }

      // Fallback: sequential findMany queries
      // 1. Group memberships (shared by role-based and direct paths)
      const groupMemberships = await db.findMany<{ groupId: number }>({
        model: 'group_user',
        where: [{ field: 'userId', operator: '=', value: userId }],
      });
      const groupIds = groupMemberships.map(m => m.groupId);

      // 2. Role-based permission IDs
      const directRoleBindings = await db.findMany<{ roleId: number }>({
        model: 'role_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'USER' },
          { field: 'subjectId', operator: '=', value: userId },
        ],
      });

      let groupRoleBindings: { roleId: number }[] = [];
      if (groupIds.length > 0) {
        groupRoleBindings = await db.findMany<{ roleId: number }>({
          model: 'role_binding',
          where: [
            { field: 'subjectType', operator: '=', value: 'GROUP' },
            { field: 'subjectId', operator: 'in', value: groupIds },
          ],
        });
      }

      const roleIds = [...new Set([
        ...directRoleBindings.map(b => b.roleId),
        ...groupRoleBindings.map(b => b.roleId),
      ])];

      let rolePermissionIds: number[] = [];
      if (roleIds.length > 0) {
        const rolePerms = await db.findMany<{ permissionId: number }>({
          model: 'role_permission',
          where: [{ field: 'roleId', operator: 'in', value: roleIds }],
        });
        rolePermissionIds = rolePerms.map(rp => rp.permissionId);
      }

      // 3. Direct permission binding IDs
      const directUserBindings = await db.findMany<{ permissionId: number }>({
        model: 'direct_permission_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'USER' },
          { field: 'subjectId', operator: '=', value: userId },
        ],
      });

      let directGroupBindings: { permissionId: number }[] = [];
      if (groupIds.length > 0) {
        directGroupBindings = await db.findMany<{ permissionId: number }>({
          model: 'direct_permission_binding',
          where: [
            { field: 'subjectType', operator: '=', value: 'GROUP' },
            { field: 'subjectId', operator: 'in', value: groupIds },
          ],
        });
      }

      // 4. Merge and deduplicate permission IDs
      const allPermissionIds = [...new Set([
        ...rolePermissionIds,
        ...directUserBindings.map(b => b.permissionId),
        ...directGroupBindings.map(b => b.permissionId),
      ])];

      if (allPermissionIds.length === 0)
        return [];

      // 5. Fetch actual permissions
      return db.findMany<Permission>({
        model: 'permission',
        where: [{ field: 'id', operator: 'in', value: allPermissionIds }],
      });
    },

    async findOrCreatePermission(input: PermissionInput): Promise<Permission> {
      const existing = await db.findOne<Permission>({
        model: 'permission',
        where: [
          { field: 'resource', operator: '=', value: input.resource },
          { field: 'action', operator: '=', value: input.action },
        ],
      });

      if (existing)
        return existing;

      return db.create<Permission>({
        model: 'permission',
        data: {
          resource: input.resource,
          action: input.action,
          effect: input.effect ?? 'ALLOW',
          conditions: input.conditions ? JSON.stringify(input.conditions) : null,
          description: `${input.action} ${input.resource}`,
        },
      });
    },

    async ensureResource(name: string): Promise<void> {
      const existing = await db.findOne<{ name: string }>({
        model: 'resource',
        where: [{ field: 'name', operator: '=', value: name }],
      });

      if (!existing) {
        await db.create({ model: 'resource', data: { name } });
      }
    },
  };
}
