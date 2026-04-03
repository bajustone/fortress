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
           JOIN fortress_role_permission rp ON rp.permission_id = p.id
           JOIN fortress_role_binding rb ON rb.role_id = rp.role_id
           WHERE (rb.subject_type = 'USER' AND rb.subject_id = ?)
              OR (rb.subject_type = 'GROUP' AND rb.subject_id IN (
                SELECT gu.group_id FROM fortress_group_user gu WHERE gu.user_id = ?
              ))`,
          [userId, userId],
        );
        return rows.map(r => ({
          ...r,
          conditions: typeof r.conditions === 'string' ? JSON.parse(r.conditions) : r.conditions,
        }));
      }

      // Fallback: sequential findMany queries
      // 1. Direct role bindings
      const directBindings = await db.findMany<{ roleId: number }>({
        model: 'role_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'USER' },
          { field: 'subjectId', operator: '=', value: userId },
        ],
      });

      // 2. Group memberships
      const groupMemberships = await db.findMany<{ groupId: number }>({
        model: 'group_user',
        where: [{ field: 'userId', operator: '=', value: userId }],
      });

      // 3. Role bindings for user's groups
      let groupBindings: { roleId: number }[] = [];
      if (groupMemberships.length > 0) {
        const groupIds = groupMemberships.map(m => m.groupId);
        groupBindings = await db.findMany<{ roleId: number }>({
          model: 'role_binding',
          where: [
            { field: 'subjectType', operator: '=', value: 'GROUP' },
            { field: 'subjectId', operator: 'in', value: groupIds },
          ],
        });
      }

      // 4. Unique role IDs
      const roleIds = [...new Set([
        ...directBindings.map(b => b.roleId),
        ...groupBindings.map(b => b.roleId),
      ])];

      if (roleIds.length === 0)
        return [];

      // 5. Role → permission mappings
      const rolePermissions = await db.findMany<{ permissionId: number }>({
        model: 'role_permission',
        where: [{ field: 'roleId', operator: 'in', value: roleIds }],
      });

      const permissionIds = [...new Set(rolePermissions.map(rp => rp.permissionId))];
      if (permissionIds.length === 0)
        return [];

      // 6. Actual permissions
      return db.findMany<Permission>({
        model: 'permission',
        where: [{ field: 'id', operator: 'in', value: permissionIds }],
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
