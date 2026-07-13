import type { DatabaseAdapter } from '../adapters/database';
import type {
  FortressUser,
  LoginIdentifier,
  PendingReason,
  Permission,
  PermissionInput,
  ServiceAccount,
  Subject,
} from './types';

// --- Stored types for typed queries ---

export interface StoredRefreshToken {
  id: string;
  userId: string;
  tokenFamily: string;
  familyCreatedAt: Date;
  successorTokenHash: string | null;
  rotatedAt: Date | null;
  isRevoked: boolean;
  expiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
  deviceName: string | null;
  lastActiveAt: Date | null;
  fingerprintHash: string | null;
}

/** Hashed, short-lived state for completing a pending authentication flow. */
export interface StoredContinuation {
  id: string;
  userId: string;
  tokenHash: string;
  reason: PendingReason;
  expiresAt: Date;
  consumedAt: Date | null;
  createdAt: Date;
}

// --- Interface ---

export interface InternalAdapter {
  /** Resolve user via login_identifier lookup, falling back to direct email match */
  findUserByIdentifier: (identifier: string) => Promise<(FortressUser & { passwordHash: string | null }) | null>;
  /** Get group names for a user via group_user → group resolution */
  getUserGroups: (userId: string) => Promise<string[]>;
  /** Find a refresh token by its SHA-256 hash */
  findRefreshTokenByHash: (tokenHash: string) => Promise<StoredRefreshToken | null>;
  /**
   * Resolve every permission that applies to a subject. For `USER` subjects,
   * walks group memberships and unions their bindings. For `SERVICE_ACCOUNT`
   * and other non-user subjects, only direct bindings on that subject are
   * considered. Inactive service accounts return an empty list (the isActive
   * gate is a second layer of defense alongside the api-key resolver).
   */
  getSubjectPermissions: (subject: Subject, tenantId?: string) => Promise<Permission[]>;
  /** Find an existing permission or create it if missing */
  findOrCreatePermission: (input: PermissionInput) => Promise<Permission>;
  /** Ensure a resource exists (no-op if already present) */
  ensureResource: (name: string) => Promise<void>;
}

// --- Factory ---

function normalizePermission(permission: Permission): Permission {
  return {
    ...permission,
    conditions: typeof permission.conditions === 'string'
      ? JSON.parse(permission.conditions)
      : permission.conditions,
  };
}

function stableJson(value: unknown): unknown {
  if (Array.isArray(value))
    return value.map(stableJson);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort())
      out[key] = stableJson((value as Record<string, unknown>)[key]);
    return out;
  }
  return value;
}

function serializePermissionConditions(
  db: DatabaseAdapter,
  conditions: PermissionInput['conditions'],
): string | PermissionInput['conditions'] | null {
  if (!conditions)
    return null;
  // M8: normalize JSON key order before storage / lookup. SQLite compares
  // text byte-for-byte; PostgreSQL JSONB normalizes object key order on the
  // server, but returning a stable object here keeps adapter behavior
  // consistent and makes tests deterministic.
  const normalized = stableJson(conditions) as PermissionInput['conditions'];
  // PostgreSQL schema stores JSONB; SQLite stores text.
  return db.dialect === 'pg' ? normalized : JSON.stringify(normalized);
}

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

    async getUserGroups(userId: string): Promise<string[]> {
      const memberships = await db.findMany<{ groupId: string }>({
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

    async getSubjectPermissions(subject: Subject, tenantId?: string): Promise<Permission[]> {
      const tenantFilter = tenantId != null;
      const tenantlessFilter = tenantId == null;
      const isUser = subject.type === 'USER';

      // Inactive service accounts never resolve any permissions. This is the
      // second line of defense — the api-key resolver also short-circuits on
      // isActive=false so requests never reach the permission check.
      if (subject.type === 'SERVICE_ACCOUNT') {
        const sa = await db.findOne<ServiceAccount>({
          model: 'service_account',
          where: [{ field: 'id', operator: '=', value: subject.id }],
        });
        if (!sa || !sa.isActive)
          return [];
      }

      // Optimized path: single JOIN query when rawQuery is available
      if (db.rawQuery) {
        const rbTenant = tenantFilter
          ? ' AND (rb.tenant_id = ? OR rb.tenant_id IS NULL)'
          : ' AND rb.tenant_id IS NULL';
        const dpbTenant = tenantFilter
          ? ' AND (dpb.tenant_id = ? OR dpb.tenant_id IS NULL)'
          : ' AND dpb.tenant_id IS NULL';

        // Role-binding predicate: always match the bare subject.
        // For USER subjects, also union group memberships.
        const rbPredicate = isUser
          ? `((rb.subject_type = 'USER' AND rb.subject_id = ?)
             OR (rb.subject_type = 'GROUP' AND rb.subject_id IN (
               SELECT gu.group_id FROM fortress_group_user gu WHERE gu.user_id = ?
             )))`
          : `(rb.subject_type = ? AND rb.subject_id = ?)`;

        const dpbPredicate = isUser
          ? `((dpb.subject_type = 'USER' AND dpb.subject_id = ?)
             OR (dpb.subject_type = 'GROUP' AND dpb.subject_id IN (
               SELECT gu.group_id FROM fortress_group_user gu WHERE gu.user_id = ?
             )))`
          : `(dpb.subject_type = ? AND dpb.subject_id = ?)`;

        const rbParams = isUser
          ? [subject.id, subject.id]
          : [subject.type, subject.id];
        const dpbParams = isUser
          ? [subject.id, subject.id]
          : [subject.type, subject.id];

        const params: unknown[] = [];
        params.push(...rbParams);
        if (tenantFilter)
          params.push(tenantId);
        params.push(...dpbParams);
        if (tenantFilter)
          params.push(tenantId);

        const rows = await db.rawQuery<Permission>(
          `SELECT DISTINCT p.id, p.resource, p.action, p.effect, p.conditions, p.description
           FROM fortress_permission p
           WHERE p.id IN (
             -- Role-based permissions
             SELECT rp.permission_id FROM fortress_role_permission rp
             JOIN fortress_role_binding rb ON rb.role_id = rp.role_id
             WHERE ${rbPredicate}${rbTenant}
             UNION
             -- Direct permission bindings
             SELECT dpb.permission_id FROM fortress_direct_permission_binding dpb
             WHERE ${dpbPredicate}${dpbTenant}
           )
           ORDER BY p.id`,
          params,
        );
        return rows.map(normalizePermission);
      }

      // Fallback: sequential findMany queries
      // Helper to filter bindings by tenant (global bindings always included)
      function matchesTenant<T extends { tenantId?: string | null }>(bindings: T[]): T[] {
        if (tenantlessFilter)
          return bindings.filter(b => b.tenantId == null);
        return bindings.filter(b => b.tenantId == null || b.tenantId === tenantId);
      }

      // 1. Group memberships — USER subjects only. Non-user subjects aren't
      //    members of groups, so skip this lookup entirely.
      let groupIds: string[] = [];
      if (isUser) {
        const groupMemberships = await db.findMany<{ groupId: string }>({
          model: 'group_user',
          where: [{ field: 'userId', operator: '=', value: subject.id }],
        });
        groupIds = groupMemberships.map(m => m.groupId);
      }

      // 2. Role-based permission IDs — direct bindings on the subject.
      const directRoleBindings = matchesTenant(await db.findMany<{ roleId: string; tenantId?: string | null }>({
        model: 'role_binding',
        where: [
          { field: 'subjectType', operator: '=', value: subject.type },
          { field: 'subjectId', operator: '=', value: subject.id },
        ],
      }));

      let groupRoleBindings: { roleId: string; tenantId?: string | null }[] = [];
      if (groupIds.length > 0) {
        groupRoleBindings = matchesTenant(await db.findMany<{ roleId: string; tenantId?: string | null }>({
          model: 'role_binding',
          where: [
            { field: 'subjectType', operator: '=', value: 'GROUP' },
            { field: 'subjectId', operator: 'in', value: groupIds },
          ],
        }));
      }

      const roleIds = [...new Set([
        ...directRoleBindings.map(b => b.roleId),
        ...groupRoleBindings.map(b => b.roleId),
      ])];

      let rolePermissionIds: string[] = [];
      if (roleIds.length > 0) {
        const rolePerms = await db.findMany<{ permissionId: string }>({
          model: 'role_permission',
          where: [{ field: 'roleId', operator: 'in', value: roleIds }],
        });
        rolePermissionIds = rolePerms.map(rp => rp.permissionId);
      }

      // 3. Direct permission binding IDs — on the subject directly.
      const directSubjectBindings = matchesTenant(await db.findMany<{ permissionId: string; tenantId?: string | null }>({
        model: 'direct_permission_binding',
        where: [
          { field: 'subjectType', operator: '=', value: subject.type },
          { field: 'subjectId', operator: '=', value: subject.id },
        ],
      }));

      let directGroupBindings: { permissionId: string; tenantId?: string | null }[] = [];
      if (groupIds.length > 0) {
        directGroupBindings = matchesTenant(await db.findMany<{ permissionId: string; tenantId?: string | null }>({
          model: 'direct_permission_binding',
          where: [
            { field: 'subjectType', operator: '=', value: 'GROUP' },
            { field: 'subjectId', operator: 'in', value: groupIds },
          ],
        }));
      }

      // 4. Merge and deduplicate permission IDs
      const allPermissionIds = [...new Set([
        ...rolePermissionIds,
        ...directSubjectBindings.map(b => b.permissionId),
        ...directGroupBindings.map(b => b.permissionId),
      ])];

      if (allPermissionIds.length === 0)
        return [];

      // 5. Fetch actual permissions
      const permissions = await db.findMany<Permission>({
        model: 'permission',
        where: [{ field: 'id', operator: 'in', value: allPermissionIds }],
      });
      return permissions.map(normalizePermission);
    },

    async findOrCreatePermission(input: PermissionInput): Promise<Permission> {
      const conditions = serializePermissionConditions(db, input.conditions);
      // The partial unique indexes (M8) guarantee at most one row per
      // (resource, action, effect, conditions). Look it up by that tuple,
      // honoring SQL's NULL-distinct rule for the no-conditions case.
      const where = [
        { field: 'resource', operator: '=' as const, value: input.resource },
        { field: 'action', operator: '=' as const, value: input.action },
        { field: 'effect', operator: '=' as const, value: input.effect ?? 'ALLOW' },
        conditions == null
          ? { field: 'conditions', operator: 'isNull' as const, value: null }
          : { field: 'conditions', operator: '=' as const, value: conditions },
      ];

      const existing = await db.findOne<Permission>({ model: 'permission', where });
      if (existing)
        return normalizePermission(existing);

      try {
        const created = await db.create<Permission>({
          model: 'permission',
          data: {
            resource: input.resource,
            action: input.action,
            effect: input.effect ?? 'ALLOW',
            conditions,
            description: `${input.action} ${input.resource}`,
          },
        });
        return normalizePermission(created);
      }
      catch (err) {
        // find-then-create is not atomic: a concurrent caller can insert the
        // same permission between our findOne and create, tripping the unique
        // index. That's the expected outcome, not an error — re-read the row
        // the winner inserted and return it. Re-throw anything that isn't a
        // resolvable duplicate.
        const winner = await db.findOne<Permission>({ model: 'permission', where });
        if (winner)
          return normalizePermission(winner);
        throw err;
      }
    },

    async ensureResource(name: string): Promise<void> {
      const where = [{ field: 'name', operator: '=' as const, value: name }];
      const existing = await db.findOne<{ name: string }>({ model: 'resource', where });
      if (existing)
        return;

      try {
        await db.create({ model: 'resource', data: { name } });
      }
      catch (err) {
        // find-then-create is not atomic — a concurrent caller may have
        // inserted the same resource name (unique). That's the desired end
        // state, so swallow the conflict if the row now exists; re-throw
        // otherwise.
        const winner = await db.findOne<{ name: string }>({ model: 'resource', where });
        if (!winner)
          throw err;
      }
    },
  };
}
