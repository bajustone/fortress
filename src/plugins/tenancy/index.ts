// TODO: Implement tenancy() plugin factory
// - PostgreSQL only: schema-per-tenant isolation via SET LOCAL search_path
// - wrapAdapter: scopes queries to tenant schema
// - middleware: reads X-Tenant-Code header
// - enrichTokenClaims: adds tenantId, tenantCode
// - Methods: createTenant, addUserToTenant, getUserTenants, switchTenant
// - Models: tenant, tenant_user

export {};
