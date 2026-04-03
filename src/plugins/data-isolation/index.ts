// TODO: Implement dataIsolation() plugin factory
// - General-purpose row-level data isolation
// - scopeRules: auto-inject WHERE on reads + defaults on creates
// - Configurable scopes: org, site, department, region, etc.
// - Bypass: withoutScope(name, fn), unscoped(fn)
// - Works on any database (PostgreSQL, MySQL, SQLite)

export {};
