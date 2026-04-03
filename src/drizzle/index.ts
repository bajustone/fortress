export { createDrizzleAdapter } from './adapter';
export type { DrizzleAdapterOptions, DrizzleDialect } from './adapter';
// Re-export only the schema object — individual table exports cause JSR "slow types"
// errors because sqliteTable()/pgTable() return types are too complex for JSR to infer.
// Consumers access tables via: fortressSchema.users, fortressSchema.roles, etc.
export { fortressSchema } from './schema';
