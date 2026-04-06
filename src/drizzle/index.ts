export { createDrizzleAdapter } from './adapter';
export type { DrizzleAdapterOptions, DrizzleDialect } from './adapter';
// Re-export only the schema objects — individual table exports cause JSR "slow types"
// errors because sqliteTable()/pgTable() return types are too complex for JSR to infer.
// Consumers access tables via: fortressSchema.users, fortressPgSchema.roles, etc.
export { fortressPgSchema } from './pg/schema';
export { fortressSchema } from './schema';
