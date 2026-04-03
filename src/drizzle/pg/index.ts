// Re-export only the schema object — individual table exports cause JSR "slow types"
// errors because pgTable() return types are too complex for JSR to infer.
// Consumers access tables via: fortressPgSchema.users, fortressPgSchema.roles, etc.
export { fortressPgSchema } from './schema';
