// TODO: Implement apiKey() plugin factory
// - Long-lived API keys for service accounts, POS devices, M2M
// - Key format: {prefix}_sk_{env}_{random}, SHA256 hash-only storage
// - Scope restriction: resource:action intersected with account permissions
// - Middleware: resolve API keys alongside JWTs
// - Methods: create, list, revoke, rotate
// - Models: api_key

export {};
