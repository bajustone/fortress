import type { EndpointDefinitionLike } from './endpoint';

/**
 * Whether Fortress should require a resolved subject but skip IAM for an
 * endpoint. Keeping this predicate shared by enforcement and manifest
 * classification prevents their authenticated-only semantics from drifting.
 */
export function isAuthenticationOnlyEndpoint(endpoint: EndpointDefinitionLike): boolean {
  const security = endpoint.meta?.security ?? [];
  return !endpoint.meta?.permission
    && !security.includes('none')
    && (security.includes('bearer') || security.includes('apiKey'));
}
