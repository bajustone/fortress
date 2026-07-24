import type { ApiKeyMethods } from '../plugins/api-key';
import type { AuditLogMethods } from '../plugins/audit-log';
import type { DataIsolationMethods } from '../plugins/data-isolation';
import type { EmailVerificationMethods } from '../plugins/email-verification';
import type { MagicLinkMethods } from '../plugins/magic-link';
import type { OAuthMethods } from '../plugins/oauth';
import type { OpenAPIMethods } from '../plugins/openapi';
import type { SocialLoginMethods } from '../plugins/social-login';
import type { TenancyMethods } from '../plugins/tenancy';
import type { TwoFactorMethods } from '../plugins/two-factor';
import type { WebAuthnMethods } from '../plugins/webauthn';
import type { EndpointDefinition, InferEndpointCallInput, InferEndpointSuccessResponse } from './endpoint';
import type { CallOptions } from './http/call';
import type { FortressPlugin } from './plugin';

/**
 * Type-level map of every built-in plugin name to its method-surface
 * interface. {@link InferPlugins} uses this to expose typed plugin methods
 * on the fortress instance.
 */
export interface PluginMethodsMap {
  'api-key': ApiKeyMethods;
  'audit-log': AuditLogMethods;
  'data-isolation': DataIsolationMethods;
  'email-verification': EmailVerificationMethods;
  'magic-link': MagicLinkMethods;
  'oauth': OAuthMethods;
  'openapi': OpenAPIMethods;
  'social-login': SocialLoginMethods;
  'tenancy': TenancyMethods;
  'two-factor': TwoFactorMethods;
  'webauthn': WebAuthnMethods;
}

/** Infer the typed plugin-methods record from a `plugins` tuple passed to {@link createFortress}. */
export type InferPlugins<T extends readonly FortressPlugin[]> = {
  [P in T[number] as P['name']]: P['name'] extends keyof PluginMethodsMap
    ? PluginMethodsMap[P['name']]
    : Record<string, (...args: any[]) => any>;
};

// ── Typed call map helpers ──────────────────────────────────────────

/** Distributes a union into an intersection, using `unknown` as the empty intersection identity. */
type UnionToIntersection<U> = [U] extends [never]
  ? unknown
  : (U extends any ? (x: U) => void : never) extends ((x: infer I) => void) ? I : never;

/**
 * Turn a record of {@link EndpointDefinition}s into a record of typed
 * callables: each key becomes a function whose input is the endpoint's
 * inferred body+query+params intersection and whose output is the inferred
 * success-response body.
 */
export type CallableForEndpoints<E> = {
  [K in keyof E as E[K] extends EndpointDefinition<any, any, any, any> ? K : never]:
  E[K] extends EndpointDefinition<any, any, any, any>
    ? (
        input: InferEndpointCallInput<E[K]>,
        options?: CallOptions,
      ) => Promise<InferEndpointSuccessResponse<E[K]>>
    : never;
};

/** A plugin without a concrete routes property contributes nothing to the call intersection. */
type PluginCallContributor<P> = P extends { routes: infer R }
  ? CallableForEndpoints<R>
  : never;

/**
 * Infer the typed call surface contributed by a plugins tuple. Walks every
 * plugin's `routes` record (if present) and intersects the callables into one
 * flat object keyed by handler name.
 */
export type InferPluginCallMap<T extends readonly FortressPlugin[]> = UnionToIntersection<
  PluginCallContributor<T[number]>
>;
