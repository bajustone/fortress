import type { AccountLockoutMethods } from '../plugins/account-lockout';
import type { AdminMethods } from '../plugins/admin';
import type { ApiKeyMethods } from '../plugins/api-key';
import type { AuditLogMethods } from '../plugins/audit-log';
import type { DataIsolationMethods } from '../plugins/data-isolation';
import type { EmailVerificationMethods } from '../plugins/email-verification';
import type { MagicLinkMethods } from '../plugins/magic-link';
import type { OAuthMethods } from '../plugins/oauth';
import type { OpenAPIMethods } from '../plugins/openapi';
import type { RateLimitMethods } from '../plugins/rate-limit';
import type { SocialLoginMethods } from '../plugins/social-login';
import type { TenancyMethods } from '../plugins/tenancy';
import type { TwoFactorMethods } from '../plugins/two-factor';
import type { WebAuthnMethods } from '../plugins/webauthn';
import type { WebhookMethods } from '../plugins/webhook';
import type { EndpointDefinition, InferEndpointCallInput, InferEndpointSuccessResponse } from './endpoint';
import type { CallOptions } from './http/call';
import type { LegacyPluginMethods, PluginMethodsOf, PluginRoutes, PluginRoutesOf, RuntimeFortressPlugin } from './plugin';

/**
 * Legacy augmentation bridge for widened plugin definitions. New plugins
 * should use `definePlugin`, which derives their surface from the definition.
 */
export interface PluginMethodsMap {
  'account-lockout': AccountLockoutMethods;
  'admin': AdminMethods;
  'api-key': ApiKeyMethods;
  'audit-log': AuditLogMethods;
  'data-isolation': DataIsolationMethods;
  'email-verification': EmailVerificationMethods;
  'magic-link': MagicLinkMethods;
  'oauth': OAuthMethods;
  'openapi': OpenAPIMethods;
  'rate-limit': RateLimitMethods;
  'social-login': SocialLoginMethods;
  'tenancy': TenancyMethods;
  'two-factor': TwoFactorMethods;
  'webauthn': WebAuthnMethods;
  'webhook': WebhookMethods;
}

type MethodsForPlugin<P extends RuntimeFortressPlugin> = P extends { methods: (...args: any[]) => infer M extends object }
  ? M
  : keyof PluginMethodsOf<P> extends never
    ? LegacyPluginMethods
    : LegacyPluginMethods extends PluginMethodsOf<P>
      ? P['name'] extends keyof PluginMethodsMap ? PluginMethodsMap[P['name']] : PluginMethodsOf<P>
      : PluginMethodsOf<P>;

/** Infer the typed plugin-methods record from a `plugins` tuple passed to createFortress. */
export type InferPlugins<T extends readonly RuntimeFortressPlugin[]> = {
  [P in T[number] as P['name']]: MethodsForPlugin<P>;
};

/** Distributes a union into an intersection, using `unknown` as the empty intersection identity. */
type UnionToIntersection<U> = [U] extends [never]
  ? unknown
  : (U extends any ? (x: U) => void : never) extends ((x: infer I) => void) ? I : never;

/** Convert endpoint records to their in-process callable surface. */
export type CallableForEndpoints<E> = {
  [K in keyof E as E[K] extends EndpointDefinition<any, any, any, any> ? K : never]:
  E[K] extends EndpointDefinition<any, any, any, any>
    ? (
        input: InferEndpointCallInput<E[K]>,
        options?: CallOptions,
      ) => Promise<InferEndpointSuccessResponse<E[K]>>
    : never;
};

type ConcreteRoutes<R> = [R] extends [PluginRoutes]
  ? undefined extends R
    ? never
    : string extends keyof R ? never : R
  : never;

type PluginCallContributorMember<P> = 'routes' extends keyof P
  ? Record<never, never> extends Pick<P, 'routes' & keyof P>
    ? never
    : P extends { routes: infer R }
      ? R extends PluginRoutes
        ? string extends keyof R ? never : CallableForEndpoints<R>
        : never
      : never
  : ConcreteRoutes<PluginRoutesOf<P>> extends infer R
    ? [R] extends [never] ? never : CallableForEndpoints<R>
    : never;

type PluginCallContributor<P> = P extends any ? PluginCallContributorMember<P> : never;

/** Infer the flat typed call surface contributed by concrete plugin routes. */
export type InferPluginCallMap<T extends readonly RuntimeFortressPlugin[]> = UnionToIntersection<
  PluginCallContributor<T[number]>
>;
