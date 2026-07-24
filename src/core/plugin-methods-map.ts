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
import type { LegacyPluginMethods, PluginMethodsOf, RuntimeFortressPlugin } from './plugin';

/**
 * Legacy augmentation bridge for widened plugin definitions.
 *
 * @deprecated Author plugins with `definePlugin`, which derives the full
 * typed surface from the definition itself — no central registry edit or
 * module augmentation required. This interface remains only so pre-v2
 * `declare module` augmentations keep resolving during migration.
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

type MethodsForPlugin<P extends RuntimeFortressPlugin> = string extends P['name']
  // Erased tuple (non-literal name): claim nothing about the surface so the
  // bare `Fortress` type stays a supertype of every concrete instantiation.
  ? object
  : P extends { methods: (...args: any[]) => infer M extends object }
    ? M
    : 'methods' extends keyof P
      // Keep the deprecated augmentation bridge only for explicitly widened
      // FortressPlugin types. Exact methodless definePlugin results have no
      // `methods` key and therefore expose an empty surface.
      ? LegacyPluginMethods extends PluginMethodsOf<P>
        ? P['name'] extends keyof PluginMethodsMap ? PluginMethodsMap[P['name']] : PluginMethodsOf<P>
        : PluginMethodsOf<P>
      : Record<never, never>;

/** Infer the typed plugin-methods record from a `plugins` tuple passed to createFortress. */
export type InferPlugins<T extends readonly RuntimeFortressPlugin[]> = {
  [P in T[number] as P['name']]: MethodsForPlugin<P>;
};
