import type { ApiKeyMethods } from '../plugins/api-key';
import type { AuditLogMethods } from '../plugins/audit-log';
import type { DataIsolationMethods } from '../plugins/data-isolation';
import type { EmailVerificationMethods } from '../plugins/email-verification';
import type { OAuthMethods } from '../plugins/oauth';
import type { SocialLoginMethods } from '../plugins/social-login';
import type { TenancyMethods } from '../plugins/tenancy';
import type { TwoFactorMethods } from '../plugins/two-factor';
import type { WebAuthnMethods } from '../plugins/webauthn';
import type { FortressPlugin } from './plugin';

export interface PluginMethodsMap {
  'api-key': ApiKeyMethods;
  'audit-log': AuditLogMethods;
  'data-isolation': DataIsolationMethods;
  'email-verification': EmailVerificationMethods;
  'oauth': OAuthMethods;
  'social-login': SocialLoginMethods;
  'tenancy': TenancyMethods;
  'two-factor': TwoFactorMethods;
  'webauthn': WebAuthnMethods;
}

/** Infer typed plugin methods from the plugins array */
export type InferPlugins<T extends readonly FortressPlugin[]> = {
  [P in T[number] as P['name']]: P['name'] extends keyof PluginMethodsMap
    ? PluginMethodsMap[P['name']]
    : Record<string, (...args: any[]) => any>;
};
