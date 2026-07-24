import type { FortressPluginRuntime } from '../../core/capabilities';
import type { RateLimitMethods } from './index';

export function isRateLimitMethods(value: unknown): value is RateLimitMethods {
  return typeof value === 'object'
    && value !== null
    && typeof Reflect.get(value, 'check') === 'function'
    && typeof Reflect.get(value, 'listRules') === 'function';
}

export function resolveRateLimitMethods(fortress: Pick<FortressPluginRuntime, 'plugins'>): RateLimitMethods {
  const plugins = fortress.plugins;
  const methods = typeof plugins === 'object' && plugins !== null
    ? Reflect.get(plugins, 'rate-limit')
    : undefined;
  if (!isRateLimitMethods(methods)) {
    throw new Error(
      'rate-limit plugin is not registered — add rateLimit({...}) to your FortressConfig.plugins',
    );
  }
  return methods;
}
