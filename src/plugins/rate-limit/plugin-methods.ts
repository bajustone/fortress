import type { AnyFortress } from '../../core/fortress';
import type { RateLimitMethods } from './index';

/** Minimal plugin surface consumed by the framework wrappers. */
export type RateLimitCheckMethods = Pick<RateLimitMethods, 'check'>;

export function isRateLimitMethods(value: unknown): value is RateLimitCheckMethods {
  return typeof value === 'object'
    && value !== null
    && typeof Reflect.get(value, 'check') === 'function';
}

export function resolveRateLimitMethods(fortress: AnyFortress): RateLimitCheckMethods {
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
