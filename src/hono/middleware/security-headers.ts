import type { MiddlewareHandler } from 'hono';

/** Options accepted by {@link createSecurityHeadersMiddleware}. */
export interface SecurityHeadersConfig {
  /** Strict-Transport-Security max-age in seconds. Default: 63072000 (2 years). Set to 0 to disable. */
  hstsMaxAge?: number;
  /** Include subdomains in HSTS. Default: true. */
  hstsIncludeSubdomains?: boolean;
  /** HSTS preload flag. Default: false. */
  hstsPreload?: boolean;
  /** X-Frame-Options value. Default: 'DENY'. Set to false to disable. */
  frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  /** X-Content-Type-Options nosniff. Default: true. */
  noSniff?: boolean;
  /** Content-Security-Policy value. Default: "default-src 'self'". Set to false to disable. */
  contentSecurityPolicy?: string | false;
  /** Referrer-Policy value. Default: 'strict-origin-when-cross-origin'. Set to false to disable. */
  referrerPolicy?: string | false;
  /** X-Permitted-Cross-Domain-Policies value. Default: 'none'. Set to false to disable. */
  permittedCrossDomainPolicies?: string | false;
}

/**
 * Hono middleware that sets security-related HTTP headers.
 * All headers are enabled by default with secure values.
 */
export function createSecurityHeadersMiddleware(config: SecurityHeadersConfig = {}): MiddlewareHandler {
  const hstsMaxAge = config.hstsMaxAge ?? 63072000;
  const hstsIncludeSubdomains = config.hstsIncludeSubdomains ?? true;
  const hstsPreload = config.hstsPreload ?? false;
  const frameOptions = config.frameOptions ?? 'DENY';
  const noSniff = config.noSniff ?? true;
  const csp = config.contentSecurityPolicy ?? 'default-src \'self\'';
  const referrerPolicy = config.referrerPolicy ?? 'strict-origin-when-cross-origin';
  const crossDomain = config.permittedCrossDomainPolicies ?? 'none';

  // Pre-build HSTS header value
  let hstsValue: string | null = null;
  if (hstsMaxAge > 0) {
    hstsValue = `max-age=${hstsMaxAge}`;
    if (hstsIncludeSubdomains)
      hstsValue += '; includeSubDomains';
    if (hstsPreload)
      hstsValue += '; preload';
  }

  return async (c, next) => {
    try {
      await next();
    }
    finally {
      // Apply to success and error responses alike. Security headers should
      // not disappear on the responses most likely to contain diagnostics.
      if (hstsValue)
        c.header('Strict-Transport-Security', hstsValue);
      if (frameOptions)
        c.header('X-Frame-Options', frameOptions);
      if (noSniff)
        c.header('X-Content-Type-Options', 'nosniff');
      if (csp)
        c.header('Content-Security-Policy', csp);
      if (referrerPolicy)
        c.header('Referrer-Policy', referrerPolicy);
      if (crossDomain)
        c.header('X-Permitted-Cross-Domain-Policies', crossDomain);
    }
  };
}
