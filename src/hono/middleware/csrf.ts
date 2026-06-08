import type { MiddlewareHandler } from 'hono';
import { matchesSkipPath } from '../../core/http/csrf';

/** Options accepted by {@link createCsrfMiddleware}. */
export interface CsrfConfig {
  /** Header name to check. Default: 'X-Fortress-CSRF'. */
  headerName?: string;
  /** Paths to skip CSRF checking. */
  skipPaths?: string[];
  /** HTTP methods that don't need CSRF checking. Default: ['GET', 'HEAD', 'OPTIONS']. */
  safeMethods?: string[];
}

/**
 * CSRF middleware using the custom-header strategy.
 *
 * Browsers enforce CORS preflight on custom headers, so cross-origin requests
 * cannot set them without explicit server permission. This middleware requires
 * a specific header to be present on non-safe HTTP methods.
 *
 * Additionally checks `Sec-Fetch-Site` to reject cross-site requests.
 */
export function createCsrfMiddleware(config?: CsrfConfig): MiddlewareHandler {
  const headerName = config?.headerName ?? 'X-Fortress-CSRF';
  const skipPaths = config?.skipPaths ?? [];
  const safeMethods = config?.safeMethods ?? ['GET', 'HEAD', 'OPTIONS'];

  return async (c, next): Promise<Response | void> => {
    const method = c.req.method.toUpperCase();

    // Safe methods don't need CSRF protection
    if (safeMethods.includes(method)) {
      await next();
      return;
    }

    // Check skip paths. Reuse the core matcher so this helper and the
    // pipeline agree: skips match at segment boundaries only (an exact match
    // or a `${skip}/` prefix), so `/api/public` never silently skips a
    // sibling like `/api/public-keys`.
    const path = new URL(c.req.url).pathname;
    if (matchesSkipPath(path, skipPaths)) {
      await next();
      return;
    }

    // Check Sec-Fetch-Site header - reject cross-site requests
    const fetchSite = c.req.header('Sec-Fetch-Site');
    if (fetchSite === 'cross-site') {
      return c.json({ error: 'CSRF_REJECTED', message: 'Cross-site requests are not allowed' }, 403);
    }

    // Require the custom CSRF header
    const csrfHeader = c.req.header(headerName);
    if (!csrfHeader) {
      return c.json({ error: 'CSRF_MISSING', message: 'Missing CSRF header' }, 403);
    }

    await next();
  };
}
