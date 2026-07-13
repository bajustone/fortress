import type { MiddlewareHandler } from 'hono';

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

    // Check skip paths at segment boundaries: `/foo` covers `/foo/bar` but
    // never `/foobar`. A trailing `/*` is accepted as subtree notation.
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

function matchesSkipPath(path: string, skipPaths: string[]): boolean {
  return skipPaths.some((configured) => {
    const withoutWildcard = configured.endsWith('/*') ? configured.slice(0, -2) : configured;
    const base = withoutWildcard.length > 1 && withoutWildcard.endsWith('/')
      ? withoutWildcard.slice(0, -1)
      : withoutWildcard;
    return path === base || path.startsWith(`${base}/`);
  });
}
