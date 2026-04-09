/**
 * Modern entry point for the Express adapter: register a single fortress
 * middleware that detects Fortress-managed paths and delegates to
 * `fortress.handleRequest`.
 *
 * Bridges Express's `(req, res, next)` callback style to/from web-standard
 * `Request`/`Response`. User routes registered before `mountFortress` keep
 * working — Express's middleware order means earlier handlers win.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { mountFortress } from '@bajustone/fortress/express';
 *
 * const app = express();
 * app.use(express.json());
 * mountFortress(app, fortress);
 * ```
 */

import type { Fortress } from '../core/fortress';
import type { ExpressMiddleware, ExpressNextFunction, ExpressRequest, ExpressResponse } from './middleware';
import {
  getPluginPathPrefixes,
  isFortressPath,
} from '../core/http/fortress-rbac';

interface ExpressApp {
  use: (path: string | ExpressMiddleware, handler?: ExpressMiddleware) => void;
}

/** Options for {@link mountFortress}. */
export interface MountFortressOptions {
  /** Optional path prefix (e.g. `/api`). Stripped before delegating to core. */
  prefix?: string;
}

/**
 * Mount a single Express middleware that delegates Fortress-managed paths to
 * `fortress.handleRequest` and otherwise calls `next()` so user routes run
 * normally.
 *
 * Cookies emitted by login/refresh/impersonate are passed through verbatim
 * via `Set-Cookie` headers, the way the browser expects them.
 */
export function mountFortress(
  app: ExpressApp,
  fortress: Fortress,
  options: MountFortressOptions = {},
): void {
  const prefix = options.prefix ?? '';
  const plugins = fortress.config.plugins ?? [];
  const pluginPathPrefixes = getPluginPathPrefixes(plugins);

  const middleware: ExpressMiddleware = async (req, res, next) => {
    let pathname = req.path;
    if (prefix && pathname.startsWith(prefix)) {
      pathname = pathname.slice(prefix.length) || '/';
    }
    else if (prefix) {
      next();
      return;
    }

    if (!isFortressPath(pathname, pluginPathPrefixes)) {
      next();
      return;
    }

    try {
      const request = expressToWebRequest(req, pathname);
      const response = await fortress.handleRequest(request);
      await sendWebResponseToExpress(response, res);
    }
    catch (err) {
      next(err);
    }
  };

  app.use(middleware);
}

/**
 * Convert an Express request to a web-standard `Request`. Headers, method,
 * URL, and body (for non-GET/HEAD) are preserved. The host comes from the
 * `host` header so the URL is parseable.
 */
function expressToWebRequest(req: ExpressRequest, pathname: string): Request {
  const host = (req.headers.host as string | undefined) ?? 'localhost';
  const protocol = ((req as { protocol?: string }).protocol) ?? 'http';
  const search = ((req as { originalUrl?: string }).originalUrl ?? '').includes('?')
    ? `?${((req as { originalUrl?: string }).originalUrl as string).split('?')[1]}`
    : '';
  const url = `${protocol}://${host}${pathname}${search}`;

  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) {
      for (const item of v) headers.append(k, item);
    }
    else if (typeof v === 'string') {
      headers.set(k, v);
    }
  }

  const init: RequestInit = { method: req.method, headers };

  // Express body parsers (express.json(), etc.) populate `req.body` as a
  // parsed object. Re-serialize for the body of the web Request so core's
  // body parsing sees the same data.
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const body = (req as { body?: unknown }).body;
    if (body !== undefined && body !== null) {
      if (typeof body === 'string') {
        init.body = body;
      }
      else if (body instanceof Uint8Array) {
        init.body = body as BodyInit;
      }
      else {
        init.body = JSON.stringify(body);
        if (!headers.has('content-type')) {
          headers.set('content-type', 'application/json');
        }
      }
    }
  }

  return new Request(url, init);
}

/**
 * Pipe a web-standard `Response` back into an Express response. Status,
 * headers (including multiple `Set-Cookie`), and body bytes are forwarded.
 */
async function sendWebResponseToExpress(
  response: Response,
  res: ExpressResponse,
): Promise<void> {
  res.status(response.status);

  // Forward all headers, including multi-valued Set-Cookie.
  const setCookies = response.headers.getSetCookie();
  for (const [k, v] of response.headers) {
    if (k.toLowerCase() === 'set-cookie')
      continue;
    res.setHeader(k, v);
  }
  if (setCookies.length > 0) {
    // Express's setHeader supports an array for set-cookie.
    (res as { setHeader: (name: string, value: string | string[]) => void })
      .setHeader('set-cookie', setCookies);
  }

  // Stream / buffer body. Most fortress responses are small JSON, so we
  // buffer to keep the bridge simple. JSON responses are parsed and re-sent
  // through `res.json()` so Express's content-type handling and our test
  // mocks (which only stub `res.json`) both work uniformly.
  const text = await response.text();
  const isJson = (response.headers.get('content-type') ?? '').includes('json');
  if (isJson) {
    try {
      res.json(JSON.parse(text));
    }
    catch {
      res.json({ raw: text });
    }
  }
  else {
    const resWithSend = res as unknown as { send?: (body: string) => void };
    if (resWithSend.send) {
      resWithSend.send(text);
    }
    else {
      res.json(text);
    }
  }
}

// Re-export for users that pull the type via the index
export type { ExpressNextFunction, ExpressRequest, ExpressResponse };
