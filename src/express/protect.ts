import type { Fortress } from '../core/fortress';
import type {
  ProtectedRouteContext,
  ProtectedRouteTarget,
  ProtectOptions,
} from '../core/http/protect';
import type { ExpressMiddleware, ExpressRequest, ExpressResponse } from './middleware';
import { protect } from '../core/http/protect';

export type ExpressProtectedRouteHandler<TResult = unknown> = (
  req: ExpressRequest,
  res: ExpressResponse,
  ctx: ProtectedRouteContext,
) => TResult | Response | Promise<TResult | Response>;

/** Wrap a host-owned Express route in Fortress's protection pipeline. */
export function protectedRoute<TResult = unknown>(
  fortress: Fortress,
  target: ProtectedRouteTarget,
  handler: ExpressProtectedRouteHandler<TResult>,
  options: ProtectOptions = {},
): ExpressMiddleware {
  return async (req, res, next) => {
    try {
      const request = expressToWebRequest(req);
      const protectedHandler = protect<TResult>(
        fortress,
        target,
        ctx => handler(req, res, ctx),
        { ...options, method: options.method ?? req.method },
      );
      const response = await protectedHandler(request);
      await sendWebResponseToExpress(response, res);
    }
    catch (err) {
      next(err);
    }
  };
}

function expressToWebRequest(req: ExpressRequest): Request {
  const host = (req.headers.host as string | undefined) ?? 'localhost';
  const protocol = ((req as { protocol?: string }).protocol) ?? 'http';
  const originalUrl = ((req as { originalUrl?: string }).originalUrl) ?? req.path;
  const search = originalUrl.includes('?') ? `?${originalUrl.split('?')[1]}` : '';
  const url = `${protocol}://${host}${req.path}${search}`;

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
        if (!headers.has('content-type'))
          headers.set('content-type', 'application/json');
      }
    }
  }

  return new Request(url, init);
}

async function sendWebResponseToExpress(response: Response, res: ExpressResponse): Promise<void> {
  res.status(response.status);
  for (const [k, v] of response.headers) {
    if (k.toLowerCase() !== 'set-cookie')
      res.setHeader(k, v);
  }
  const setCookies = response.headers.getSetCookie();
  if (setCookies.length > 0) {
    (res as { setHeader: (name: string, value: string | string[]) => void })
      .setHeader('set-cookie', setCookies);
  }

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
    if (resWithSend.send)
      resWithSend.send(text);
    else
      res.json(text);
  }
}

export type { ProtectedRouteContext, ProtectedRouteTarget, ProtectOptions };
