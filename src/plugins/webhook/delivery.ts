/**
 * Webhook delivery over `@bajustone/fetcher`.
 *
 * fetcher is 100% native `fetch` and does **no** IP pinning of its own, so the
 * SSRF guard must live *inside* the transport: {@link ssrfSafeFetch} is a
 * fetcher `FetchFn` that resolves + validates the target and issues the request
 * through `node:https` with a custom `lookup` that pins the connection to the
 * resolved IP — closing the DNS-rebinding window. A plain fetch (or a
 * pre-flight check followed by a normal fetch) would re-resolve DNS and reopen
 * that window, so the guard MUST be the transport.
 *
 * @module
 */

import type { FetchFn } from '@bajustone/fetcher';
import { Buffer } from 'node:buffer';
import { request as httpsRequest } from 'node:https';
import { createFetch } from '@bajustone/fetcher';
import { resolveSafeWebhookTarget } from './ssrf';

/** How retries are handled for a delivery client. See the webhook config docs. */
export type RetryMode = 'pluginScheduled' | 'inProcess' | 'queue';

/**
 * A fetcher `FetchFn` that delivers through `node:https` with the SSRF guard
 * and connect-time IP pinning applied. Resolution + validation + connection
 * all use the same resolved IP, so there is no TOCTOU gap.
 */
export function ssrfSafeFetch(): FetchFn {
  return async (req: Request): Promise<Response> => {
    // Throws on non-https / private / unresolved — fetcher turns the throw
    // into a `{ ok: false }` result via its never-throws contract.
    const target = await resolveSafeWebhookTarget(req.url);
    const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : await req.text();

    const headers: Record<string, string> = {};
    req.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return new Promise<Response>((resolve, reject) => {
      const clientReq = httpsRequest(
        {
          protocol: target.url.protocol,
          hostname: target.url.hostname,
          port: target.url.port || 443,
          path: `${target.url.pathname}${target.url.search}`,
          method: req.method,
          headers,
          // Pin the connection to the exact validated IP (DNS-rebind defense).
          lookup: (_hostname, _options, cb) => cb(null, target.address, target.family),
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', chunk => chunks.push(chunk as Buffer));
          res.on('end', () => {
            const resHeaders = new Headers();
            for (const [key, value] of Object.entries(res.headers)) {
              if (typeof value === 'string')
                resHeaders.set(key, value);
              else if (Array.isArray(value))
                resHeaders.set(key, value.join(', '));
            }
            const status = res.statusCode && res.statusCode >= 200 ? res.statusCode : 502;
            resolve(new Response(Buffer.concat(chunks), { status, headers: resHeaders }));
          });
        },
      );

      // Honor the fetcher timeout middleware's AbortSignal.
      if (req.signal) {
        if (req.signal.aborted)
          clientReq.destroy(new Error('aborted'));
        else
          req.signal.addEventListener('abort', () => clientReq.destroy(new Error('aborted')), { once: true });
      }

      clientReq.on('error', reject);
      clientReq.end(body);
    });
  };
}

/**
 * Build a delivery client. Always wires the {@link ssrfSafeFetch} transport
 * (never a plain fetch) and a per-attempt timeout. For `inProcess` retries it
 * also configures fetcher's retry middleware — POST must be opted in
 * explicitly (fetcher does not retry POST by default), which is safe because
 * every delivery carries a stable `webhook-id` for receiver-side dedup.
 */
export function createDeliveryClient(opts: { timeoutMs?: number; retryMode: RetryMode; fetch?: FetchFn }): ReturnType<typeof createFetch> {
  return createFetch({
    baseUrl: '',
    fetch: opts.fetch ?? ssrfSafeFetch(),
    timeout: opts.timeoutMs ?? 10_000,
    ...(opts.retryMode === 'inProcess'
      ? {
          retry: {
            attempts: 5,
            methods: ['POST'],
            backoff: 5_000,
            factor: 2,
            maxBackoff: 5 * 60_000,
          },
        }
      : {}),
  });
}

/** Outcome of a single delivery attempt (or one `inProcess` retry sequence). */
export type DeliveryResult
  = | { ok: true; status: number }
    | { ok: false; kind: 'http' | 'network'; status: number | null; responseBody: string | null; message: string };

async function safeReadBody(response: Response): Promise<string | null> {
  try {
    const text = await response.text();
    return text.slice(0, 2048); // first ~2KB, for debugging
  }
  catch {
    return null;
  }
}

/**
 * Deliver `body` to `url` with `headers`. Never throws: fetcher's transport
 * resolves network/timeout failures to a `Response` with `ok === false`
 * (`status === 0`), so the result is always a classified {@link DeliveryResult}.
 */
export async function deliver(
  client: ReturnType<typeof createDeliveryClient>,
  url: string,
  body: string,
  headers: Record<string, string>,
): Promise<DeliveryResult> {
  const response = await client.post(url, {
    body,
    headers: { 'Content-Type': 'application/json', ...headers },
  });

  if (response.ok)
    return { ok: true, status: response.status };

  // status === 0 marks a transport failure (network/timeout/SSRF-rejected);
  // anything else is a real HTTP status from the receiver.
  const transport = response.status === 0;
  return {
    ok: false,
    kind: transport ? 'network' : 'http',
    status: transport ? null : response.status,
    responseBody: transport ? null : await safeReadBody(response),
    message: transport ? 'Transport error (network, timeout, or blocked target)' : `HTTP ${response.status}`,
  };
}
