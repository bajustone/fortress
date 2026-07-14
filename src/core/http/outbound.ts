/**
 * Shared client for fortress's *outbound* HTTP — OAuth token exchange, OIDC
 * discovery, provider userinfo, GitHub profile, and the HIBP breach check.
 *
 * Built on `@bajustone/fetcher` so every outbound call gets:
 *   - a **timeout** (native `fetch` has none, so a hung upstream would block a
 *     login/registration indefinitely);
 *   - the **never-throws** contract — transport failures (network/timeout)
 *     resolve to a `Response` with `ok === false` rather than rejecting, so
 *     call sites branch on `.ok`/`.result()` instead of try/catch;
 *   - optional **schema-validated parsing** via a per-call `responseSchema`.
 *
 * Always invoked with absolute URLs, so `baseUrl` is unused (an absolute path
 * overrides it in fetcher).
 */
import type { Middleware } from '@bajustone/fetcher';
import { createFetch } from '@bajustone/fetcher';

/** Default outbound timeout (ms), covering headers and full body consumption. */
export const OUTBOUND_TIMEOUT_MS = 10_000;

function requestWithSignal(request: Request, signal: AbortSignal): Request {
  return new Request(request, request.body
    ? { signal, body: request.body, duplex: 'half' } as RequestInit
    : { signal });
}

/**
 * Keep the deadline alive until the response body is consumed. A fetch-only
 * timeout stops at response headers, allowing a peer to dribble the body
 * forever after returning an immediate 200 response.
 */
function fullExchangeTimeout(ms: number): Middleware {
  return async (request, next) => {
    const controller = new AbortController();
    const userSignal = request.signal;
    const abortFromUser = (): void => controller.abort(userSignal.reason);
    if (userSignal.aborted)
      abortFromUser();
    else
      userSignal.addEventListener('abort', abortFromUser, { once: true });

    const timer = setTimeout(() => {
      controller.abort(new DOMException(`Request timed out after ${ms}ms`, 'TimeoutError'));
    }, ms);
    let cleaned = false;
    const cleanup = (): void => {
      if (cleaned)
        return;
      cleaned = true;
      clearTimeout(timer);
      userSignal.removeEventListener('abort', abortFromUser);
    };

    try {
      const response = await next(requestWithSignal(request, controller.signal));
      if (!response.body) {
        cleanup();
        return response;
      }

      const reader = response.body.getReader();
      const body = new ReadableStream<Uint8Array>({
        async pull(streamController) {
          try {
            const chunk = await reader.read();
            if (chunk.done) {
              cleanup();
              streamController.close();
            }
            else {
              streamController.enqueue(chunk.value);
            }
          }
          catch (error) {
            cleanup();
            streamController.error(error);
          }
        },
        async cancel(reason) {
          cleanup();
          await reader.cancel(reason);
        },
      });

      return new Response(body, {
        headers: response.headers,
        status: response.status,
        statusText: response.statusText,
      });
    }
    catch (error) {
      cleanup();
      throw error;
    }
  };
}

/** Create an outbound client whose deadline covers headers and response body. */
export function createOutboundClient(timeoutMs: number = OUTBOUND_TIMEOUT_MS): ReturnType<typeof createFetch> {
  return createFetch({ baseUrl: '', middleware: [fullExchangeTimeout(timeoutMs)] });
}

/** Shared fetcher client for Fortress outbound HTTP. */
export const outboundClient = createOutboundClient();
