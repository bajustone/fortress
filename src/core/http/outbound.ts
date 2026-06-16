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
import { createFetch } from '@bajustone/fetcher';

/** Default outbound timeout (ms). Applied to every call unless overridden per-call. */
export const OUTBOUND_TIMEOUT_MS = 10_000;

/** Shared fetcher client for fortress's outbound HTTP. */
export const outboundClient = createFetch({ baseUrl: '', timeout: OUTBOUND_TIMEOUT_MS });
