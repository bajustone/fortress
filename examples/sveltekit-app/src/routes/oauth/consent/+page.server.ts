/**
 * OAuth consent page (Pattern B).
 *
 * The browser arrives here with `?flow=<id>` after `GET /api/oauth/authorize`
 * detected an authenticated session and 302'd to the configured `consentUrl`.
 *
 * Server load fetches the flow metadata from Fortress (cookie-authed —
 * `event.fetch` automatically forwards cookies to the same origin). The
 * page then renders the client name + scopes and offers Allow / Deny.
 *
 * Both actions POST to the corresponding Fortress endpoint and `throw
 * redirect` to the URL Fortress hands back (the OAuth client's
 * `redirect_uri` with `?code=...&state=...` or `?error=access_denied&state=...`).
 *
 * For a cross-origin setup, swap `event.fetch('/api/...')` for an absolute
 * URL and either (a) move the load to a `+page.ts` (browser-side) so the
 * fetch goes out with `credentials: 'include'`, or (b) give the SvelteKit
 * server its own session and proxy.
 */

import type { Actions, RequestEvent } from '@sveltejs/kit';
import { error, redirect } from '@sveltejs/kit';

interface FlowMetadata {
  flowId: number;
  client: { clientId: string; name: string };
  redirectUri: string;
  scopes: string[];
  state: string;
}

export async function load(event: RequestEvent): Promise<{ flow: FlowMetadata }> {
  const flow = event.url.searchParams.get('flow');
  if (!flow)
    throw error(400, 'Missing flow id');

  const res = await event.fetch(`/api/oauth/flows/${encodeURIComponent(flow)}`);
  if (res.status === 401)
    throw redirect(303, `/login?flow=${encodeURIComponent(flow)}`);
  if (!res.ok)
    throw error(res.status, await res.text());

  const meta = (await res.json()) as FlowMetadata;
  return { flow: meta };
}

async function postFlowAction(
  event: RequestEvent,
  decision: 'approve' | 'deny',
): Promise<never> {
  const flow = event.url.searchParams.get('flow');
  if (!flow)
    throw error(400, 'Missing flow id');

  const res = await event.fetch(
    `/api/oauth/flows/${encodeURIComponent(flow)}/${decision}`,
    { method: 'POST' },
  );
  if (!res.ok)
    throw error(res.status, await res.text());

  const { redirectUrl } = (await res.json()) as { redirectUrl: string };
  throw redirect(303, redirectUrl);
}

export const actions: Actions = {
  approve: event => postFlowAction(event, 'approve'),
  deny: event => postFlowAction(event, 'deny'),
};
