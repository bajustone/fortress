/**
 * Standard Webhooks signing — HMAC-SHA256 over `{id}.{timestamp}.{body}`.
 *
 * @see https://www.standardwebhooks.com
 * @module
 */

/**
 * Sign a webhook payload per the Standard Webhooks spec: HMAC-SHA256 over
 * `{webhookId}.{timestamp}.{body}`, base64-encoded. Uses Web Crypto so it runs
 * on every fortress runtime.
 */
export async function signPayload(secret: string, webhookId: string, timestamp: number, body: string): Promise<string> {
  const content = `${webhookId}.${timestamp}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(content));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

/**
 * Build the Standard Webhooks delivery headers for one attempt.
 *
 * `webhookId` must be **stable across retries of the same delivery** (receivers
 * use it as their idempotency key); only `timestamp` changes per attempt. The
 * caller is responsible for passing a stable id (e.g. `msg_<deliveryId>`).
 */
export async function signatureHeaders(
  secret: string,
  webhookId: string,
  timestamp: number,
  body: string,
): Promise<Record<string, string>> {
  const signature = await signPayload(secret, webhookId, timestamp, body);
  return {
    'webhook-id': webhookId,
    'webhook-timestamp': String(timestamp),
    'webhook-signature': `v1,${signature}`,
  };
}
