/**
 * SSRF protection for webhook delivery.
 *
 * Webhook URLs are consumer-supplied, so delivery is a live SSRF surface
 * (cloud metadata endpoints, internal services). This module resolves the
 * target host, refuses private/loopback/link-local/CGNAT addresses (IPv4,
 * IPv6, and `::ffff:`-mapped forms), and returns the *resolved IP* so the
 * caller can pin the connection to it — closing the DNS-rebinding window
 * between validation and connect.
 *
 * Lifted verbatim from the original `index.ts` (logic unchanged); the delivery
 * transport (`delivery.ts`) pins {@link SafeWebhookTarget.address} via a custom
 * `lookup`, and {@link assertSafeWebhookUrl} is exported for custom transports.
 *
 * @module
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/** A validated webhook target plus the exact resolved IP to pin the connection to. */
export interface SafeWebhookTarget {
  url: URL;
  address: string;
  family: 4 | 6;
}

function stripIpv6Brackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function parseIpv4(address: string): number[] | null {
  const parts = address.split('.');
  if (parts.length !== 4)
    return null;
  const octets = parts.map(part => Number(part));
  if (octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255))
    return null;
  return octets;
}

function extractMappedIpv4(address: string): string | null {
  const lower = stripIpv6Brackets(address).toLowerCase();
  if (!lower.startsWith('::ffff:'))
    return null;
  const tail = lower.slice('::ffff:'.length);
  if (parseIpv4(tail))
    return tail;
  const words = tail.split(':');
  if (words.length !== 2)
    return null;
  const hi = Number.parseInt(words[0], 16);
  const lo = Number.parseInt(words[1], 16);
  if (!Number.isInteger(hi) || !Number.isInteger(lo) || hi < 0 || hi > 0xFFFF || lo < 0 || lo > 0xFFFF)
    return null;
  return `${hi >> 8}.${hi & 0xFF}.${lo >> 8}.${lo & 0xFF}`;
}

function isPrivateIpv4(address: string): boolean {
  const octets = parseIpv4(address);
  if (!octets)
    return false;
  const [a, b] = octets;
  return a === 0
    || a === 10
    || a === 127
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19))
    || a >= 224;
}

/** `true` if `address` is a loopback/private/link-local/CGNAT/multicast IP (v4, v6, or `::ffff:` mapped). */
export function isPrivateIp(address: string): boolean {
  const host = stripIpv6Brackets(address).toLowerCase();
  const mapped = extractMappedIpv4(host);
  if (mapped)
    return isPrivateIpv4(mapped);
  if (isPrivateIpv4(host))
    return true;
  if (host === '::' || host === '::1')
    return true;
  return host.startsWith('fc')
    || host.startsWith('fd')
    || host.startsWith('fe80:')
    || host.startsWith('ff');
}

/**
 * Resolve `url` to a {@link SafeWebhookTarget}, throwing when it is not https
 * or resolves to a loopback/private/link-local/CGNAT address (including
 * IPv4-mapped IPv6 forms like `::ffff:169.254.169.254`) or a `localhost`/
 * `.local`/`.localhost` host. The returned `address`/`family` is the exact IP
 * the caller must pin the connection to.
 */
export async function resolveSafeWebhookTarget(url: string): Promise<SafeWebhookTarget> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:')
    throw new Error('Webhook URL must use https');
  const host = stripIpv6Brackets(parsed.hostname.toLowerCase());
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local'))
    throw new Error('Webhook URL host is not allowed');

  const literalFamily = isIP(host);
  const records = literalFamily === 0
    ? await lookup(host, { all: true, verbatim: true })
    : [{ address: host, family: literalFamily }];
  if (records.length === 0)
    throw new Error('Webhook URL host did not resolve');
  if (records.some(record => isPrivateIp(record.address)))
    throw new Error('Webhook URL resolves to a private address');

  const selected = records[0];
  return { url: parsed, address: selected.address, family: selected.family as 4 | 6 };
}

/**
 * Resolve `url` and throw when it points at a loopback, link-local, RFC1918,
 * or otherwise non-public address. Exported for tests and for custom delivery
 * transports that want to reuse fortress's SSRF guard. The built-in transport
 * (`delivery.ts`) already calls {@link resolveSafeWebhookTarget} and pins the
 * resolved IP, so callers using it do not need to invoke this themselves.
 */
export async function assertSafeWebhookUrl(url: string): Promise<void> {
  await resolveSafeWebhookTarget(url);
}
