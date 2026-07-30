/**
 * SSRF protection for webhook delivery.
 *
 * Webhook URLs are consumer-supplied, so delivery is a live SSRF surface
 * (cloud metadata endpoints, internal services). This module resolves the
 * target host, refuses private/loopback/link-local/CGNAT addresses (IPv4,
 * IPv6, `::ffff:`-mapped, and `64:ff9b::/96` NAT64 forms), and returns the *resolved IP* so the
 * caller can pin the connection to it — closing the DNS-rebinding window
 * between validation and connect.
 *
 * Originally extracted from `index.ts`; the delivery transport (`delivery.ts`)
 * pins {@link SafeWebhookTarget.address} via a custom
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

type Ipv4Octets = [number, number, number, number];
type Ipv6Groups = [number, number, number, number, number, number, number, number];
const DECIMAL_OCTET = /^\d+$/;
const HEX_GROUP = /^[\da-f]{1,4}$/i;

/** Parse one decimal IPv4 octet without accepting Number's permissive syntax. */
function parseIpv4Octet(value: string): number | null {
  if (!DECIMAL_OCTET.test(value))
    return null;
  const octet = Number(value);
  return Number.isInteger(octet) && octet >= 0 && octet <= 255 ? octet : null;
}

/** Parse one complete IPv6 group; partial parseInt results are never valid IP input. */
function parseIpv6Group(value: string): number | null {
  if (!HEX_GROUP.test(value))
    return null;
  return Number.parseInt(value, 16);
}

function parseIpv4(address: string): Ipv4Octets | null {
  const parts = address.split('.');
  if (parts.length !== 4)
    return null;
  const [first, second, third, fourth] = parts;
  // The length check establishes these values exist; retain that proof so a
  // malformed address cannot acquire a permissive default octet.
  if (first === undefined || second === undefined || third === undefined || fourth === undefined)
    return null;
  const a = parseIpv4Octet(first);
  const b = parseIpv4Octet(second);
  const c = parseIpv4Octet(third);
  const d = parseIpv4Octet(fourth);
  if (a === null || b === null || c === null || d === null)
    return null;
  return [a, b, c, d];
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
  const [highWord, lowWord] = words;
  if (highWord === undefined || lowWord === undefined)
    return null;
  const hi = parseIpv6Group(highWord);
  const lo = parseIpv6Group(lowWord);
  if (hi === null || lo === null)
    return null;
  return `${hi >> 8}.${hi & 0xFF}.${lo >> 8}.${lo & 0xFF}`;
}

function isPrivateIpv4(address: string): boolean {
  const octets = parseIpv4(address);
  // A DNS result or literal that does not parse as an IPv4 address is never a
  // public destination. The outer resolver rejects it rather than guessing.
  if (octets === null)
    return true;
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

/**
 * Expand an IPv6 literal to its 8 16-bit groups, handling `::` compression and
 * a trailing embedded dotted-quad. Returns null for anything not well-formed.
 */
function ipv6Groups(address: string): Ipv6Groups | null {
  let host = stripIpv6Brackets(address).toLowerCase();
  const zone = host.indexOf('%');
  if (zone !== -1)
    host = host.slice(0, zone);
  if (!host.includes(':'))
    return null;

  // Fold a trailing dotted-quad (e.g. `64:ff9b::1.2.3.4`) into two hex groups.
  if (host.includes('.')) {
    const lastColon = host.lastIndexOf(':');
    const v4 = parseIpv4(host.slice(lastColon + 1));
    if (v4 === null)
      return null;
    const [a, b, c, d] = v4;
    const hi = ((a << 8) | b).toString(16);
    const lo = ((c << 8) | d).toString(16);
    host = `${host.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = host.split('::');
  if (halves.length > 2)
    return null;
  const [firstHalf, secondHalf] = halves;
  if (firstHalf === undefined)
    return null;
  const head = firstHalf === '' ? [] : firstHalf.split(':');
  const tail = secondHalf === undefined ? null : (secondHalf === '' ? [] : secondHalf.split(':'));

  let parts: string[];
  if (tail === null) {
    parts = head; // no `::` — must already be 8 groups
  }
  else {
    const missing = 8 - head.length - tail.length;
    if (missing < 1)
      return null;
    parts = [...head, ...Array.from<string>({ length: missing }).fill('0'), ...tail];
  }
  if (parts.length !== 8)
    return null;

  const groups: number[] = [];
  for (const part of parts) {
    const group = parseIpv6Group(part);
    if (group === null)
      return null;
    groups.push(group);
  }
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
  if (g0 === undefined || g1 === undefined || g2 === undefined || g3 === undefined
    || g4 === undefined || g5 === undefined || g6 === undefined || g7 === undefined) {
    return null;
  }
  return [g0, g1, g2, g3, g4, g5, g6, g7];
}

/**
 * Decode the IPv4 embedded in an RFC 6052 NAT64 well-known-prefix (`64:ff9b::/96`)
 * address, or null if `address` isn't in that prefix. On a NAT64/DNS64 network
 * the gateway connects to this translated IPv4, so it must face the same
 * private-range checks — `64:ff9b::a9fe:a9fe` is the cloud metadata IP.
 */
function extractNat64Ipv4(groups: Ipv6Groups): string | null {
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
  if (g0 === 0x0064 && g1 === 0xFF9B
    && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return `${(g6 >> 8) & 0xFF}.${g6 & 0xFF}.${(g7 >> 8) & 0xFF}.${g7 & 0xFF}`;
  }
  return null;
}

/** `true` if `address` is a loopback/private/link-local/CGNAT/multicast IP (v4, v6, `::ffff:` mapped, or `64:ff9b::/96` NAT64). */
export function isPrivateIp(address: string): boolean {
  const host = stripIpv6Brackets(address).toLowerCase();
  const family = isIP(host);
  // `isPrivateIp` only receives literal addresses from DNS/literal resolution.
  // If it cannot prove this is one, treat the target as unsafe rather than
  // allowing a parser disagreement to become a public destination.
  if (family === 0)
    return true;
  if (family === 4)
    return isPrivateIpv4(host);

  const mapped = extractMappedIpv4(host);
  if (mapped)
    return isPrivateIpv4(mapped);
  const groups = ipv6Groups(host);
  if (groups === null)
    return true;
  const nat64 = extractNat64Ipv4(groups);
  if (nat64)
    return isPrivateIpv4(nat64);
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
  if (selected === undefined)
    throw new Error('Webhook URL host did not resolve');
  if (selected.family !== 4 && selected.family !== 6)
    throw new Error('Webhook URL resolved to an unsupported address family');
  return { url: parsed, address: selected.address, family: selected.family };
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
