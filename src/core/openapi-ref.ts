/**
 * One place that knows how to read an OpenAPI `$ref` and what a component name
 * is allowed to look like.
 *
 * Route metadata used to come only from Fortress's own well-formed endpoint
 * definitions. The CLI's `--module` flag now feeds it arbitrary application
 * JSON Schema, so ref parsing has to be exact: validation, dependency
 * ordering, and code generation must all agree on which component a given
 * `$ref` denotes, or one of them silently disagrees with the others.
 *
 * Scope: local refs are supported as JSON Pointer fragments (RFC 6901);
 * external refs are checked for URI-reference syntax (RFC 3986). A plain-name
 * `$anchor` fragment (`#thing`) is valid JSON Schema but outside the supported
 * subset — it is rejected explicitly rather than guessed at, which is a
 * support boundary, not an RFC violation.
 */

/** OpenAPI 3.1 §4.8.7: Components Object keys MUST match this. */
export const COMPONENT_NAME_RE = /^[\w.-]+$/;

export type ParsedRef
  /** `#/components/schemas/<name>` — the only form this codebase emits. */
  = | { kind: 'component'; name: string }
  /** Some other pointer into the current document. Legal, but not a schema. */
    | { kind: 'other-local'; tokens: string[] }
  /** Anything not rooted at `#`. Legal OpenAPI; resolved by the consumer. */
    | { kind: 'external' }
    | { kind: 'malformed'; reason: string };

/**
 * Decode one JSON Pointer reference token.
 *
 * Two layers of escaping stack here, and the order matters. The fragment is
 * URI-encoded, so percent-escapes come off first (RFC 3986). Then JSON Pointer
 * escapes (RFC 6901 §4): `~1` before `~0`, because doing it the other way
 * turns the literal `~01` into `/` instead of `~1`.
 *
 * In practice this is unreachable for conformant component names — the
 * OpenAPI grammar above allows neither `~` nor `/` — but decoding correctly
 * costs nothing and turns a confusing "undefined component" into an accurate
 * error.
 */
const INVALID_JSON_POINTER_ESCAPE_RE = /~(?:[^01]|$)/;
const URI_SCHEME_RE = /^[a-z][a-z\d+.-]*$/i;
const URI_SCHEME_PREFIX_RE = /^[a-z][a-z\d+.-]*:/i;
const INVALID_PERCENT_ESCAPE_RE = /%(?![\da-f]{2})/i;
const URI_PORT_SUFFIX_RE = /^:\d*$/;
const URI_PORT_RE = /^\d*$/;
// RFC 3986 IPvFuture: "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" ).
// `unreserved` includes '~', so it must be permitted here.
const URI_IP_FUTURE_RE = /^v[\da-f]+\.[\w.!$&'()*+,;=:~-]+$/i;
const URI_SPECIAL_CHARACTERS = new Set(`-._~:/?#[]@!$&'()*+,;=%`);

function decodeReferenceToken(token: string): { value: string } | { reason: string } {
  let decoded: string;
  try {
    decoded = decodeURIComponent(token);
  }
  catch {
    return { reason: `invalid percent-encoding in '${token}'` };
  }
  if (INVALID_JSON_POINTER_ESCAPE_RE.test(decoded))
    return { reason: `invalid JSON Pointer escape in '${token}'` };
  return { value: decoded.replace(/~1/g, '/').replace(/~0/g, '~') };
}

function isUriReferenceCharacter(character: string): boolean {
  const code = character.charCodeAt(0);
  const isDigit = code >= 48 && code <= 57;
  const isUppercase = code >= 65 && code <= 90;
  const isLowercase = code >= 97 && code <= 122;
  return isDigit || isUppercase || isLowercase || URI_SPECIAL_CHARACTERS.has(character);
}

function isValidIpLiteral(value: string): boolean {
  if (URI_IP_FUTURE_RE.test(value))
    return true;
  // WHATWG and RFC 3986 use the same bracketed IPv6 syntax. The fixed
  // scheme/authority wrapper makes URL useful here without its otherwise
  // lenient path and percent-encoding normalization.
  return URL.canParse(`http://[${value}]/`);
}

/** Return why a string is not an RFC 3986 URI-reference, if anything. */
function invalidUriReference(ref: string): string | undefined {
  if (INVALID_PERCENT_ESCAPE_RE.test(ref))
    return 'invalid percent-encoding';
  if (![...ref].every(isUriReferenceCharacter))
    return 'contains characters not permitted in a URI-reference';
  if (ref.indexOf('#') !== ref.lastIndexOf('#'))
    return 'contains more than one \'#\' fragment delimiter';

  const beforeFragment = ref.split('#', 1)[0]!;
  const beforeQuery = beforeFragment.split('?', 1)[0]!;
  if (!beforeQuery.startsWith('//')) {
    const firstSegment = beforeQuery.split('/', 1)[0]!;
    const colon = firstSegment.indexOf(':');
    if (colon >= 0 && !URI_SCHEME_RE.test(firstSegment.slice(0, colon)))
      return `has an invalid URI scheme '${firstSegment.slice(0, colon)}'`;
  }

  // '[' and ']' are only legal around an IP-literal in an authority host.
  const schemeEnd = beforeQuery.match(URI_SCHEME_PREFIX_RE)?.[0].length ?? 0;
  const hierarchy = beforeQuery.slice(schemeEnd);
  const authority = hierarchy.startsWith('//') ? hierarchy.slice(2).split('/', 1)[0]! : undefined;
  if (authority === undefined) {
    if (ref.includes('[') || ref.includes(']'))
      return 'contains an IP-literal bracket outside a URI authority';
  }
  else {
    const lastAt = authority.lastIndexOf('@');
    const userInfo = lastAt >= 0 ? authority.slice(0, lastAt) : '';
    const hostAndPort = authority.slice(lastAt + 1);
    const pathAfterAuthority = hierarchy.slice(2 + authority.length);
    const queryOrFragment = ref.slice(beforeQuery.length);
    if (userInfo.includes('@') || userInfo.includes('[') || userInfo.includes(']')
      || pathAfterAuthority.includes('[') || pathAfterAuthority.includes(']')
      || queryOrFragment.includes('[') || queryOrFragment.includes(']')) {
      return 'contains an IP-literal bracket outside an authority host';
    }
    if (hostAndPort.includes('[') || hostAndPort.includes(']')) {
      const closing = hostAndPort.indexOf(']');
      if (!hostAndPort.startsWith('[') || closing <= 1 || hostAndPort.slice(1).includes('[')
        || hostAndPort.slice(closing + 1).includes(']')
        || !isValidIpLiteral(hostAndPort.slice(1, closing))
        || (hostAndPort.slice(closing + 1) !== '' && !URI_PORT_SUFFIX_RE.test(hostAndPort.slice(closing + 1)))) {
        return 'contains malformed IP-literal brackets';
      }
    }
    else {
      const portSeparator = hostAndPort.lastIndexOf(':');
      if (portSeparator >= 0 && !URI_PORT_RE.test(hostAndPort.slice(portSeparator + 1)))
        return 'contains a non-numeric URI port';
      if (portSeparator >= 0 && hostAndPort.slice(0, portSeparator).includes(':'))
        return 'contains an unbracketed IP-literal';
    }
  }
  return undefined;
}

/** Classify a `$ref` value. Never throws. */
export function parseSchemaRef(ref: unknown): ParsedRef {
  if (typeof ref !== 'string')
    return { kind: 'malformed', reason: `expected a string, got ${typeof ref}` };
  if (ref === '')
    return { kind: 'malformed', reason: 'empty reference' };

  const uriError = invalidUriReference(ref);
  if (uriError)
    return { kind: 'malformed', reason: uriError };
  if (!ref.startsWith('#'))
    return { kind: 'external' };

  const fragment = ref.slice(1);
  if (fragment === '')
    return { kind: 'other-local', tokens: [] };
  // A plain-name fragment is a legal JSON Schema `$anchor`, but `$anchor` is
  // not part of the supported subset and nothing here can resolve it. Reject
  // it as unsupported rather than silently treating it as a pointer.
  if (!fragment.startsWith('/')) {
    return {
      kind: 'malformed',
      reason: `fragment '#${fragment}' is not a JSON Pointer; $anchor references are not supported`,
    };
  }

  // Split on literal '/' before decoding: a percent-encoded %2F is data, not a
  // separator, and decoding first would invent a segment boundary.
  const rawTokens = fragment.slice(1).split('/');
  const tokens: string[] = [];
  for (const rawToken of rawTokens) {
    const decoded = decodeReferenceToken(rawToken);
    if ('reason' in decoded)
      return { kind: 'malformed', reason: decoded.reason };
    tokens.push(decoded.value);
  }

  if (tokens.length === 3 && tokens[0] === 'components' && tokens[1] === 'schemas' && tokens[2] !== '')
    return { kind: 'component', name: tokens[2]! };

  // Keep decoded tokens rather than joining them back into a pointer string.
  // A token may itself contain '/' (encoded as ~1 or %2F); re-splitting a
  // reconstructed string would invent a segment boundary that was never in
  // the reference.
  return { kind: 'other-local', tokens };
}

/** Throw unless `name` is a legal OpenAPI Components key. */
export function assertComponentName(name: string, where?: string): void {
  if (COMPONENT_NAME_RE.test(name))
    return;
  throw new Error(
    `Invalid OpenAPI component name '${name}'${where ? ` in ${where}` : ''}. `
    + `OpenAPI component keys must match ^[a-zA-Z0-9._-]+$ (e.g. User, User_1, user-name, my.org.User).`,
  );
}
