/**
 * One place that knows how to read an OpenAPI `$ref` and what a component name
 * is allowed to look like.
 *
 * Route metadata used to come only from Fortress's own well-formed endpoint
 * definitions. The CLI's `--module` flag now feeds it arbitrary application
 * JSON Schema, so ref parsing has to be exact: validation, dependency
 * ordering, and code generation must all agree on which component a given
 * `$ref` denotes, or one of them silently disagrees with the others.
 */

/** OpenAPI 3.1 §4.8.7: Components Object keys MUST match this. */
export const COMPONENT_NAME_RE = /^[\w.-]+$/;

export type ParsedRef
  /** `#/components/schemas/<name>` — the only form this codebase emits. */
  = | { kind: 'component'; name: string }
  /** Some other pointer into the current document. Legal, but not a schema. */
    | { kind: 'other-local'; pointer: string }
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
function decodeReferenceToken(token: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(token);
  }
  catch {
    return null;
  }
  return decoded.replace(/~1/g, '/').replace(/~0/g, '~');
}

/** Classify a `$ref` value. Never throws. */
export function parseSchemaRef(ref: unknown): ParsedRef {
  if (typeof ref !== 'string')
    return { kind: 'malformed', reason: `expected a string, got ${typeof ref}` };
  if (ref === '')
    return { kind: 'malformed', reason: 'empty reference' };
  if (!ref.startsWith('#'))
    return { kind: 'external' };

  const fragment = ref.slice(1);
  if (fragment === '')
    return { kind: 'other-local', pointer: '' };
  if (!fragment.startsWith('/'))
    return { kind: 'malformed', reason: `fragment must start with '/', got '${fragment}'` };

  // Split on literal '/' before decoding: a percent-encoded %2F is data, not a
  // separator, and decoding first would invent a segment boundary.
  const rawTokens = fragment.slice(1).split('/');
  const tokens: string[] = [];
  for (const rawToken of rawTokens) {
    const token = decodeReferenceToken(rawToken);
    if (token === null)
      return { kind: 'malformed', reason: `invalid percent-encoding in '${rawToken}'` };
    tokens.push(token);
  }

  if (tokens.length === 3 && tokens[0] === 'components' && tokens[1] === 'schemas' && tokens[2] !== '')
    return { kind: 'component', name: tokens[2]! };

  return { kind: 'other-local', pointer: `/${tokens.join('/')}` };
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
