import { describe, expect, it } from 'vitest';
import { parseSchemaRef } from './openapi-ref';

describe('parseSchemaRef', () => {
  it('decodes valid percent and JSON Pointer escapes without changing token boundaries', () => {
    expect(parseSchemaRef('#/components/schemas/Foo%2DBar')).toEqual({
      kind: 'component',
      name: 'Foo-Bar',
    });
    expect(parseSchemaRef('#/components/schemas/Thing/properties/a~1b/~0tail')).toEqual({
      kind: 'other-local',
      tokens: ['components', 'schemas', 'Thing', 'properties', 'a/b', '~tail'],
    });
  });

  it.each([
    ['#/components/schemas/Thing/properties/a~2b', 'invalid JSON Pointer escape'],
    ['#/components/schemas/Thing/properties/trailing~', 'invalid JSON Pointer escape'],
    ['#/components/schemas/Thing/properties/%7E2', 'invalid JSON Pointer escape'],
    ['#/components/schemas/Thing/properties/bad%2', 'invalid percent-encoding'],
  ])('rejects malformed local pointer %s', (ref, reason) => {
    expect(parseSchemaRef(ref)).toEqual(expect.objectContaining({ kind: 'malformed' }));
    expect(parseSchemaRef(ref)).toEqual(expect.objectContaining({ reason: expect.stringContaining(reason) }));
  });

  it.each([
    ['other schema.json#/Thing', 'characters not permitted'],
    ['other.json%2', 'invalid percent-encoding'],
    ['https://example.test/a#one#two', 'more than one \'#\''],
    ['http://[broken]/path', 'malformed IP-literal'],
    ['http://example.test:not-a-port/path', 'non-numeric URI port'],
    ['relative/[bracket]', 'outside a URI authority'],
  ])('rejects malformed external URI-reference %s', (ref, reason) => {
    expect(parseSchemaRef(ref)).toEqual(expect.objectContaining({
      kind: 'malformed',
      reason: expect.stringContaining(reason),
    }));
  });

  it.each([
    'other.json#/components/schemas/Thing',
    '../schemas/common.json',
    'https://example.test/schemas.json#/Thing',
    'https://[2001:db8::1]:443/schemas.json',
    '//example.test/schemas.json',
    'urn:example:fortress',
  ])('accepts valid external URI-reference %s', (ref) => {
    expect(parseSchemaRef(ref)).toEqual({ kind: 'external' });
  });
});
