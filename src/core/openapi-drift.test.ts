/**
 * CI gate over fortress's emitted OpenAPI spec, using `@bajustone/fetcher`'s
 * `lintSpec`. It surfaces keyword usages the runtime validator does not enforce
 * (type-vs-runtime divergence).
 *
 * Two keywords are intentionally allowed: `format` (always annotation-only in
 * JSON Schema — fortress pairs it with an enforcing `pattern` via `email()` /
 * `uuid()` / … and keeps it for OpenAPI docs) and `additionalProperties`
 * (records, and response-only schemas that are never request-validated). Any
 * OTHER keyword fetcher's runtime can't enforce (`multipleOf`,
 * `exclusiveMinimum`, `minItems`, `uniqueItems`, …) is a real gap — adding one
 * to a fortress schema fails this gate so it's caught before it ships.
 */
import { lintSpec } from '@bajustone/fetcher/spec-tools';
import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../testing';
import { createFortress } from './fortress';
import { toOpenAPI } from './openapi';

interface SpecDriftIssue { pointer: string; keyword: string; severity: string; message: string }

const KNOWN_UNENFORCED = new Set(['format', 'additionalProperties']);

function coreSpec(): unknown {
  const fortress = createFortress({ jwt: { key: 'x'.repeat(32) }, database: createTestAdapter() });
  return toOpenAPI([...fortress.endpoints], { title: 'Fortress', version: '0.0.0' });
}

describe('openAPI spec drift (lintSpec gate)', () => {
  it('emits no error-severity drift', () => {
    const issues = lintSpec(coreSpec()) as SpecDriftIssue[];
    expect(issues.filter(i => i.severity === 'error')).toEqual([]);
  });

  it('emits no unexpected unenforced keywords', () => {
    const issues = lintSpec(coreSpec()) as SpecDriftIssue[];
    const unexpected = issues.filter(i => !KNOWN_UNENFORCED.has(i.keyword));
    // Rendered as readable strings so a failure points straight at the offending schema.
    expect(unexpected.map(i => `${i.keyword} @ ${i.pointer}`)).toEqual([]);
  });
});
