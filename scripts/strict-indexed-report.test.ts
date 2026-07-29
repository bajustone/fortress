import { describe, expect, it } from 'vitest';
import {
  classifyDiagnosticFile,
  formatSummary,
  isProjectSourceFile,
  normalizeDiagnosticPath,
  parseTypeScriptOutput,
  StrictIndexedTelemetryError,
  summarizeDiagnostics,
} from './strict-indexed-report.mjs';

describe('strict-indexed diagnostic classification', () => {
  it('counts shipped source as production', () => {
    expect(classifyDiagnosticFile('src/drizzle/adapter.ts')).toBe('production');
    expect(classifyDiagnosticFile('src/core/migrations/migrations.ts')).toBe('production');
  });

  it('counts every collected suite suffix as tests', () => {
    expect(classifyDiagnosticFile('src/plugins/webhook/webhook.test.ts')).toBe('test');
    expect(classifyDiagnosticFile('src/drizzle/pg/pg.integration-test.ts')).toBe('test');
    // vitest collects src/**/*.spec.ts and publication excludes it, so a spec
    // must never land in the production population.
    expect(classifyDiagnosticFile('src/example.spec.ts')).toBe('test');
  });

  it('does not mistake a production file merely containing "test" for a suite', () => {
    expect(classifyDiagnosticFile('src/testing/checks.ts')).toBe('production');
    expect(classifyDiagnosticFile('src/core/latest.ts')).toBe('production');
    expect(classifyDiagnosticFile('src/spec.ts')).toBe('production');
  });
});

describe('strict-indexed output parsing', () => {
  it('parses diagnostics and ignores indented elaboration lines', () => {
    const output = [
      'src/sveltekit/handle.ts(357,21): error TS2345: Argument of type \'string | undefined\' is not assignable.',
      '  Type \'undefined\' is not assignable to type \'string\'.',
      'src/testing/adapter-conformance.test.ts(278,14): error TS2532: Object is possibly \'undefined\'.',
      '',
    ].join('\n');

    const diagnostics = parseTypeScriptOutput(output);

    expect(diagnostics).toHaveLength(2);
    expect(diagnostics[0]).toMatchObject({
      file: 'src/sveltekit/handle.ts',
      line: 357,
      column: 21,
      code: 'TS2345',
      population: 'production',
    });
    expect(diagnostics[1]).toMatchObject({ code: 'TS2532', population: 'test' });
  });

  it('treats a project-level error as a failed measurement', () => {
    expect(() => parseTypeScriptOutput('error TS5058: The specified path does not exist: \'nope.json\'.'))
      .toThrow(StrictIndexedTelemetryError);
  });

  it('refuses to silently drop output it does not recognise', () => {
    expect(() => parseTypeScriptOutput('Found 396 errors in 71 files.'))
      .toThrow(/Unrecognised TypeScript output line/);
  });

  it('rejects an indented line that continues nothing', () => {
    expect(() => parseTypeScriptOutput('  arbitrary garbage'))
      .toThrow(/no diagnostic to continue/);
    expect(() => parseTypeScriptOutput('  arbitrary garbage'))
      .toThrow(StrictIndexedTelemetryError);
  });

  it('allows several continuations under one diagnostic', () => {
    const output = [
      'src/core/fortress.ts(10,3): error TS2532: Object is possibly \'undefined\'.',
      '  Type \'undefined\' is not assignable to type \'string\'.',
      '    The nested elaboration is also indented.',
      'src/core/fortress.ts(20,3): error TS18048: Value is possibly \'undefined\'.',
    ].join('\n');

    expect(parseTypeScriptOutput(output)).toHaveLength(2);
  });

  it('accepts genuinely clean output', () => {
    expect(parseTypeScriptOutput('')).toEqual([]);
  });
});

describe('strict-indexed source-set enforcement', () => {
  it('rejects a config-file diagnostic rather than counting it as production', () => {
    // A typo'd compiler option exits 2 with a file-associated diagnostic, which
    // would otherwise parse as one ordinary production error and report clean.
    for (const line of [
      'scripts/tsconfig.strict-indexed.json(4,5): error TS5023: Unknown compiler option \'nope\'.',
      'scripts/tsconfig.strict-indexed.json(4,5): error TS5025: Unknown compiler option \'nope\'. Did you mean \'x\'?',
    ]) {
      expect(() => parseTypeScriptOutput(line)).toThrow(StrictIndexedTelemetryError);
      expect(() => parseTypeScriptOutput(line)).toThrow(/outside the measured source set/);
    }
  });

  it('rejects diagnostics from files outside the measured project', () => {
    expect(() => parseTypeScriptOutput('scripts/check-strict-indexed.mjs(1,1): error TS2532: Object is possibly \'undefined\'.'))
      .toThrow(/outside the measured source set/);
    expect(() => parseTypeScriptOutput('examples/hono-app/index.ts(1,1): error TS2532: Object is possibly \'undefined\'.'))
      .toThrow(/outside the measured source set/);
  });

  it('recognises project sources regardless of path spelling', () => {
    expect(isProjectSourceFile('src/core/fortress.ts')).toBe(true);
    expect(isProjectSourceFile('./src/core/fortress.ts')).toBe(true);
    expect(isProjectSourceFile('src\\core\\fortress.ts')).toBe(true);
    expect(isProjectSourceFile('scripts/tsconfig.strict-indexed.json')).toBe(false);
    expect(isProjectSourceFile('src/core/fortress.js')).toBe(false);
    expect(isProjectSourceFile('sources/core/fortress.ts')).toBe(false);
  });

  it('normalises separators and relative prefixes before classifying', () => {
    expect(normalizeDiagnosticPath('./src/a.ts')).toBe('src/a.ts');
    expect(normalizeDiagnosticPath('src\\plugins\\x.test.ts')).toBe('src/plugins/x.test.ts');
    expect(classifyDiagnosticFile('./src/plugins/x.test.ts')).toBe('test');
  });
});

describe('strict-indexed summary', () => {
  it('totals each population separately', () => {
    const summary = summarizeDiagnostics([
      { population: 'production' },
      { population: 'production' },
      { population: 'test' },
    ]);

    expect(summary).toEqual({ production: 2, test: 1, total: 3 });
  });

  it('reports the two populations as distinct lines', () => {
    expect(formatSummary({ production: 109, test: 287, total: 396 })).toContain('production  109');
    expect(formatSummary({ production: 109, test: 287, total: 396 })).toContain('tests       287');
  });
});
