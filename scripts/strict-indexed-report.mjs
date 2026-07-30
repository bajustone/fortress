/**
 * Parsing and classification for the `noUncheckedIndexedAccess` strictness
 * telemetry (issue #28). Kept separate from the runner so the counting rules
 * are unit-testable without invoking the compiler.
 */

/**
 * Suffixes that make a file part of the test population rather than shipped
 * source. Mirrors the suites vitest collects and the files npm/JSR publication
 * excludes, so a spec is never counted as production code.
 */
const TEST_FILE_PATTERN = /\.(?:test|integration-test|spec)\.ts$/;

const DIAGNOSTIC_LINE = /^(?<file>[^(]+)\((?<line>\d+),(?<column>\d+)\): error (?<code>TS\d+): /;
const GLOBAL_ERROR_LINE = /^error TS\d+: /;
const TRAILING_CARRIAGE_RETURN = /\r$/;
const INDENTED_LINE = /^\s/;

/**
 * The only files this telemetry is allowed to count. A malformed project emits
 * file-associated config diagnostics (`tsconfig.json(4,5): error TS5025: ...`)
 * that otherwise parse as ordinary production errors, which would report a
 * near-empty count and exit clean while measuring nothing.
 */
const PROJECT_SOURCE_FILE = /^src\/.+\.ts$/;
const WINDOWS_SEPARATOR = /\\/g;
const LEADING_RELATIVE_PREFIX = /^\.\//;

/** Raised for anything that means the measurement itself is untrustworthy. */
export class StrictIndexedTelemetryError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StrictIndexedTelemetryError';
  }
}

export function normalizeDiagnosticPath(file) {
  return file.replace(WINDOWS_SEPARATOR, '/').replace(LEADING_RELATIVE_PREFIX, '');
}

export function isProjectSourceFile(file) {
  return PROJECT_SOURCE_FILE.test(normalizeDiagnosticPath(file));
}

export function classifyDiagnosticFile(file) {
  return TEST_FILE_PATTERN.test(normalizeDiagnosticPath(file)) ? 'test' : 'production';
}

/**
 * Parse `tsc --pretty false` output into individual diagnostics.
 *
 * Unlike pretty mode, plain mode prints no "Found N errors" trailer, so there
 * is no self-reported total to reconcile against. Instead every non-empty line
 * must be recognised as either a diagnostic or an indented continuation; an
 * unrecognised line means the compiler's format moved and the counts can no
 * longer be trusted, so it is fatal rather than silently dropped.
 */
export function parseTypeScriptOutput(output) {
  const diagnostics = [];

  for (const rawLine of output.split('\n')) {
    const line = rawLine.replace(TRAILING_CARRIAGE_RETURN, '');
    if (line.trim() === '')
      continue;
    // Continuation lines elaborate the diagnostic above them and are indented.
    // Requiring a preceding diagnostic keeps indentation from becoming a blanket
    // escape hatch that would let unaccounted output pass as clean.
    if (INDENTED_LINE.test(line)) {
      if (diagnostics.length === 0) {
        throw new StrictIndexedTelemetryError(
          `Indented line has no diagnostic to continue, so the output could not be accounted for:\n  ${line}`,
        );
      }
      continue;
    }

    if (GLOBAL_ERROR_LINE.test(line)) {
      throw new StrictIndexedTelemetryError(
        `TypeScript reported a project-level error, so no per-file count is available:\n  ${line}`,
      );
    }

    const match = DIAGNOSTIC_LINE.exec(line);
    if (!match?.groups) {
      throw new StrictIndexedTelemetryError(
        `Unrecognised TypeScript output line — the diagnostic format may have changed:\n  ${line}`,
      );
    }

    const file = normalizeDiagnosticPath(match.groups.file);
    if (!isProjectSourceFile(file)) {
      throw new StrictIndexedTelemetryError(
        `Diagnostic outside the measured source set (expected src/**/*.ts), so the measurement is not trustworthy:\n  ${line}`,
      );
    }

    const { line: lineNumber, column, code } = match.groups;
    diagnostics.push({
      file,
      line: Number(lineNumber),
      column: Number(column),
      code,
      population: classifyDiagnosticFile(file),
    });
  }

  return diagnostics;
}

export function summarizeDiagnostics(diagnostics) {
  let production = 0;
  let test = 0;
  for (const diagnostic of diagnostics) {
    if (diagnostic.population === 'test')
      test += 1;
    else
      production += 1;
  }
  return { production, test, total: production + test };
}

const BUCKETS = ['production', 'test'];

/**
 * Parses and validates the checked-in baseline.
 *
 * Strict about shape on purpose: a typo'd or malformed key would otherwise read
 * as a missing bucket and silently disable half the ratchet.
 */
export function parseBaseline(text, source = 'baseline') {
  let parsed;
  try {
    parsed = JSON.parse(text);
  }
  catch (error) {
    throw new StrictIndexedTelemetryError(`${source} is not valid JSON: ${error.message}`);
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
    throw new StrictIndexedTelemetryError(`${source} must be a JSON object with 'production' and 'test' counts`);

  const unknown = Object.keys(parsed).filter(key => !BUCKETS.includes(key));
  if (unknown.length > 0)
    throw new StrictIndexedTelemetryError(`${source} has unrecognised key(s): ${unknown.join(', ')}`);

  for (const bucket of BUCKETS) {
    const value = parsed[bucket];
    if (!Number.isInteger(value) || value < 0)
      throw new StrictIndexedTelemetryError(`${source} key '${bucket}' must be a non-negative integer, received ${JSON.stringify(value)}`);
  }

  return { production: parsed.production, test: parsed.test };
}

/**
 * Compares each bucket independently. Buckets are never summed: a cleanup in
 * the test suite must not be able to absorb a new production diagnostic.
 */
export function compareToBaseline(summary, baseline) {
  const regressions = [];
  const reductions = [];

  for (const bucket of BUCKETS) {
    const current = summary[bucket];
    const expected = baseline[bucket];
    if (current > expected)
      regressions.push({ bucket, current, baseline: expected });
    else if (current < expected)
      reductions.push({ bucket, current, baseline: expected });
  }

  return { regressions, reductions };
}

export function formatRatchetReport(summary, baseline, comparison) {
  const lines = [
    'noUncheckedIndexedAccess ratchet (buckets are compared independently)',
    `  production  ${summary.production}  baseline ${baseline.production}`,
    `  tests       ${summary.test}  baseline ${baseline.test}`,
    `  total       ${summary.total}  informational only — never used for gating`,
  ];

  for (const { bucket, current, baseline: expected } of comparison.regressions)
    lines.push(`✖ ${bucket} diagnostics increased: expected ≤ ${expected}, actual ${current}, delta +${current - expected}`);

  for (const { bucket, current, baseline: expected } of comparison.reductions)
    lines.push(`✔ ${bucket} diagnostics decreased ${expected} → ${current} — lower it in scripts/strict-indexed-baseline.json to lock the gain in`);

  if (comparison.regressions.length === 0 && comparison.reductions.length === 0)
    lines.push('✔ both buckets match the baseline');

  return lines.join('\n');
}
