import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import {
  compareToBaseline,
  formatRatchetReport,
  parseBaseline,
  parseTypeScriptOutput,
  StrictIndexedTelemetryError,
  summarizeDiagnostics,
} from './strict-indexed-report.mjs';

const CONFIG = 'scripts/tsconfig.strict-indexed.json';
const BASELINE = 'scripts/strict-indexed-baseline.json';
// tsc exits 0 with a clean program and 2 once it has reported diagnostics.
// Every other code (1 for a bad/missing project, 3 for config resolution)
// means we never got a usable measurement.
const TSC_CLEAN = 0;
const TSC_REPORTED_DIAGNOSTICS = 2;

const root = fileURLToPath(new URL('..', import.meta.url));

function measure() {
  const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');
  const result = spawnSync(process.execPath, [tsc, '-p', CONFIG, '--pretty', 'false'], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });

  if (result.error)
    throw new StrictIndexedTelemetryError(`Could not run tsc: ${result.error.message}`);
  if (result.signal)
    throw new StrictIndexedTelemetryError(`tsc was terminated by signal ${result.signal}`);
  if (result.status !== TSC_CLEAN && result.status !== TSC_REPORTED_DIAGNOSTICS) {
    throw new StrictIndexedTelemetryError(
      `tsc exited with ${result.status}, which means it did not complete a check:\n${`${result.stdout}${result.stderr}`.trim()}`,
    );
  }

  const diagnostics = parseTypeScriptOutput(`${result.stdout}\n${result.stderr}`);

  // Guards against a silently empty parse: the exit code and the parsed count
  // have to agree on whether anything was reported.
  const expectsDiagnostics = result.status === TSC_REPORTED_DIAGNOSTICS;
  if (expectsDiagnostics && diagnostics.length === 0)
    throw new StrictIndexedTelemetryError('tsc reported diagnostics but none could be parsed from its output');
  if (!expectsDiagnostics && diagnostics.length > 0)
    throw new StrictIndexedTelemetryError('tsc exited clean but diagnostics were parsed from its output');

  return summarizeDiagnostics(diagnostics);
}

function readBaseline() {
  let text;
  try {
    text = readFileSync(new URL(`../${BASELINE}`, import.meta.url), 'utf-8');
  }
  catch (error) {
    throw new StrictIndexedTelemetryError(`Could not read ${BASELINE}: ${error.message}`);
  }
  return parseBaseline(text, BASELINE);
}

try {
  const summary = measure();
  const baseline = readBaseline();
  const comparison = compareToBaseline(summary, baseline);
  console.log(formatRatchetReport(summary, baseline, comparison));

  // Only an increase fails. Matching or beating the baseline passes, so a batch
  // that removes diagnostics is never blocked on updating the file first. A
  // broken measurement, config, or baseline still exits non-zero via the catch.
  process.exit(comparison.regressions.length > 0 ? 1 : 0);
}
catch (error) {
  console.error(error instanceof StrictIndexedTelemetryError ? error.message : error);
  process.exit(1);
}
