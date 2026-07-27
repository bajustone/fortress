import { spawnSync } from 'node:child_process';
import {
  isForbiddenProjectPath,
  validatePublicationFiles,
  validateTrackedRepositoryFiles,
} from './publication-policy.mjs';

const forbiddenExamples = [
  'AUDIT-ts-ergonomics.md',
  'plan.md',
  'progress.html',
  'src/internal.test.ts',
  'examples/demo.test.ts',
  'docs/guide.spec.ts',
  'src/core/__snapshots__/contract.snap',
  'src/core/__tests__/auth.ts',
  'examples/__tests__/fixtures.ts',
  'plan-v2.md',
  'planning_notes.md',
  'Cargo.toml',
  '.cargo/config.toml',
  'rustfmt.toml',
  'clippy.toml',
  'crates/fortress/src/lib.rs',
  'docs/rust.md',
  'docs/guide/rust.md',
  'docs/port-to-rust.md',
  'docs/rust-sdk/README.md',
  'docs/fortress-rust/README.md',
  'docs/rewrite-rust-report.html',
  'docs/generated.html',
];
const allowedNearMisses = [
  'docs/plugins/audit-log.md',
  'docs/threat-model.md',
  'src/testing/index.ts',
  'src/plugins/openapi/spec-builder.ts',
  'docs/trust.md',
  'docs/rustic-design.md',
  'plans.md',
  'planet.md',
  'contextual.md',
  'progressive.md',
  'auditor.md',
  'docs/plan.md',
  'src/core/tests/helper.ts',
];
for (const path of forbiddenExamples) {
  if (!isForbiddenProjectPath(path))
    throw new Error(`Publication policy failed to reject fixture: ${path}`);
}
for (const path of allowedNearMisses) {
  if (isForbiddenProjectPath(path))
    throw new Error(`Publication policy rejected valid fixture: ${path}`);
}

// .gitignore must stay a subset of the policy. An ignore broader than the
// policy is silent: `git add .` skips the file and reports nothing, so a
// permitted document would simply never be committed.
const ignoreProbe = spawnSync('git', ['check-ignore', '--', ...allowedNearMisses], {
  encoding: 'utf8',
});
if (ignoreProbe.status !== 0 && ignoreProbe.status !== 1)
  throw new Error(`git check-ignore failed: ${String(ignoreProbe.stderr)}`);
const overBroadIgnores = String(ignoreProbe.stdout).split('\n').filter(Boolean);
if (overBroadIgnores.length > 0) {
  throw new Error(
    `.gitignore is broader than the publication policy and would silently drop permitted files:\n${
      overBroadIgnores.map(path => `  - ${path}`).join('\n')}`,
  );
}

const syntheticErrors = validatePublicationFiles({
  registry: 'jsr',
  files: new Set(['jsr.json', 'package.json', 'README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'bin/fortress.ts']),
  requiredTargets: new Set(),
  expectedMigrations: new Set(),
});
if (!syntheticErrors.some(error => error.includes('npm-only CLI')))
  throw new Error('Publication policy failed to reject the CLI from a synthetic JSR manifest');

// Both registries would otherwise ship a conventional __tests__ layout, which
// no test-filename or snapshot rule catches.
const syntheticTestDirectoryErrors = validatePublicationFiles({
  registry: 'npm',
  files: new Set(['package.json', 'README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'bin/fortress.ts', 'src/core/__tests__/auth.ts']),
  requiredTargets: new Set(),
  expectedMigrations: new Set(),
});
if (!syntheticTestDirectoryErrors.some(error => error.includes('forbidden npm file: src/core/__tests__/auth.ts')))
  throw new Error('Publication policy failed to reject a __tests__ directory from a synthetic npm manifest');

// Tests belong in the repository; only Rust, generated HTML, and root planning
// material are out of scope for the TypeScript branch.
const syntheticTracked = validateTrackedRepositoryFiles([
  'plan-v2.md',
  'docs/plan.md',
  'src/core/__tests__/auth.ts',
]);
if (syntheticTracked.length !== 1 || !syntheticTracked[0].includes('plan-v2.md')) {
  throw new Error(
    `Repository scope policy misclassified synthetic tracked files: ${JSON.stringify(syntheticTracked)}`,
  );
}

const tracked = spawnSync('git', ['ls-files', '-z'], { encoding: 'buffer' });
if (tracked.status !== 0)
  throw new Error(`git ls-files failed: ${String(tracked.stderr)}`);
const trackedFiles = tracked.stdout
  .toString('utf8')
  .split('\0')
  .filter(Boolean);
const repositoryErrors = validateTrackedRepositoryFiles(trackedFiles);
if (repositoryErrors.length > 0)
  throw new Error(repositoryErrors.join('\n'));

console.log(`✔ publication policy fixtures and TypeScript-branch scope passed (${trackedFiles.length} tracked files)`);
