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
];
for (const path of forbiddenExamples) {
  if (!isForbiddenProjectPath(path))
    throw new Error(`Publication policy failed to reject fixture: ${path}`);
}
for (const path of allowedNearMisses) {
  if (isForbiddenProjectPath(path))
    throw new Error(`Publication policy rejected valid fixture: ${path}`);
}

const syntheticErrors = validatePublicationFiles({
  registry: 'jsr',
  files: new Set(['jsr.json', 'package.json', 'README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'bin/fortress.ts']),
  requiredTargets: new Set(),
  expectedMigrations: new Set(),
});
if (!syntheticErrors.some(error => error.includes('npm-only CLI')))
  throw new Error('Publication policy failed to reject the CLI from a synthetic JSR manifest');

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
