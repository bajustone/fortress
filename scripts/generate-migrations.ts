import { fileURLToPath } from 'node:url';
import {
  checkMigrationArtifacts,
  generateMigrationArtifacts,
  hasMigrationArtifactDrift,
} from '../src/core/migrations/artifact-files';
import { getExpectedMigrationArtifacts } from '../src/core/migrations/artifacts';

function printDrift(drift: Awaited<ReturnType<typeof checkMigrationArtifacts>>): void {
  for (const category of ['missing', 'mismatched', 'extra'] as const) {
    for (const path of drift[category])
      console.error(`${category}: ${path}`);
  }
}

async function main(): Promise<void> {
  const root = fileURLToPath(new URL('..', import.meta.url));
  if (process.argv.includes('--list')) {
    // Machine-readable catalog for the publication checks, which run under Node
    // and cannot import this TypeScript module directly. Keep stdout pure JSON.
    console.log(JSON.stringify([...getExpectedMigrationArtifacts().keys()].sort()));
    return;
  }
  if (process.argv.includes('--check')) {
    const drift = await checkMigrationArtifacts(root);
    if (hasMigrationArtifactDrift(drift)) {
      console.error('Migration artifacts are out of date. Run `bun run generate:migrations`.');
      printDrift(drift);
      process.exitCode = 1;
      return;
    }
    console.log(`Migration artifacts are current (${getExpectedMigrationArtifacts().size} files).`);
    return;
  }
  await generateMigrationArtifacts(root);
  console.log(`Generated ${getExpectedMigrationArtifacts().size} migration artifacts.`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
