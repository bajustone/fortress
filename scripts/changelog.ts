import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf-8'));
const version = pkg.version;

// Find the previous tag
const tags = execSync('git tag --sort=-v:refname', { encoding: 'utf-8' })
  .trim()
  .split('\n')
  .filter(Boolean);

const prevTag = tags.find(t => t !== `v${version}`) ?? tags[0];

if (!prevTag) {
  console.log('No previous tag found, skipping changelog generation');
  process.exit(0);
}

// Get commits since previous tag
const log = execSync(
  `git log ${prevTag}..HEAD --pretty=format:"%s" --no-merges`,
  { encoding: 'utf-8' },
)
  .trim()
  .split('\n')
  .filter(Boolean);

if (log.length === 0) {
  console.log('No new commits since last tag, skipping changelog generation');
  process.exit(0);
}

// Categorize commits
const added: string[] = [];
const changed: string[] = [];
const fixed: string[] = [];

for (const msg of log) {
  const lower = msg.toLowerCase();
  if (lower.startsWith('fix')) {
    fixed.push(msg);
  }
  else if (
    lower.startsWith('update')
    || lower.startsWith('refactor')
    || lower.startsWith('improve')
    || lower.startsWith('change')
  ) {
    changed.push(msg);
  }
  else {
    added.push(msg);
  }
}

// Build section
const today = new Date().toISOString().split('T')[0];
let section = `\n## [${version}] - ${today}\n`;

if (added.length > 0) {
  section += `\n### Added\n${added.map(m => `- ${m}`).join('\n')}\n`;
}
if (changed.length > 0) {
  section += `\n### Changed\n${changed.map(m => `- ${m}`).join('\n')}\n`;
}
if (fixed.length > 0) {
  section += `\n### Fixed\n${fixed.map(m => `- ${m}`).join('\n')}\n`;
}

// Insert after "# Changelog" header
const changelogPath = join(root, 'CHANGELOG.md');
const existing = readFileSync(changelogPath, 'utf-8');

const headerEnd = existing.indexOf('\n');
const updated
  = existing.slice(0, headerEnd + 1) + section + existing.slice(headerEnd + 1);

writeFileSync(changelogPath, updated);

// Stage the file so it's included in the version commit
execSync('git add CHANGELOG.md', { cwd: root });

console.log(`Updated CHANGELOG.md for v${version}`);
