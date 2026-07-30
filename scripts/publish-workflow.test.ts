import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

// actionlint remains authoritative for workflow validity. These assertions
// protect the release-safety properties it cannot know about: which events may
// publish, that recovery publishes an immutable tag under the npm CLI the tag
// was validated against, and that it never bypasses the tag's own gates.
const workflow = readFileSync(
  resolve(import.meta.dirname, '../.github/workflows/publish.yml'),
  'utf8',
);

const lines = workflow.split('\n');

function jobBlock(name: string): string {
  const start = lines.indexOf(`  ${name}:`);
  expect(start, `job ${name} is missing`).toBeGreaterThan(-1);
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    if (line.startsWith('  ') && !line.startsWith('   ') && line.trimEnd().endsWith(':')) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

const tagJobs = ['verify-version', 'quality', 'publish-jsr', 'publish-npm'];
const recovery = jobBlock('recover-npm');

describe('publish workflow', () => {
  it('runs the tagged release path only for pushed tags', () => {
    expect(workflow).toContain('tags: [\'v*\']');
    for (const job of tagJobs)
      expect(jobBlock(job), job).toContain('if: github.event_name == \'push\'');
  });

  it('runs recovery only for an explicitly confirmed manual dispatch', () => {
    expect(recovery).toContain('if: github.event_name == \'workflow_dispatch\'');
    expect(workflow).toContain('workflow_dispatch:');
    expect(workflow).toContain('Type recover-npm-publication to confirm');
    expect(recovery).toContain('test "$CONFIRM" = \'recover-npm-publication\'');
    expect(workflow).toContain('concurrency:');
  });

  it('serializes every publication of this package, not merely one version', () => {
    const group = lines.find(line => line.trimStart().startsWith('group: publish-')) ?? '';
    // A constant group is the requirement. Any expression here would key on
    // the event or the version, letting two different versions publish
    // concurrently, where whichever finished last would decide `latest`.
    expect(group.trim()).toBe('group: publish-bajustone-fortress');
    expect(workflow).toContain('cancel-in-progress: false');

    // Negative control for the keys this replaced: both are version-specific,
    // so a 2.0.0 recovery and a 2.0.1 tag run would not exclude each other.
    const versionKeyed = (version: string): string => `publish-v${version}`;
    expect(versionKeyed('2.0.0')).not.toBe(versionKeyed('2.0.1'));
  });

  it('validates the requested version before it is resolved into a ref', () => {
    expect(recovery.indexOf('Validate recovery request'))
      .toBeLessThan(recovery.indexOf('actions/checkout'));
    expect(recovery).toContain('grep -Eq');
    const checkoutRef = recovery.split('\n').find(line => line.includes('ref: refs/tags/v'));
    expect(checkoutRef).toContain('github.event.inputs.version');
    expect(recovery).toContain('fetch-depth: 0');
  });

  it('publishes only an immutable tag commit contained in main', () => {
    expect(recovery).toContain('git ls-remote origin');
    expect(recovery).toContain('git merge-base --is-ancestor');
    expect(recovery).toContain('refs/remotes/origin/main');
    expect(recovery).toContain('require("./package.json").version');
    expect(recovery).toContain('require("./jsr.json").version');
  });

  it('requires the JSR half to exist and the npm half to be genuinely absent', () => {
    expect(recovery).toContain('_meta.json');
    expect(recovery).toContain('test "$JSR_STATUS" = \'200\'');
  });

  it('derives npm state from one successful response, never from a failed lookup', () => {
    expect(recovery).toContain('npm view @bajustone/fortress --json');
    expect(recovery).toContain('versions.includes(target)');
    expect(recovery).toContain('npm did not return package metadata');
    expect(recovery).toContain('npm did not return a version list');
    expect(recovery).toContain('npm returned an unusable version list');
    expect(recovery).toContain('npm did not return dist-tags');
    expect(recovery).toContain('npm did not return a latest dist-tag');
    // A discarded lookup failure is exactly how an outage becomes "absent".
    expect(recovery).not.toContain('2>&1');
  });

  it('refuses a recovery that would not move the latest dist-tag forward', () => {
    expect(recovery).toContain('is not a served version');
    expect(recovery).toContain('is not a stable release');
    expect(recovery).toContain('is not older than');
    expect(recovery).toContain('newer stable versions');
    expect(recovery).toContain('BigInt');

    // Why the comparison must be numeric: lexically, 10.0.0 sorts below 2.0.0,
    // so a lexical guard would happily downgrade latest from 10.0.0 to 2.0.0.
    const compare = (left: string, right: string): number => {
      const a = left.split('.').map(part => BigInt(part));
      const b = right.split('.').map(part => BigInt(part));
      for (let index = 0; index < 3; index += 1) {
        if ((a[index] ?? 0n) < (b[index] ?? 0n))
          return -1;
        if ((a[index] ?? 0n) > (b[index] ?? 0n))
          return 1;
      }
      return 0;
    };
    expect(compare('10.0.0', '2.0.0')).toBe(1);
    expect(compare('1.0.2', '2.0.0')).toBe(-1);
    expect(['10.0.0', '2.0.0'].sort()).toEqual(['10.0.0', '2.0.0']);
  });

  it('runs the tagged release gates and never bypasses the publish lifecycle', () => {
    expect(recovery).toContain('bun run check:release');
    expect(recovery).toContain('bun run check:npm-publication');
    expect(recovery).toContain('npm install --global npm@11.9.0');
    expect(recovery).toContain('test "$(npm --version)" = \'11.9.0\'');
    expect(recovery).toContain('npm publish --access public');
    expect(recovery).not.toContain('--ignore-scripts');
    expect(recovery).toContain('id-token: write');
  });

  it('asserts the published artifact came from the tagged commit', () => {
    expect(recovery).toContain('dist-tags.latest');
    expect(recovery).toContain('gitHead');
    expect(recovery).toContain('"$RELEASE_SHA"');
  });

  it('leaves JSR publication to the tagged release path only', () => {
    expect(recovery).not.toContain('deno publish');
    expect(jobBlock('publish-jsr')).toContain('deno publish --allow-dirty');
  });
});
