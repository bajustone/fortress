import { describe, expect, it } from 'vitest';
import { promoteUnreleased } from './internal/changelog';

describe('promoteUnreleased', () => {
  it('promotes the top section in place and retains curated notes', () => {
    const input = '# Changelog\n\n## [Unreleased]\n\n### Fixed\n- curated fix\n\n### Changed\n- migration instructions\n\n## [0.2.8] - 2026-06-10\n';
    const output = promoteUnreleased(input, '1.0.0-rc.2', '2026-07-15', '\n### Fixed\n- generated fix\n');

    expect(output).toContain('## [1.0.0-rc.2] - 2026-07-15');
    expect(output).toContain('### Fixed\n- curated fix\n\n- generated fix');
    expect(output.match(/### Fixed/g)).toHaveLength(1);
    expect(output).toContain('### Changed\n- migration instructions');
    expect(output.indexOf('[1.0.0-rc.2]')).toBeLessThan(output.indexOf('[0.2.8]'));
    expect(output).not.toContain('[Unreleased]');
  });

  it('refuses to promote a historical or missing Unreleased section', () => {
    const malformed = '# Changelog\n\n## [0.2.8] - 2026-06-10\n\n## [Unreleased]\n';
    expect(() => promoteUnreleased(malformed, '1.0.0', '2026-07-15')).toThrow('first release section');
  });
});
