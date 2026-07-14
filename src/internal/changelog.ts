const CHANGELOG_HEADER = '# Changelog';
const UNRELEASED_HEADING = '## [Unreleased]';
const SECTION_HEADING = /^### /;

function parseGeneratedSections(value: string): Array<{ heading: string; body: string[] }> {
  const lines = value.trim().split('\n');
  const sections: Array<{ heading: string; body: string[] }> = [];
  for (const line of lines) {
    if (SECTION_HEADING.test(line))
      sections.push({ heading: line, body: [] });
    else if (sections.length > 0 && line.length > 0)
      sections.at(-1)!.body.push(line);
  }
  return sections;
}

/** Promote the first, top-level Unreleased section without detaching its notes. */
export function promoteUnreleased(
  changelog: string,
  version: string,
  date: string,
  generatedSection = '',
): string {
  const lines = changelog.split('\n');
  if (lines[0] !== CHANGELOG_HEADER)
    throw new Error('CHANGELOG.md must start with # Changelog');

  const releaseStart = lines.findIndex((line, index) => index > 0 && line.startsWith('## '));
  if (releaseStart < 0 || lines[releaseStart] !== UNRELEASED_HEADING)
    throw new Error('CHANGELOG.md must have [Unreleased] as its first release section');

  lines[releaseStart] = `## [${version}] - ${date}`;
  let releaseEnd = lines.findIndex((line, index) => index > releaseStart && line.startsWith('## '));
  if (releaseEnd < 0)
    releaseEnd = lines.length;

  for (const generated of parseGeneratedSections(generatedSection)) {
    const existingHeading = lines.findIndex(
      (line, index) => index > releaseStart && index < releaseEnd && line === generated.heading,
    );
    if (existingHeading >= 0) {
      let insertion = lines.findIndex(
        (line, index) => index > existingHeading && index < releaseEnd && SECTION_HEADING.test(line),
      );
      if (insertion < 0)
        insertion = releaseEnd;
      lines.splice(insertion, 0, ...generated.body, '');
      releaseEnd += generated.body.length + 1;
    }
    else {
      lines.splice(releaseStart + 1, 0, '', generated.heading, ...generated.body);
      releaseEnd += generated.body.length + 2;
    }
  }
  return lines.join('\n');
}
