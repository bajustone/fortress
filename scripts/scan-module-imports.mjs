/**
 * Detects whether a built bundle actually imports a module at runtime.
 *
 * Loading a bundle proves nothing about its dependencies when the module is
 * installed anyway — every CI job here runs `bun install` with devDependencies,
 * so `vitest` resolves from `node_modules` regardless. The only durable check is
 * to look for the import in the emitted artifact.
 */

/**
 * Strips comment-only lines and block comments that open a line, so a JSDoc
 * `@example` showing an import is not mistaken for a real one.
 *
 * Deliberately conservative: a trailing comment on a code line is left in
 * place. Erring toward a false positive is safe here, whereas dropping too much
 * could hide a genuine import.
 */
export function stripLeadingComments(source) {
  const kept = [];
  let inBlockComment = false;

  for (const line of source.split('\n')) {
    const trimmed = line.trim();

    if (inBlockComment) {
      const end = trimmed.indexOf('*/');
      if (end === -1)
        continue;
      inBlockComment = false;
      kept.push(trimmed.slice(end + 2));
      continue;
    }

    if (trimmed.startsWith('//'))
      continue;

    if (trimmed.startsWith('/*')) {
      const end = trimmed.indexOf('*/');
      if (end === -1) {
        inBlockComment = true;
        continue;
      }
      kept.push(trimmed.slice(end + 2));
      continue;
    }

    kept.push(line);
  }

  return kept.join('\n');
}

function patternsFor(moduleName) {
  const specifier = `${moduleName}(?:/[^'"\`]*)?`;
  const quoted = `['"\`]${specifier}['"\`]`;
  return [
    new RegExp(`\\bfrom\\s*${quoted}`),
    new RegExp(`\\bimport\\s*\\(\\s*${quoted}\\s*\\)`),
    new RegExp(`\\brequire\\s*\\(\\s*${quoted}\\s*\\)`),
    new RegExp(`\\bimport\\s+${quoted}`),
  ];
}

/** Returns the code lines that import `moduleName`, ignoring comment-only lines. */
export function findModuleImports(source, moduleName) {
  const patterns = patternsFor(moduleName);
  return stripLeadingComments(source)
    .split('\n')
    .filter(line => patterns.some(pattern => pattern.test(line)))
    .map(line => line.trim());
}

/** Throws when `source` imports `moduleName` at runtime. */
export function assertNoRuntimeImport(source, moduleName, artifact) {
  const found = findModuleImports(source, moduleName);
  if (found.length > 0) {
    throw new Error(
      `${artifact} imports '${moduleName}' at runtime, which must stay out of the shipped bundle:\n  ${found.join('\n  ')}`,
    );
  }
}
