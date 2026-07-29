import { describe, expect, it } from 'vitest';
import { assertNoRuntimeImport, findModuleImports, stripLeadingComments } from './scan-module-imports.mjs';

describe('runtime import detection', () => {
  it('flags every import form', () => {
    for (const source of [
      `import { it } from 'vitest';`,
      `import {it} from "vitest";`,
      `import 'vitest';`,
      `const m = await import('vitest');`,
      `const m = require('vitest');`,
      `export { x } from 'vitest';`,
    ]) {
      expect(findModuleImports(source, 'vitest'), source).toHaveLength(1);
    }
  });

  it('flags subpath imports', () => {
    expect(findModuleImports(`import { defineConfig } from 'vitest/config';`, 'vitest')).toHaveLength(1);
  });

  it('ignores an import shown inside a JSDoc example', () => {
    const source = [
      '/**',
      ' * @example',
      ' * ```ts',
      ` * import { beforeEach, describe, it } from 'vitest';`,
      ' * ```',
      ' */',
      `export function runAdapterTests() {}`,
    ].join('\n');

    expect(findModuleImports(source, 'vitest')).toEqual([]);
  });

  it('ignores line comments', () => {
    expect(findModuleImports(`// import { it } from 'vitest';`, 'vitest')).toEqual([]);
  });

  it('still flags a real import that follows a comment block mentioning the module', () => {
    const source = [
      '/* historically this imported vitest:',
      ` * import { it } from 'vitest';`,
      ' */',
      `import { it } from 'vitest';`,
    ].join('\n');

    expect(findModuleImports(source, 'vitest')).toHaveLength(1);
  });

  it('does not flag unrelated identifiers or bare strings', () => {
    expect(findModuleImports(`const vitestLike = 'vitest';`, 'vitest')).toEqual([]);
    expect(findModuleImports(`import { x } from 'not-vitest';`, 'vitest')).toEqual([]);
  });

  it('keeps code that trails a closing block comment', () => {
    expect(stripLeadingComments(`/* note */ import { it } from 'vitest';`)).toContain('vitest');
  });
});

describe('assertNoRuntimeImport', () => {
  it('passes for a bundle with no runtime import', () => {
    expect(() => assertNoRuntimeImport(`export function a() {}`, 'vitest', 'dist/testing.js')).not.toThrow();
  });

  it('names the artifact and the offending line', () => {
    expect(() => assertNoRuntimeImport(`import { it } from 'vitest';`, 'vitest', 'dist/testing.js'))
      .toThrow(/dist\/testing\.js imports 'vitest' at runtime/);
  });
});
