import { Buffer } from 'node:buffer';

const JWT_SECRET_LITERAL_RE = /jwt:\s*\{[\s\S]{0,120}?\bkey\s*:\s*(['"`])([^'"`]+)\1(?!\s*\.repeat)/g;
const ENCRYPTION_SECRET_LITERAL_RE = /\b(?:secretEncryptionKey|tokenEncryptionKey)\s*:\s*(['"`])([^'"`]+)\1/g;
const VERSION_PIN_RE = /@bajustone\/fortress@~(\d+)(?:\.\d+)?/g;
const PRE_STABLE_RE = /Pre-(\d+)\.0/gi;
const SVELTE_DEMO_CREDENTIAL_RE = /email:\s*'alice@example\.com'[\s\S]*?password:\s*'([^']+)'/;
const INSECURE_COOKIE_CONFIG_RE = /cookies:\s*\{\s*secure:\s*false\s*\}/;
const JSDOC_RE = /\/\*\*[\s\S]*?\*\//g;
const PROPERTY_AFTER_JSDOC_RE = /^\s*(?:readonly\s+)?([A-Za-z_$][\w$]*)\??\s*:/;

function lineNumber(content, index) {
  return content.slice(0, index).split('\n').length;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function deprecatedOptionNames(files) {
  const names = new Set();
  for (const [path, content] of Object.entries(files)) {
    if (!path.startsWith('src/') || !path.endsWith('.ts'))
      continue;
    for (const comment of content.matchAll(JSDOC_RE)) {
      if (!comment[0].includes('@deprecated'))
        continue;
      const following = content.slice((comment.index ?? 0) + comment[0].length);
      const property = following.match(PROPERTY_AFTER_JSDOC_RE)?.[1];
      if (property)
        names.add(property);
    }
  }
  return [...names].sort();
}

function isDocumentationPath(path) {
  return path === 'README.md'
    || path.startsWith('docs/')
    || path.startsWith('examples/')
    || path === 'scripts/fixtures/readme-hono-adapter-declaration.ts';
}

export function findDocumentationDrift(files, packageVersion = '1.0.0') {
  const errors = [];
  const packageMajor = Number.parseInt(packageVersion.split('.')[0] ?? '0', 10);
  const deprecatedNames = deprecatedOptionNames(files);

  for (const [path, content] of Object.entries(files)) {
    if (!isDocumentationPath(path) && path !== 'src/testing/index.ts')
      continue;

    if (isDocumentationPath(path)) {
      for (const name of deprecatedNames) {
        const usage = new RegExp(`\\b${escapeRegExp(name)}\\s*:`, 'g');
        for (const match of content.matchAll(usage)) {
          errors.push(`${path}:${lineNumber(content, match.index)} uses deprecated option ${name}`);
        }
      }
    }

    for (const pattern of [JWT_SECRET_LITERAL_RE, ENCRYPTION_SECRET_LITERAL_RE]) {
      for (const match of content.matchAll(pattern)) {
        if (Buffer.byteLength(match[2], 'utf8') < 32) {
          errors.push(
            `${path}:${lineNumber(content, match.index)} uses a test/example secret shorter than 32 bytes`,
          );
        }
      }
    }

    for (const match of content.matchAll(VERSION_PIN_RE)) {
      if (Number.parseInt(match[1], 10) < packageMajor)
        errors.push(`${path}:${lineNumber(content, match.index)} pins an obsolete pre-${packageMajor}.0 release line`);
    }
    for (const match of content.matchAll(PRE_STABLE_RE)) {
      if (Number.parseInt(match[1], 10) <= packageMajor)
        errors.push(`${path}:${lineNumber(content, match.index)} contains obsolete pre-stable guidance`);
    }
  }

  const svelteSource = files['examples/sveltekit-app/src/lib/server/fortress.ts'];
  if (svelteSource !== undefined) {
    const password = svelteSource.match(SVELTE_DEMO_CREDENTIAL_RE)?.[1];
    const svelteReadme = files['examples/sveltekit-app/README.md'] ?? '';
    if (!password || password.length < 15)
      errors.push('SvelteKit demo source must seed a password of at least 15 characters');
    else if (!svelteReadme.includes(`alice@example.com\` / \`${password}`))
      errors.push('SvelteKit README credentials do not match the seeded demo user');
    if (!INSECURE_COOKIE_CONFIG_RE.test(svelteSource))
      errors.push('SvelteKit plain-HTTP demo must explicitly disable secure cookies');
  }

  return errors;
}
