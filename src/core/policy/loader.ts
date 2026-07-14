/**
 * Load a {@link PolicyDocument} from disk with optional env-specific
 * override. Node filesystem/path modules are imported only when these
 * file-oriented helpers run, keeping the package root import runtime-neutral.
 *
 * @module
 */

import type { PolicyDocument } from './types';
import { Errors } from '../errors';

export interface LoadPolicyOptions {
  /** Override the default `fortress.policy.json` path. */
  filePath?: string;
  /** Pick an env-specific file (`fortress.policy.<env>.json`). Defaults to `process.env.FORTRESS_ENV`. */
  env?: string;
  /** Working directory when resolving the default file paths. Defaults to `process.cwd()`. */
  cwd?: string;
}

/** Default base file name. */
export const DEFAULT_POLICY_FILE = 'fortress.policy.json';

async function exists(filePath: string): Promise<boolean> {
  const { access } = await import('node:fs/promises');
  try {
    await access(filePath);
    return true;
  }
  catch (err) {
    if ((err as { code?: string }).code === 'ENOENT')
      return false;
    throw err;
  }
}

/** Return the resolved policy-file path for an environment, or `null` if no file exists. */
export async function resolvePolicyPath(options: LoadPolicyOptions = {}): Promise<string | null> {
  if (options.filePath)
    return await exists(options.filePath) ? options.filePath : null;

  const { join } = await import('node:path');
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env.FORTRESS_ENV;
  if (env) {
    const envPath = join(cwd, `fortress.policy.${env}.json`);
    if (await exists(envPath))
      return envPath;
  }
  const basePath = join(cwd, DEFAULT_POLICY_FILE);
  return await exists(basePath) ? basePath : null;
}

/** Load and parse a policy document. Throws when the file is missing or unparseable. */
export async function loadPolicy(options: LoadPolicyOptions = {}): Promise<{ policy: PolicyDocument; filePath: string }> {
  const filePath = await resolvePolicyPath(options);
  if (!filePath)
    throw Errors.notFound(`No policy file found (looked for fortress.policy.<env>.json then fortress.policy.json)`);
  try {
    const { readFile } = await import('node:fs/promises');
    const text = await readFile(filePath, 'utf-8');
    const parsed = JSON.parse(text) as PolicyDocument;
    return { policy: parsed, filePath };
  }
  catch (err) {
    if (err instanceof SyntaxError)
      throw Errors.badRequest(`Failed to parse policy file ${filePath}: ${err.message}`);
    throw err;
  }
}
