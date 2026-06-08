/**
 * Load a {@link PolicyDocument} from disk with optional env-specific
 * override.
 *
 * Default file: `fortress.policy.json` in the working directory.
 * Env override: `fortress.policy.<env>.json` (e.g. `fortress.policy.production.json`).
 *
 * The env-specific file fully **replaces** the base document; merge is not
 * attempted because policy is small and ambiguous merges produce worse
 * surprises than explicit duplication.
 *
 * @module
 */

import type { PolicyDocument } from './types';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
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

/** Return the resolved policy-file path for an environment, or `null` if no file exists. */
export function resolvePolicyPath(options: LoadPolicyOptions = {}): string | null {
  if (options.filePath) {
    return existsSync(options.filePath) ? options.filePath : null;
  }
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env.FORTRESS_ENV;
  if (env) {
    const envPath = join(cwd, `fortress.policy.${env}.json`);
    if (existsSync(envPath))
      return envPath;
  }
  const basePath = join(cwd, DEFAULT_POLICY_FILE);
  return existsSync(basePath) ? basePath : null;
}

/** Load and parse a policy document. Throws when the file is missing or unparseable. */
export function loadPolicy(options: LoadPolicyOptions = {}): { policy: PolicyDocument; filePath: string } {
  const filePath = resolvePolicyPath(options);
  if (!filePath)
    throw Errors.notFound(`No policy file found (looked for fortress.policy.<env>.json then fortress.policy.json)`);
  try {
    const text = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(text) as PolicyDocument;
    return { policy: parsed, filePath };
  }
  catch (err) {
    if (err instanceof SyntaxError)
      throw Errors.badRequest(`Failed to parse policy file ${filePath}: ${err.message}`);
    throw err;
  }
}
