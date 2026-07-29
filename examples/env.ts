type ExampleEnvironment = Readonly<Record<string, string | undefined>>;

const ENV_SETUP_HINT = 'Copy .env.example to .env before running an example.';

/** Read a required environment variable with an actionable example setup error. */
export function requireExampleEnv(
  name: string,
  env: ExampleEnvironment = process.env,
): string {
  const value = env[name]?.trim();
  if (!value)
    throw new Error(`[fortress example] Missing ${name}. ${ENV_SETUP_HINT}`);
  return value;
}
