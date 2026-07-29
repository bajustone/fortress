import { pathToFileURL } from 'node:url';
import { getContainerRuntimeClient } from 'testcontainers';

const DEFAULT_TIMEOUT_MS = 5_000;

/** Probe the same Docker-compatible runtime discovery path Testcontainers uses. */
export async function probeContainerRuntime({
  connect = getContainerRuntimeClient,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  let timeout;
  try {
    await Promise.race([
      connect(),
      new Promise((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error(`container runtime probe timed out after ${timeoutMs}ms`)),
          timeoutMs,
        );
      }),
    ]);
  }
  finally {
    if (timeout !== undefined)
      clearTimeout(timeout);
  }
}

export function formatContainerRuntimeError(error) {
  const reason = error instanceof Error ? error.message : String(error);
  return `✖ PostgreSQL integration tests require an accessible Docker-compatible container runtime.\n`
    + `  Testcontainers could not connect: ${reason}\n`
    + '  Start Docker Desktop, Colima, Podman, or another supported runtime, then verify\n'
    + '  its Docker-compatible socket (and DOCKER_HOST, when used) is accessible.\n'
    + '  The strict `bun run test:integration` command does not skip this release-critical suite.';
}

const isEntrypoint = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  try {
    await probeContainerRuntime();
    console.log('✔ Docker-compatible container runtime is available to Testcontainers');
  }
  catch (error) {
    console.error(formatContainerRuntimeError(error));
    process.exit(1);
  }
}
