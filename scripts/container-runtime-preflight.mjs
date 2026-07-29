const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 60_000;

async function connectWithTestcontainers() {
  const { getContainerRuntimeClient } = await import('testcontainers');
  return getContainerRuntimeClient();
}

/** @param {Record<string, string | undefined>} env */
export function resolveContainerRuntimeTimeout(env = process.env) {
  const configured = env.FORTRESS_CONTAINER_PROBE_TIMEOUT_MS;
  if (configured === undefined || configured === '')
    return DEFAULT_TIMEOUT_MS;
  const timeoutMs = Number(configured);
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(
      `FORTRESS_CONTAINER_PROBE_TIMEOUT_MS must be an integer between 1 and ${MAX_TIMEOUT_MS}`,
    );
  }
  return timeoutMs;
}

/**
 * Probe the same Docker-compatible runtime discovery path Testcontainers uses.
 * Testcontainers does not expose cancellation for runtime discovery; CLI callers
 * exit after a timeout so a still-pending connection cannot delay the workflow.
 * @param {{ connect?: () => Promise<unknown>, timeoutMs?: number }} options
 */
export async function probeContainerRuntime({
  connect = connectWithTestcontainers,
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
    + '  CI and release runs never skip this release-critical integration suite.';
}
