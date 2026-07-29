import {
  formatContainerRuntimeError,
  probeContainerRuntime,
  resolveContainerRuntimeTimeout,
} from './container-runtime-preflight.mjs';

try {
  const timeoutMs = resolveContainerRuntimeTimeout();
  await probeContainerRuntime({ timeoutMs });
  console.log('✔ Docker-compatible container runtime is available to Testcontainers');
  process.exit(0);
}
catch (error) {
  console.error(formatContainerRuntimeError(error));
  process.exit(1);
}
