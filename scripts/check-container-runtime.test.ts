import { describe, expect, it, vi } from 'vitest';
import { formatContainerRuntimeError, probeContainerRuntime } from './check-container-runtime.mjs';

describe('container runtime preflight', () => {
  it('accepts the runtime discovery path used by Testcontainers', async () => {
    const connect = vi.fn().mockResolvedValue({ runtime: 'available' });

    await expect(probeContainerRuntime({ connect, timeoutMs: 50 })).resolves.toBeUndefined();
    expect(connect).toHaveBeenCalledOnce();
  });

  it('surfaces an unavailable runtime immediately', async () => {
    const connect = vi.fn().mockRejectedValue(new Error('daemon unavailable'));

    await expect(
      probeContainerRuntime({ connect, timeoutMs: 50 }),
    ).rejects.toThrow('daemon unavailable');
  });

  it('times out without waiting for the integration hook limit', async () => {
    const connect = vi.fn(() => new Promise(() => {}));

    await expect(
      probeContainerRuntime({ connect, timeoutMs: 5 }),
    ).rejects.toThrow('container runtime probe timed out after 5ms');
  });

  it('formats an actionable strict-workflow error', () => {
    const output = formatContainerRuntimeError(new Error('daemon unavailable'));

    expect(output).toContain('Docker-compatible container runtime');
    expect(output).toContain('Docker Desktop, Colima, Podman');
    expect(output).toContain('DOCKER_HOST');
    expect(output).toContain('does not skip this release-critical suite');
  });
});
