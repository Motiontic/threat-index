import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const load = vi.fn();
vi.mock('@modelcontextprotocol/server/ext/skills', () => ({
  memorySkillFiles: (f: unknown) => f,
  SkillsExtension: { load: (...a: unknown[]) => load(...a) },
}));

import { FAILURE_TTL_MS, register, resetSkillCatalog, skillCatalog } from './skills';

class SecretBoom extends Error {}

let errors: string[];
beforeEach(() => {
  resetSkillCatalog();
  load.mockReset();
  errors = [];
  vi.spyOn(console, 'error').mockImplementation((l: string) => {
    errors.push(l);
  });
});
afterEach(() => vi.restoreAllMocks());

describe('skillCatalog', () => {
  it('caches a failed load for 60 seconds, logs the class name only, then retries', async () => {
    load.mockRejectedValue(new SecretBoom('token abc123'));
    expect(await skillCatalog(1000)).toBeNull();
    expect(await skillCatalog(1000 + FAILURE_TTL_MS - 1)).toBeNull();
    expect(load).toHaveBeenCalledTimes(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('mcp_skills_unavailable');
    expect(errors[0]).toContain('SecretBoom');
    expect(errors[0]).not.toContain('abc123');
    const cat = { attach: vi.fn() };
    load.mockResolvedValue(cat);
    expect(await skillCatalog(1000 + FAILURE_TTL_MS)).toBe(cat);
    expect(await skillCatalog(1)).toBe(cat);
    expect(load).toHaveBeenCalledTimes(2);
  });
});

describe('register', () => {
  it('serves the tools without skills when attach throws', () => {
    const server = { server: { registerCapabilities: vi.fn() } };
    const catalog = {
      attach: () => {
        throw new SecretBoom('private detail');
      },
    };
    expect(() => register(server as never, catalog as never)).not.toThrow();
    expect(errors[0]).toContain('mcp_skills_attach_failed');
    expect(errors[0]).toContain('SecretBoom');
    expect(errors[0]).not.toContain('private detail');
  });
  it('does nothing without a catalog', () => {
    const server = { server: { registerCapabilities: vi.fn() } };
    register(server as never, null);
    expect(server.server.registerCapabilities).not.toHaveBeenCalled();
  });
});
