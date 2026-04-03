import { describe, expect, it } from 'vitest';

import { generateResourceTypes } from './resource-sync';

describe('generateResourceTypes', () => {
  it('generates TypeScript types from resource definitions', () => {
    const types = generateResourceTypes({
      resources: {
        user: { actions: ['create', 'read', 'update', 'delete'] },
        post: { actions: ['create', 'read', 'publish'] },
      },
    });

    expect(types).toContain('\'user\'');
    expect(types).toContain('\'post\'');
    expect(types).toContain('\'create\' | \'read\' | \'update\' | \'delete\'');
    expect(types).toContain('\'create\' | \'read\' | \'publish\'');
    expect(types).toContain('FortressResource');
    expect(types).toContain('FortressAction');
  });

  it('handles empty resources', () => {
    const types = generateResourceTypes({ resources: {} });
    expect(types).toContain('never');
  });

  it('handles single resource', () => {
    const types = generateResourceTypes({
      resources: {
        invoice: { actions: ['create', 'void'] },
      },
    });

    expect(types).toContain('\'invoice\'');
    expect(types).toContain('\'create\' | \'void\'');
  });
});
