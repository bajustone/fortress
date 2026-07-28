import { describe, expect, it } from 'vitest';
import { authComponentSchemas, authEndpoints } from '../../core/auth/auth-endpoints';
import { createFortress } from '../../core/fortress';
import { toOpenAPI } from '../../core/openapi';
import { endpoint, obj, str } from '../../core/schema-builder';
import { oauth } from '../../plugins/oauth';
import { createTestAdapter } from '../../testing';
import { openapi } from './index';
import { buildOpenAPISpec } from './spec-builder';

const SECRET = 'openapi-test-secret-at-least-32-bytes!!';

function pathEndpoint(path: string, handler: string) {
  return endpoint('GET', path)
    .summary(`${handler} route`)
    .security('none')
    .response(200, 'ok', obj({ ok: str() }, 'ok'))
    .handler(handler)
    .build();
}

describe('spec-builder path parameters', () => {
  it('parses a hyphenated :param as one whole parameter name', () => {
    // The old `\w+` scan stopped at the hyphen and emitted 'item', disagreeing
    // with the router, which captures the whole segment as 'item-id'.
    const spec = buildOpenAPISpec([pathEndpoint('/items/:item-id', 'getItem')], {}, {
      title: 'T',
      version: '1.0.0',
    });
    expect(spec.paths['/items/{item-id}']).toBeDefined();
    const params = spec.paths['/items/{item-id}'].get.parameters;
    expect(params).toHaveLength(1);
    expect(params![0].name).toBe('item-id');
    expect(params![0].in).toBe('path');
  });

  it('rejects a literal brace segment the router matches verbatim', () => {
    // At runtime '/things/{id}' matches the literal text '{id}'. Emitting it as
    // an OpenAPI template would invent a parameter the route never declared.
    expect(() => buildOpenAPISpec([pathEndpoint('/things/{id}', 'getThing')], {}, {
      title: 'T',
      version: '1.0.0',
    })).toThrow(/literal segment '\{id\}'/);
  });

  it('rejects a wildcard segment the router expands but OpenAPI cannot express', () => {
    // '/files/*' serves '/files/report.pdf' at runtime. Emitting it verbatim
    // would document a literal '/files/*' path no client can call.
    expect(() => buildOpenAPISpec([pathEndpoint('/files/*', 'getFile')], {}, {
      title: 'T',
      version: '1.0.0',
    })).toThrow(/wildcard segment '\*'/);
  });

  it('rejects braces inside a :param suffix', () => {
    // The whole suffix is the parameter name, so '/:a{b}' would emit the
    // invalid path '/{a{b}}' and parameter 'a{b}' if braces were not rejected.
    expect(() => buildOpenAPISpec([pathEndpoint('/:a{b}', 'weird')], {}, {
      title: 'T',
      version: '1.0.0',
    })).toThrow(/path parameter ':a\{b\}' containing '\{' or '\}'/);
  });

  it('rejects a path that declares the same parameter twice', () => {
    // '/dup/:id/:id' is a duplicate (name, in) pair OpenAPI forbids; at runtime
    // the second capture silently overwrites the first.
    expect(() => buildOpenAPISpec([pathEndpoint('/dup/:id/:id', 'getDup')], {}, {
      title: 'T',
      version: '1.0.0',
    })).toThrow(/declares path parameter ':id' more than once/);
  });
});

describe('spec-builder', () => {
  it('builds a valid OpenAPI 3.1.0 spec', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test API',
      version: '1.0.0',
    });

    expect(spec.openapi).toBe('3.1.0');
    expect(spec.info.title).toBe('Test API');
    expect(spec.info.version).toBe('1.0.0');
    expect(spec.paths).toBeDefined();
    expect(spec.components.schemas).toBeDefined();
    expect(spec.components.securitySchemes).toBeDefined();
  });

  it('includes auth endpoints in paths', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test',
      version: '1.0.0',
    });

    expect(spec.paths['/auth/login']).toBeDefined();
    expect(spec.paths['/auth/login'].post).toBeDefined();
    expect(spec.paths['/auth/login'].post.summary).toBe('Login with credentials');
    expect(spec.paths['/auth/register']).toBeDefined();
    expect(spec.paths['/auth/refresh']).toBeDefined();
    expect(spec.paths['/auth/me']).toBeDefined();
    expect(spec.paths['/auth/sessions']).toBeDefined();
  });

  it('converts :param to {param} in paths', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test',
      version: '1.0.0',
    });

    expect(spec.paths['/auth/sessions/{id}']).toBeDefined();
    expect(spec.paths['/auth/sessions/{id}'].delete.parameters).toBeDefined();
    expect(spec.paths['/auth/sessions/{id}'].delete.parameters![0].name).toBe('id');
    expect(spec.paths['/auth/sessions/{id}'].delete.parameters![0].in).toBe('path');
  });

  it('includes request body schemas', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test',
      version: '1.0.0',
    });

    const loginOp = spec.paths['/auth/login'].post;
    expect(loginOp.requestBody).toBeDefined();
    expect(loginOp.requestBody!.content['application/json'].schema.properties).toHaveProperty('identifier');
    expect(loginOp.requestBody!.content['application/json'].schema.properties).toHaveProperty('password');
  });

  it('includes response schemas', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test',
      version: '1.0.0',
    });

    const loginOp = spec.paths['/auth/login'].post;
    expect(loginOp.responses['200']).toBeDefined();
    expect(loginOp.responses['200'].description).toBe('Login successful');
    expect(loginOp.responses['401']).toBeDefined();
  });

  it('includes component schemas', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test',
      version: '1.0.0',
    });

    expect(spec.components.schemas.User).toBeDefined();
    expect(spec.components.schemas.AuthResult).toBeDefined();
    expect(spec.components.schemas.ErrorResponse).toBeDefined();
    expect(spec.components.schemas.SessionInfo).toBeDefined();
  });

  it('includes security schemes only for used requirements', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test',
      version: '1.0.0',
    });

    // Auth endpoints use bearer and none
    expect(spec.components.securitySchemes.bearerAuth).toBeDefined();
    // No basic or apiKey used
    expect(spec.components.securitySchemes.basicAuth).toBeUndefined();
  });

  it('adds servers when provided', () => {
    const spec = buildOpenAPISpec([], {}, {
      title: 'Test',
      version: '1.0.0',
      servers: [{ url: 'https://api.example.com', description: 'Production' }],
    });

    expect(spec.servers).toHaveLength(1);
    expect(spec.servers![0].url).toBe('https://api.example.com');
  });

  it('handles endpoints without meta or responses', () => {
    const minimal = endpoint('GET', '/health').handler('health').build();
    const spec = buildOpenAPISpec([minimal], {}, { title: 'Test', version: '1.0.0' });

    expect(spec.paths['/health'].get).toBeDefined();
    expect(spec.paths['/health'].get.responses['200']).toBeDefined();
  });

  it('strips Standard Schema/runtime internals from embedded schemas', () => {
    const runtimeSchema = {
      'type': 'object',
      'properties': {
        name: { 'type': 'string', '~standard': { validate: () => ({ value: 'x' }) } },
      },
      'required': ['name'],
      '~standard': { validate: () => ({ value: {} }) },
      'extraFn': () => undefined,
      'undef': undefined,
    } as any;
    const ep = endpoint('POST', '/schools')
      .summary('Create school')
      .body(runtimeSchema)
      .response(201, 'Created', runtimeSchema)
      .handler('schools.create')
      .build();

    const spec = buildOpenAPISpec([ep], {}, { title: 'Test', version: '1.0.0' });
    const serialized = JSON.stringify(spec);
    expect(serialized).not.toContain('~standard');
    expect(serialized).not.toContain('extraFn');
    expect(spec.paths['/schools'].post.requestBody!.content['application/json'].schema).toEqual({
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    });
  });

  it('supports root tags and handler operationIds when requested', () => {
    const ep = endpoint('GET', '/api/v1/schools/:id')
      .summary('Get school')
      .params(obj({ id: str() }, 'id'))
      .response(200, 'OK')
      .handler('schools.get')
      .build();

    const spec = buildOpenAPISpec([ep], {}, {
      title: 'REB EdIT API',
      version: '0.0.0',
      tags: [{ name: 'Schools' }],
      operationId: 'handler',
    });

    expect(spec.tags).toEqual([{ name: 'Schools' }]);
    expect(spec.paths['/api/v1/schools/{id}'].get.operationId).toBe('schools.get');
  });
});

describe('standalone toOpenAPI helper', () => {
  it('builds a pure spec from endpoint definitions without a Fortress instance', () => {
    const school = endpoint('GET', '/api/v1/schools/:id')
      .summary('Get school')
      .tags('Schools')
      .security('none')
      .params(obj({ id: str() }, 'id'))
      .response(200, 'OK', obj({ data: str() }, 'data'))
      .handler('schools.get')
      .build();

    const spec = toOpenAPI([school], {
      title: 'REB EdIT API',
      version: '0.0.0',
      servers: [{ url: 'http://localhost:3001', description: 'Local development' }],
      tags: [{ name: 'Schools' }],
    });

    expect(spec.info.title).toBe('REB EdIT API');
    expect(spec.paths['/api/v1/schools/{id}'].get.operationId).toBe('schools.get');
    expect(spec.paths['/api/v1/schools/{id}'].get.responses['200'].content?.['application/json'].schema).toMatchObject({
      type: 'object',
      required: ['data'],
    });
  });
});

describe('openapi plugin', () => {
  it('registers as a fortress plugin', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi()],
    });

    expect(fortress.plugins.openapi).toBeDefined();
    expect(fortress.plugins.openapi.generateSpec).toBeTypeOf('function');
    expect(fortress.plugins.openapi.getSpec).toBeTypeOf('function');
    expect(fortress.plugins.openapi.getUI).toBeTypeOf('function');
  });

  it('generates spec with all core endpoints', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi({ title: 'My API', version: '2.0.0' })],
    });

    const spec = await fortress.plugins.openapi.generateSpec();
    expect(spec.info.title).toBe('My API');
    expect(spec.info.version).toBe('2.0.0');
    expect(spec.paths['/auth/login']).toBeDefined();
    expect(spec.paths['/iam/roles']).toBeDefined();
  });

  it('includes plugin routes in spec', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [
        oauth({ issuerUrl: 'https://auth.example.com' }),
        openapi(),
      ],
    });

    const spec = await fortress.plugins.openapi.generateSpec();
    expect(spec.paths['/oauth/token']).toBeDefined();
    expect(spec.paths['/oauth/introspect']).toBeDefined();
    expect(spec.paths['/oauth/userinfo']).toBeDefined();
  });

  it('includes top-level host routes in spec', async () => {
    const hostEndpoint = endpoint('GET', '/api/v1/schools')
      .summary('List schools')
      .tags('Schools')
      .security('none')
      .response(200, 'OK')
      .handler('schools.list')
      .build();
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      routes: { listSchools: hostEndpoint },
      plugins: [openapi({ includeCoreAuth: false, includeCoreIam: false, operationId: 'handler' })],
    });

    const spec = await fortress.plugins.openapi.generateSpec();
    expect(spec.paths['/api/v1/schools']).toBeDefined();
    expect(spec.paths['/api/v1/schools'].get.operationId).toBe('schools.list');
  });

  it('excludes core auth when configured', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi({ includeCoreAuth: false })],
    });

    const spec = await fortress.plugins.openapi.generateSpec();
    expect(spec.paths['/auth/login']).toBeUndefined();
    // IAM should still be there
    expect(spec.paths['/iam/roles']).toBeDefined();
  });

  it('excludes core IAM when configured', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi({ includeCoreIam: false })],
    });

    const spec = await fortress.plugins.openapi.generateSpec();
    expect(spec.paths['/iam/roles']).toBeUndefined();
    // Auth should still be there
    expect(spec.paths['/auth/login']).toBeDefined();
  });

  it('getUI returns Scalar HTML', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi()],
    });

    const html = fortress.plugins.openapi.getUI();
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('@scalar/api-reference');
    expect(html).toContain('./openapi.json');
  });

  it('getUI uses relative spec URL for prefix compatibility', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi({ specPath: '/docs/api.json', uiPath: '/docs/ui' })],
    });

    const html = fortress.plugins.openapi.getUI();
    expect(html).toContain('data-url="./api.json"');
  });

  it('getUI handles spec in parent directory', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi({ specPath: '/spec.json', uiPath: '/docs/ui' })],
    });

    const html = fortress.plugins.openapi.getUI();
    expect(html).toContain('data-url="../spec.json"');
  });

  it('fortress.endpoints includes all endpoint definitions', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [oauth({ issuerUrl: 'https://auth.example.com' }), openapi()],
    });

    // Should have auth + IAM + OAuth + OpenAPI endpoints
    expect(fortress.endpoints.length).toBeGreaterThan(20);

    const paths = fortress.endpoints.map(e => e.path);
    expect(paths).toContain('/auth/login');
    expect(paths).toContain('/iam/roles');
    expect(paths).toContain('/oauth/token');
    expect(paths).toContain('/openapi.json');
  });
});

describe('openapi resource/action enum enrichment', () => {
  async function seedResources(db: ReturnType<typeof createTestAdapter>): Promise<void> {
    await db.create({ model: 'resource', data: { name: 'students', description: 'Student records' } });
    await db.create({ model: 'resource', data: { name: 'posts', description: 'Blog posts' } });
    await db.create({ model: 'permission', data: { resource: 'students', action: 'read', effect: 'ALLOW', description: 'read students' } });
    await db.create({ model: 'permission', data: { resource: 'students', action: 'write', effect: 'ALLOW', description: 'write students' } });
    await db.create({ model: 'permission', data: { resource: 'students', action: 'delete', effect: 'ALLOW', description: 'delete students' } });
    await db.create({ model: 'permission', data: { resource: 'posts', action: 'read', effect: 'ALLOW', description: 'read posts' } });
    await db.create({ model: 'permission', data: { resource: 'posts', action: 'publish', effect: 'ALLOW', description: 'publish posts' } });
  }

  it('builds oneOf discriminated unions for Permission and PermissionInput', async () => {
    const db = createTestAdapter();
    await seedResources(db);

    const fortress = createFortress({
      jwt: { key: SECRET },
      database: db,
      plugins: [openapi()],
    });

    const spec = await fortress.plugins.openapi.generateSpec();

    // Permission should be a oneOf with per-resource branches
    const permission = spec.components.schemas.Permission;
    expect(permission.oneOf).toBeDefined();
    expect(permission.oneOf).toHaveLength(2);

    // Each branch should have const resource and enum actions
    const studentsBranch = permission.oneOf!.find(b => b.properties?.resource?.const === 'students');
    expect(studentsBranch).toBeDefined();
    expect(studentsBranch!.properties!.action.enum).toEqual(['read', 'write', 'delete']);
    expect(studentsBranch!.properties!.effect!.enum).toEqual(['ALLOW', 'DENY']);
    expect(studentsBranch!.required).toContain('id');

    const postsBranch = permission.oneOf!.find(b => b.properties?.resource?.const === 'posts');
    expect(postsBranch).toBeDefined();
    expect(postsBranch!.properties!.action.enum).toEqual(['read', 'publish']);

    // PermissionInput should also be oneOf but without id
    const permInput = spec.components.schemas.PermissionInput;
    expect(permInput.oneOf).toBeDefined();
    expect(permInput.oneOf).toHaveLength(2);

    const inputBranch = permInput.oneOf!.find(b => b.properties?.resource?.const === 'students');
    expect(inputBranch).toBeDefined();
    expect(inputBranch!.required).not.toContain('id');
    expect(inputBranch!.properties!.action.enum).toEqual(['read', 'write', 'delete']);
  });

  it('adds flat enums to /iam/check inline body', async () => {
    const db = createTestAdapter();
    await seedResources(db);

    const fortress = createFortress({
      jwt: { key: SECRET },
      database: db,
      plugins: [openapi()],
    });

    const spec = await fortress.plugins.openapi.generateSpec();
    const checkOp = spec.paths['/iam/check']?.post;
    expect(checkOp).toBeDefined();

    // The body is a `oneOf` of the subject and legacy user forms; both
    // branches must document the same enums.
    const bodySchema = checkOp.requestBody!.content['application/json'].schema;
    expect(bodySchema.oneOf).toHaveLength(2);
    for (const branch of bodySchema.oneOf!) {
      expect(branch.properties!.resource.enum).toEqual(['posts', 'students']);
      expect(branch.properties!.action.enum).toEqual(['delete', 'publish', 'read', 'write']);
    }
  });

  it('falls back to plain strings when no resources are registered', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi()],
    });

    const spec = await fortress.plugins.openapi.generateSpec();

    // Should have the original static schemas, not oneOf
    const permission = spec.components.schemas.Permission;
    expect(permission.oneOf).toBeUndefined();
    expect(permission.properties?.resource?.type).toBe('string');
    expect(permission.properties?.resource?.enum).toBeUndefined();
  });
});
