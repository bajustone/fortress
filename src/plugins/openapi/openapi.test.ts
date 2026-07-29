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

function requireValue<T>(value: T | undefined, description: string): T {
  if (value === undefined)
    throw new Error(`Expected ${description}`);
  return value;
}

function requireRecord<T>(record: Record<string, T>, key: string, description: string): T {
  return requireValue(record[key], description);
}

function requireAt<T>(values: readonly T[], index: number, description: string): T {
  return requireValue(values[index], description);
}

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
    const itemPath = requireRecord(spec.paths, '/items/{item-id}', 'path /items/{item-id}');
    const itemOperation = requireRecord(itemPath, 'get', 'GET operation for /items/{item-id}');
    const params = requireValue(itemOperation.parameters, 'path parameters for /items/{item-id}');
    expect(params).toHaveLength(1);
    const parameter = requireAt(params, 0, 'first path parameter for /items/{item-id}');
    expect(parameter.name).toBe('item-id');
    expect(parameter.in).toBe('path');
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

    const loginPath = requireRecord(spec.paths, '/auth/login', 'path /auth/login');
    const loginOperation = requireRecord(loginPath, 'post', 'POST operation for /auth/login');
    expect(loginOperation.summary).toBe('Login with credentials');
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

    const sessionPath = requireRecord(spec.paths, '/auth/sessions/{id}', 'path /auth/sessions/{id}');
    const sessionOperation = requireRecord(sessionPath, 'delete', 'DELETE operation for /auth/sessions/{id}');
    const parameters = requireValue(sessionOperation.parameters, 'path parameters for /auth/sessions/{id}');
    const parameter = requireAt(parameters, 0, 'first path parameter for /auth/sessions/{id}');
    expect(parameter.name).toBe('id');
    expect(parameter.in).toBe('path');
  });

  it('includes request body schemas', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test',
      version: '1.0.0',
    });

    const loginPath = requireRecord(spec.paths, '/auth/login', 'path /auth/login');
    const loginOp = requireRecord(loginPath, 'post', 'POST operation for /auth/login');
    const requestBody = requireValue(loginOp.requestBody, 'request body for /auth/login');
    const mediaType = requireRecord(requestBody.content, 'application/json', 'JSON request body for /auth/login');
    const properties = requireValue(mediaType.schema.properties, 'request properties for /auth/login');
    expect(properties).toHaveProperty('identifier');
    expect(properties).toHaveProperty('password');
  });

  it('includes response schemas', () => {
    const spec = buildOpenAPISpec(Object.values(authEndpoints), authComponentSchemas, {
      title: 'Test',
      version: '1.0.0',
    });

    const loginPath = requireRecord(spec.paths, '/auth/login', 'path /auth/login');
    const loginOp = requireRecord(loginPath, 'post', 'POST operation for /auth/login');
    const successResponse = requireRecord(loginOp.responses, '200', '200 response for /auth/login');
    expect(successResponse.description).toBe('Login successful');
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

    const servers = requireValue(spec.servers, 'OpenAPI servers');
    expect(servers).toHaveLength(1);
    expect(requireAt(servers, 0, 'first OpenAPI server').url).toBe('https://api.example.com');
  });

  it('handles endpoints without meta or responses', () => {
    const minimal = endpoint('GET', '/health').handler('health').build();
    const spec = buildOpenAPISpec([minimal], {}, { title: 'Test', version: '1.0.0' });

    const healthPath = requireRecord(spec.paths, '/health', 'path /health');
    const healthOperation = requireRecord(healthPath, 'get', 'GET operation for /health');
    expect(healthOperation.responses['200']).toBeDefined();
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
    const schoolsPath = requireRecord(spec.paths, '/schools', 'path /schools');
    const schoolsOperation = requireRecord(schoolsPath, 'post', 'POST operation for /schools');
    const requestBody = requireValue(schoolsOperation.requestBody, 'request body for /schools');
    const mediaType = requireRecord(requestBody.content, 'application/json', 'JSON request body for /schools');
    expect(mediaType.schema).toEqual({
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
    const schoolPath = requireRecord(spec.paths, '/api/v1/schools/{id}', 'path /api/v1/schools/{id}');
    expect(requireRecord(schoolPath, 'get', 'GET operation for /api/v1/schools/{id}').operationId).toBe('schools.get');
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
    const schoolPath = requireRecord(spec.paths, '/api/v1/schools/{id}', 'path /api/v1/schools/{id}');
    const schoolOperation = requireRecord(schoolPath, 'get', 'GET operation for /api/v1/schools/{id}');
    expect(schoolOperation.operationId).toBe('schools.get');
    const successResponse = requireRecord(schoolOperation.responses, '200', '200 response for /api/v1/schools/{id}');
    const content = requireValue(successResponse.content, 'response content for /api/v1/schools/{id}');
    expect(requireRecord(content, 'application/json', 'JSON response for /api/v1/schools/{id}').schema).toMatchObject({
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
    const schoolsPath = requireRecord(spec.paths, '/api/v1/schools', 'path /api/v1/schools');
    expect(requireRecord(schoolsPath, 'get', 'GET operation for /api/v1/schools').operationId).toBe('schools.list');
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

    // Permission should be a oneOf with per-resource branches.
    const permission = requireRecord(spec.components.schemas, 'Permission', 'Permission component schema');
    const permissionBranches = requireValue(permission.oneOf, 'Permission oneOf branches');
    expect(permissionBranches).toHaveLength(2);

    // Each branch should have const resource and enum actions.
    const studentsBranch = requireValue(
      permissionBranches.find(branch => branch.properties?.resource?.const === 'students'),
      'students Permission branch',
    );
    const studentProperties = requireValue(studentsBranch.properties, 'students Permission properties');
    expect(requireRecord(studentProperties, 'action', 'students Permission action property').enum).toEqual(['read', 'write', 'delete']);
    expect(requireRecord(studentProperties, 'effect', 'students Permission effect property').enum).toEqual(['ALLOW', 'DENY']);
    expect(studentsBranch.required).toContain('id');

    const postsBranch = requireValue(
      permissionBranches.find(branch => branch.properties?.resource?.const === 'posts'),
      'posts Permission branch',
    );
    const postProperties = requireValue(postsBranch.properties, 'posts Permission properties');
    expect(requireRecord(postProperties, 'action', 'posts Permission action property').enum).toEqual(['read', 'publish']);

    // PermissionInput should also be oneOf but without id.
    const permInput = requireRecord(spec.components.schemas, 'PermissionInput', 'PermissionInput component schema');
    const inputBranches = requireValue(permInput.oneOf, 'PermissionInput oneOf branches');
    expect(inputBranches).toHaveLength(2);

    const inputBranch = requireValue(
      inputBranches.find(branch => branch.properties?.resource?.const === 'students'),
      'students PermissionInput branch',
    );
    expect(inputBranch.required).not.toContain('id');
    const inputProperties = requireValue(inputBranch.properties, 'students PermissionInput properties');
    expect(requireRecord(inputProperties, 'action', 'students PermissionInput action property').enum).toEqual(['read', 'write', 'delete']);
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
    const checkPath = requireRecord(spec.paths, '/iam/check', 'path /iam/check');
    const checkOp = requireRecord(checkPath, 'post', 'POST operation for /iam/check');

    // The body is a `oneOf` of the subject and legacy user forms; both
    // branches must document the same enums.
    const requestBody = requireValue(checkOp.requestBody, 'request body for /iam/check');
    const mediaType = requireRecord(requestBody.content, 'application/json', 'JSON request body for /iam/check');
    const branches = requireValue(mediaType.schema.oneOf, '/iam/check body oneOf branches');
    expect(branches).toHaveLength(2);
    for (const branch of branches) {
      const properties = requireValue(branch.properties, '/iam/check body branch properties');
      expect(requireRecord(properties, 'resource', '/iam/check resource property').enum).toEqual(['posts', 'students']);
      expect(requireRecord(properties, 'action', '/iam/check action property').enum).toEqual(['delete', 'publish', 'read', 'write']);
    }
  });

  it('falls back to plain strings when no resources are registered', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [openapi()],
    });

    const spec = await fortress.plugins.openapi.generateSpec();

    // Should have the original static schemas, not oneOf.
    const permission = requireRecord(spec.components.schemas, 'Permission', 'Permission component schema');
    expect(permission.oneOf).toBeUndefined();
    const properties = requireValue(permission.properties, 'Permission properties');
    const resource = requireRecord(properties, 'resource', 'Permission resource property');
    expect(resource.type).toBe('string');
    expect(resource.enum).toBeUndefined();
  });
});
