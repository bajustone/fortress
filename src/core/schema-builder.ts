import type { EndpointDefinition, EndpointResponse, HttpMethod, SecurityRequirement } from './endpoint';
import type { JSONSchema } from './json-schema';

// ── Schema Builders ─────────────────────────────────────────────────

export function str(description?: string): JSONSchema {
  const s: JSONSchema = { type: 'string' };
  if (description)
    s.description = description;
  return s;
}

export function num(description?: string): JSONSchema {
  const s: JSONSchema = { type: 'number' };
  if (description)
    s.description = description;
  return s;
}

export function int(description?: string): JSONSchema {
  const s: JSONSchema = { type: 'integer' };
  if (description)
    s.description = description;
  return s;
}

export function bool(description?: string): JSONSchema {
  const s: JSONSchema = { type: 'boolean' };
  if (description)
    s.description = description;
  return s;
}

export function arr(items: JSONSchema, description?: string): JSONSchema {
  const s: JSONSchema = { type: 'array', items };
  if (description)
    s.description = description;
  return s;
}

export function obj(
  properties: Record<string, JSONSchema>,
  ...required: string[]
): JSONSchema {
  const s: JSONSchema = { type: 'object', properties };
  if (required.length > 0)
    s.required = required;
  return s;
}

export function nullable(schema: JSONSchema): JSONSchema {
  return { ...schema, nullable: true };
}

export function oneOf(...schemas: JSONSchema[]): JSONSchema {
  return { oneOf: schemas };
}

export function anyOf(...schemas: JSONSchema[]): JSONSchema {
  return { anyOf: schemas };
}

export function ref(name: string): JSONSchema {
  return { $ref: `#/components/schemas/${name}` };
}

export function enums<T extends string | number>(...values: T[]): JSONSchema {
  return { enum: values };
}

export function strFormat(format: string, description?: string): JSONSchema {
  const s: JSONSchema = { type: 'string', format };
  if (description)
    s.description = description;
  return s;
}

// ── Endpoint Builder ────────────────────────────────────────────────

export class EndpointBuilder {
  private _method: HttpMethod;
  private _path: string;
  private _handler = '';
  private _summary = '';
  private _description?: string;
  private _tags: string[] = [];
  private _security: SecurityRequirement[] = [];
  private _deprecated = false;
  private _permission?: { resource: string; action: string };
  private _body?: JSONSchema;
  private _query?: JSONSchema;
  private _params?: JSONSchema;
  private _responses: Record<number, EndpointResponse> = {};

  constructor(method: HttpMethod, path: string) {
    this._method = method;
    this._path = path;
  }

  summary(s: string): this {
    this._summary = s;
    return this;
  }

  description(s: string): this {
    this._description = s;
    return this;
  }

  tags(...t: string[]): this {
    this._tags.push(...t);
    return this;
  }

  security(...s: SecurityRequirement[]): this {
    this._security.push(...s);
    return this;
  }

  deprecated(): this {
    this._deprecated = true;
    return this;
  }

  permission(resource: string, action: string): this {
    this._permission = { resource, action };
    return this;
  }

  body(schema: JSONSchema): this {
    this._body = schema;
    return this;
  }

  query(schema: JSONSchema): this {
    this._query = schema;
    return this;
  }

  params(schema: JSONSchema): this {
    this._params = schema;
    return this;
  }

  response(status: number, description: string, schema?: JSONSchema): this {
    this._responses[status] = { description, schema };
    return this;
  }

  handler(name: string): this {
    this._handler = name;
    return this;
  }

  build(): EndpointDefinition {
    const def: EndpointDefinition = {
      method: this._method,
      path: this._path,
      handler: this._handler,
    };

    if (this._summary || this._tags.length > 0 || this._security.length > 0 || this._description || this._deprecated || this._permission) {
      def.meta = {
        summary: this._summary,
        ...(this._description && { description: this._description }),
        ...(this._tags.length > 0 && { tags: this._tags }),
        ...(this._security.length > 0 && { security: this._security }),
        ...(this._deprecated && { deprecated: true }),
        ...(this._permission && { permission: this._permission }),
      };
    }

    if (this._body || this._query || this._params) {
      def.input = {};
      if (this._body)
        def.input.body = this._body;
      if (this._query)
        def.input.query = this._query;
      if (this._params)
        def.input.params = this._params;
    }

    if (Object.keys(this._responses).length > 0) {
      def.responses = this._responses;
    }

    return def;
  }
}

export function endpoint(method: HttpMethod, path: string): EndpointBuilder {
  return new EndpointBuilder(method, path);
}
