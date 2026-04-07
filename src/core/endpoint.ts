import type { JSONSchema } from './json-schema';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

export type SecurityRequirement = 'bearer' | 'basic' | 'apiKey' | 'none';

export interface EndpointPermission {
  resource: string;
  action: string;
}

export interface EndpointMeta {
  summary: string;
  description?: string;
  tags?: string[];
  security?: SecurityRequirement[];
  deprecated?: boolean;
  /** IAM permission required to access this endpoint. Enforced by RBAC middleware. */
  permission?: EndpointPermission;
}

export interface EndpointInput {
  body?: JSONSchema;
  query?: JSONSchema;
  params?: JSONSchema;
}

export interface EndpointResponse {
  description: string;
  schema?: JSONSchema;
}

export interface EndpointDefinition {
  method: HttpMethod;
  path: string;
  handler: string;
  meta?: EndpointMeta;
  input?: EndpointInput;
  responses?: Record<number, EndpointResponse>;
}

/**
 * Component schemas are reusable JSON Schema definitions
 * that endpoints reference via $ref (e.g., '#/components/schemas/User').
 */
export interface ComponentSchemas {
  [name: string]: JSONSchema;
}
