import type { JSONSchema } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';

/** HTTP method an {@link EndpointDefinition} can declare. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

/** Authentication scheme required to call an endpoint. */
export type SecurityRequirement = 'bearer' | 'basic' | 'apiKey' | 'none';

/** A required IAM permission, expressed as a `(resource, action)` pair. */
export interface EndpointPermission {
  resource: string;
  action: string;
}

/** OpenAPI / IAM metadata attached to an {@link EndpointDefinition}. */
export interface EndpointMeta {
  summary: string;
  description?: string;
  tags?: string[];
  security?: SecurityRequirement[];
  deprecated?: boolean;
  /** IAM permission required to access this endpoint. Enforced by RBAC middleware. */
  permission?: EndpointPermission;
}

/** Request input declarations for an endpoint — JSON Schemas for OpenAPI plus Standard Schemas for runtime validation. */
export interface EndpointInput {
  /** JSON Schema for OpenAPI spec generation. */
  body?: JSONSchema;
  query?: JSONSchema;
  params?: JSONSchema;
  /** Standard Schema references for runtime validation (set by endpoint builder). */
  bodySchema?: StandardSchemaV1;
  querySchema?: StandardSchemaV1;
  paramsSchema?: StandardSchemaV1;
}

/** A single OpenAPI response definition (description plus optional JSON Schema). */
export interface EndpointResponse {
  description: string;
  schema?: JSONSchema;
}

/** Declarative description of one HTTP endpoint, including its handler key, OpenAPI metadata, input schemas, and responses. */
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
