/**
 * JSON Schema types (draft 2020-12 subset).
 *
 * Fortress uses JSON Schema as the universal format for endpoint definitions.
 * OpenAPI 3.1 uses JSON Schema natively, so conversion is trivial.
 * Consumers can convert to Zod, Valibot, TypeBox, etc.
 */
export interface JSONSchema {
  type?: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object' | 'null';
  properties?: Record<string, JSONSchema>;
  required?: string[];
  items?: JSONSchema;
  enum?: (string | number | boolean | null)[];
  format?: string;
  description?: string;
  default?: unknown;
  nullable?: boolean;
  oneOf?: JSONSchema[];
  anyOf?: JSONSchema[];
  allOf?: JSONSchema[];
  $ref?: string;
  additionalProperties?: boolean | JSONSchema;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  title?: string;
}
