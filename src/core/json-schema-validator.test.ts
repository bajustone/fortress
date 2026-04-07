import type { JSONSchema } from './json-schema';
import { describe, expect, it } from 'vitest';
import { validateJsonSchema } from './json-schema-validator';

function expectValid(schema: JSONSchema, data: unknown): void {
  expect(validateJsonSchema(schema, data)).toEqual([]);
}

function expectInvalid(schema: JSONSchema, data: unknown, count = 1): void {
  const issues = validateJsonSchema(schema, data);
  expect(issues.length).toBeGreaterThanOrEqual(count);
}

describe('json-schema-validator', () => {
  describe('type checks', () => {
    it('validates string type', () => {
      expectValid({ type: 'string' }, 'hello');
      expectInvalid({ type: 'string' }, 123);
      expectInvalid({ type: 'string' }, true);
    });

    it('validates number type', () => {
      expectValid({ type: 'number' }, 42);
      expectValid({ type: 'number' }, 3.14);
      expectInvalid({ type: 'number' }, 'hello');
    });

    it('validates integer type', () => {
      expectValid({ type: 'integer' }, 42);
      expectInvalid({ type: 'integer' }, 3.14);
      expectInvalid({ type: 'integer' }, 'hello');
    });

    it('validates boolean type', () => {
      expectValid({ type: 'boolean' }, true);
      expectValid({ type: 'boolean' }, false);
      expectInvalid({ type: 'boolean' }, 'true');
    });

    it('validates object type', () => {
      expectValid({ type: 'object' }, {});
      expectInvalid({ type: 'object' }, []);
      expectInvalid({ type: 'object' }, 'hello');
    });

    it('validates array type', () => {
      expectValid({ type: 'array' }, []);
      expectValid({ type: 'array' }, [1, 2]);
      expectInvalid({ type: 'array' }, {});
    });

    it('validates null type', () => {
      expectValid({ type: 'null' }, null);
      expectInvalid({ type: 'null' }, undefined);
    });
  });

  describe('nullable', () => {
    it('accepts null when nullable', () => {
      expectValid({ type: 'string', nullable: true }, null);
      expectValid({ type: 'string', nullable: true }, 'hello');
    });

    it('rejects null when not nullable', () => {
      expectInvalid({ type: 'string' }, null);
    });
  });

  describe('enum', () => {
    it('validates enum values', () => {
      const schema: JSONSchema = { enum: ['a', 'b', 'c'] };
      expectValid(schema, 'a');
      expectValid(schema, 'b');
      expectInvalid(schema, 'd');
    });
  });

  describe('string constraints', () => {
    it('validates minLength', () => {
      expectValid({ type: 'string', minLength: 3 }, 'abc');
      expectInvalid({ type: 'string', minLength: 3 }, 'ab');
    });

    it('validates maxLength', () => {
      expectValid({ type: 'string', maxLength: 3 }, 'abc');
      expectInvalid({ type: 'string', maxLength: 3 }, 'abcd');
    });

    it('validates pattern', () => {
      expectValid({ type: 'string', pattern: '^[a-z]+$' }, 'abc');
      expectInvalid({ type: 'string', pattern: '^[a-z]+$' }, 'ABC');
    });
  });

  describe('number constraints', () => {
    it('validates minimum', () => {
      expectValid({ type: 'number', minimum: 0 }, 0);
      expectValid({ type: 'number', minimum: 0 }, 5);
      expectInvalid({ type: 'number', minimum: 0 }, -1);
    });

    it('validates maximum', () => {
      expectValid({ type: 'number', maximum: 10 }, 10);
      expectInvalid({ type: 'number', maximum: 10 }, 11);
    });
  });

  describe('objects', () => {
    it('validates required fields', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: { name: { type: 'string' }, age: { type: 'integer' } },
        required: ['name', 'age'],
      };
      expectValid(schema, { name: 'Alice', age: 30 });
      expectInvalid(schema, { name: 'Alice' });
      expectInvalid(schema, {}, 2);
    });

    it('validates property types', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: { name: { type: 'string' } },
      };
      expectValid(schema, { name: 'Alice' });
      expectInvalid(schema, { name: 123 });
    });

    it('validates nested objects', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          address: {
            type: 'object',
            properties: { city: { type: 'string' } },
            required: ['city'],
          },
        },
        required: ['address'],
      };
      expectValid(schema, { address: { city: 'NYC' } });
      expectInvalid(schema, { address: {} });
    });

    it('allows extra properties by default', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: { name: { type: 'string' } },
      };
      expectValid(schema, { name: 'Alice', extra: true });
    });
  });

  describe('arrays', () => {
    it('validates array items', () => {
      const schema: JSONSchema = { type: 'array', items: { type: 'integer' } };
      expectValid(schema, [1, 2, 3]);
      expectInvalid(schema, [1, 'two', 3]);
    });

    it('validates nested arrays', () => {
      const schema: JSONSchema = {
        type: 'array',
        items: { type: 'array', items: { type: 'string' } },
      };
      expectValid(schema, [['a'], ['b', 'c']]);
      expectInvalid(schema, [['a'], [1]]);
    });
  });

  describe('oneOf', () => {
    it('validates oneOf (exactly one match)', () => {
      const schema: JSONSchema = {
        oneOf: [{ type: 'string' }, { type: 'integer' }],
      };
      expectValid(schema, 'hello');
      expectValid(schema, 42);
      expectInvalid(schema, true);
    });
  });

  describe('anyOf', () => {
    it('validates anyOf (at least one match)', () => {
      const schema: JSONSchema = {
        anyOf: [{ type: 'string' }, { type: 'integer' }],
      };
      expectValid(schema, 'hello');
      expectValid(schema, 42);
      expectInvalid(schema, true);
    });
  });

  describe('error format', () => {
    it('returns issues with path', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: { name: { type: 'string' } },
        required: ['name'],
      };
      const issues = validateJsonSchema(schema, {});
      expect(issues[0].path).toEqual([{ key: 'name' }]);
      expect(issues[0].message).toContain('Missing required field');
    });

    it('returns nested paths', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          user: {
            type: 'object',
            properties: { name: { type: 'string' } },
          },
        },
      };
      const issues = validateJsonSchema(schema, { user: { name: 123 } });
      expect(issues[0].path).toEqual([{ key: 'user' }, { key: 'name' }]);
    });
  });
});
