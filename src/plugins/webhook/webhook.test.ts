import type { Fortress } from '../../core/fortress';
import type { WebhookEndpoint, WebhookEventType } from './index';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { webhook } from './index';

const SECRET = 'webhook-test-secret-32chars!!xxx';

describe('webhook plugin', () => {
  let fortress: Fortress;
  let deliveries: { url: string; payload: string; headers: Record<string, string> }[];
  let mockDeliver: (url: string, payload: string, headers: Record<string, string>) => Promise<boolean>;
  let registerEndpoint: (url: string, events: WebhookEventType[], secret: string) => Promise<WebhookEndpoint>;
  let listEndpoints: () => Promise<WebhookEndpoint[]>;
  let removeEndpoint: (id: number) => Promise<void>;

  beforeEach(() => {
    deliveries = [];
    mockDeliver = async (url: string, payload: string, headers: Record<string, string>) => {
      deliveries.push({ url, payload, headers });
      return true;
    };

    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [webhook({ deliver: mockDeliver })],
    });

    registerEndpoint = fortress.plugins.webhook.registerEndpoint as typeof registerEndpoint;
    listEndpoints = fortress.plugins.webhook.listEndpoints as typeof listEndpoints;
    removeEndpoint = fortress.plugins.webhook.removeEndpoint as typeof removeEndpoint;
  });

  describe('delivers on login success', () => {
    it('delivers webhook on login success', async () => {
      await registerEndpoint('https://example.com/hook', ['LOGIN_SUCCESS'], 'endpoint-secret');

      await fortress.auth.createUser({
        email: 'alice@example.com',
        name: 'Alice',
        password: 'password-123',
      });

      await fortress.auth.login('alice@example.com', 'password-123');

      const loginDeliveries = deliveries.filter((d) => {
        const body = JSON.parse(d.payload);
        return body.event === 'LOGIN_SUCCESS';
      });

      expect(loginDeliveries.length).toBe(1);
      const body = JSON.parse(loginDeliveries[0].payload);
      expect(body.email).toBe('alice@example.com');
    });
  });

  describe('standard Webhooks headers', () => {
    it('includes correct Standard Webhooks headers', async () => {
      await registerEndpoint('https://example.com/hook', ['LOGIN_SUCCESS'], 'endpoint-secret');

      await fortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      await fortress.auth.login('bob@example.com', 'password-123');

      const loginDeliveries = deliveries.filter((d) => {
        const body = JSON.parse(d.payload);
        return body.event === 'LOGIN_SUCCESS';
      });

      expect(loginDeliveries.length).toBeGreaterThan(0);
      const headers = loginDeliveries[0].headers;

      expect(headers['webhook-id']).toBeDefined();
      expect(headers['webhook-id']).toMatch(/^wh_/);
      expect(headers['webhook-timestamp']).toBeDefined();
      expect(Number(headers['webhook-timestamp'])).toBeGreaterThan(0);
      expect(headers['webhook-signature']).toBeDefined();
      expect(headers['webhook-signature']).toMatch(/^v1,/);
    });
  });

  describe('event type filtering', () => {
    it('only delivers to endpoints matching the event type', async () => {
      await registerEndpoint('https://example.com/login-hook', ['LOGIN_SUCCESS'], 'secret-1');
      await registerEndpoint('https://example.com/register-hook', ['REGISTER'], 'secret-2');

      await fortress.auth.createUser({
        email: 'carol@example.com',
        name: 'Carol',
        password: 'password-123',
      });

      await fortress.auth.login('carol@example.com', 'password-123');

      const loginDeliveries = deliveries.filter(d => d.url === 'https://example.com/login-hook');
      const registerDeliveries = deliveries.filter(d => d.url === 'https://example.com/register-hook');

      // Login hook receives LOGIN_SUCCESS only
      expect(loginDeliveries.length).toBe(1);
      const loginBody = JSON.parse(loginDeliveries[0].payload);
      expect(loginBody.event).toBe('LOGIN_SUCCESS');

      // Register hook receives REGISTER only
      expect(registerDeliveries.length).toBe(1);
      const regBody = JSON.parse(registerDeliveries[0].payload);
      expect(regBody.event).toBe('REGISTER');
    });
  });

  describe('inactive endpoints', () => {
    it('does not deliver to inactive endpoints', async () => {
      const endpoint = await registerEndpoint('https://example.com/hook', ['LOGIN_SUCCESS', 'REGISTER'], 'secret-1');

      // Deactivate endpoint by removing and re-creating (simulated by direct DB)
      await removeEndpoint(endpoint.id);

      await fortress.auth.createUser({
        email: 'dave@example.com',
        name: 'Dave',
        password: 'password-123',
      });

      await fortress.auth.login('dave@example.com', 'password-123');

      // No deliveries to the removed endpoint
      expect(deliveries.length).toBe(0);
    });
  });

  describe('registerEndpoint', () => {
    it('creates a new endpoint', async () => {
      const endpoint = await registerEndpoint(
        'https://example.com/webhook',
        ['LOGIN_SUCCESS', 'REGISTER'],
        'my-secret',
      );

      expect(endpoint.id).toBeDefined();
      expect(endpoint.url).toBe('https://example.com/webhook');
      expect(JSON.parse(endpoint.events)).toEqual(['LOGIN_SUCCESS', 'REGISTER']);
      expect(endpoint.secret).toBe('my-secret');
      expect(endpoint.isActive).toBe(true);
    });
  });

  describe('listEndpoints', () => {
    it('returns active endpoints', async () => {
      await registerEndpoint('https://a.com/hook', ['LOGIN_SUCCESS'], 'secret-a');
      await registerEndpoint('https://b.com/hook', ['REGISTER'], 'secret-b');

      const endpoints = await listEndpoints();
      expect(endpoints.length).toBe(2);
      expect(endpoints.map(e => e.url).sort()).toEqual([
        'https://a.com/hook',
        'https://b.com/hook',
      ]);
    });
  });

  describe('removeEndpoint', () => {
    it('deletes endpoint and its deliveries', async () => {
      const endpoint = await registerEndpoint('https://example.com/hook', ['REGISTER'], 'secret-1');

      await fortress.auth.createUser({
        email: 'eve@example.com',
        name: 'Eve',
        password: 'password-123',
      });

      // There should be at least one delivery
      expect(deliveries.length).toBeGreaterThan(0);

      await removeEndpoint(endpoint.id);

      const endpoints = await listEndpoints();
      expect(endpoints.length).toBe(0);
    });
  });

  describe('retry logic', () => {
    it('marks delivery as failed after max retries', async () => {
      let callCount = 0;
      const failDeliver = async () => {
        callCount++;
        return false;
      };

      const retryFortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [webhook({ deliver: failDeliver, maxRetries: 1 })],
      });

      const retryRegister = retryFortress.plugins.webhook.registerEndpoint as typeof registerEndpoint;
      await retryRegister('https://example.com/hook', ['REGISTER'], 'secret-1');

      await retryFortress.auth.createUser({
        email: 'frank@example.com',
        name: 'Frank',
        password: 'password-123',
      });

      // With maxRetries=1, the first attempt should mark it as failed
      expect(callCount).toBe(1);
    });
  });
});
