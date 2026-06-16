/**
 * Public types for the webhook plugin v1 (custom events + Bring-Your-Own-Queue).
 *
 * @module
 */

import type { FetchFn } from '@bajustone/fetcher';
import type { StandardSchemaV1 } from '../../core/standard-schema';
import type { RetryMode } from './delivery';
import type { WebhookQueue } from './queue/types';

export type { RetryMode } from './delivery';
export type { WebhookQueue, WebhookQueueContext, WebhookQueueJob } from './queue/types';

/** A fortress lifecycle hook a built-in event auto-emits from. */
export type BuiltinEventSource = 'afterLogin' | 'onLoginFailure' | 'beforeLogout' | 'afterRegister' | 'afterTokenRefresh';

/**
 * Declares an event consumers (or the built-ins) can emit. Built-in auth events
 * and user-defined events share this one shape and the same emit path.
 */
export interface WebhookEventDeclaration<S extends StandardSchemaV1 = StandardSchemaV1> {
  /** Dot-cased event name, e.g. `auth.login.success` or `order.paid`. */
  name: string;
  description?: string;
  /** Standard Schema V1 validator (fortress builder, fetcher builder, Zod, …); the payload is validated at `emit()` time. */
  schema?: S;
  /** If set, the plugin auto-emits this event from the named fortress hook. */
  source?: BuiltinEventSource;
}

/** A registered delivery endpoint. `secret` is redacted from `listEndpoints()`. */
export interface WebhookEndpoint {
  id: string;
  url: string;
  events: string; // JSON array of event names
  secret: string;
  isActive: boolean;
  deactivatedReason: string | null;
  consecutiveFailures: number;
  createdAt: Date;
}

/** A persisted delivery attempt row — the transactional outbox record. */
export interface WebhookDelivery {
  id: string;
  endpointId: string;
  eventType: string;
  payload: string; // JSON
  status: 'pending' | 'success' | 'failed';
  attempts: number;
  idempotencyKey: string | null;
  lastAttemptAt: Date | null;
  nextRetryAt: Date | null;
  responseStatus: number | null;
  responseBody: string | null;
  errorKind: string | null;
  createdAt: Date;
}

/** Delivery tuning + observability seams. */
export interface WebhookDeliveryConfig {
  /** Per-attempt timeout (ms). Default 10_000. */
  timeoutMs?: number;
  /** Who owns retries. Default `'pluginScheduled'`. */
  retry?: RetryMode;
  /** Statuses that permanently deactivate an endpoint. Default `[404, 410, 421]`. */
  permanentStatuses?: number[];
  /** Consecutive failures before the circuit breaker deactivates an endpoint. Default 15. */
  maxConsecutiveFailures?: number;
  /** Called on a terminal `failed` delivery — the DLQ/alert seam. */
  onDeliveryFailed?: (delivery: WebhookDelivery) => void | Promise<void>;
  /** Called when an endpoint is auto-deactivated (permanent status or circuit breaker). */
  onEndpointDeactivated?: (endpoint: WebhookEndpoint, reason: string) => void | Promise<void>;
  /**
   * Override the delivery transport (a fetcher `FetchFn`). Defaults to the
   * SSRF-guarded `ssrfSafeFetch()`. Use for custom transports or to intercept
   * delivery in tests — **bypasses the SSRF guard**, so only override when you
   * control the targets.
   */
  fetch?: FetchFn;
}

/** Options for `emit()`. */
export interface EmitOptions {
  /** Dedup key — a second `emit` with the same `(endpoint, idempotencyKey)` is a no-op. */
  idempotencyKey?: string;
}

/** Options for `registerEndpoint()`. */
export interface RegisterEndpointOptions {
  /** Signing secret. If omitted, a CSPRNG secret is generated and returned once. */
  secret?: string;
}

/** Patch accepted by `updateEndpoint()`. */
export interface UpdateEndpointPatch {
  url?: string;
  events?: string[];
  isActive?: boolean;
}

/** An endpoint with `secret` removed — the shape returned by `listEndpoints()`/`updateEndpoint()`. */
export type RedactedWebhookEndpoint = Omit<WebhookEndpoint, 'secret'>;

export interface WebhookConfig {
  /** Event registry. Defaults to {@link import('./builtin-events').builtinEvents}(). */
  events?: WebhookEventDeclaration[];
  /** Delivery queue (BYOQ). Defaults to the dev-only `inMemoryQueue()`. */
  queue?: WebhookQueue;
  /** Maximum delivery retries. Default 5. */
  maxRetries?: number;
  /** Reject `emit()` payloads larger than this many bytes. Default 262144 (256 KB). */
  maxPayloadBytes?: number;
  delivery?: WebhookDeliveryConfig;
}

/** Distinct, catchable failure codes thrown by `emit()`. */
export type WebhookEmitErrorCode = 'unknown_event' | 'invalid_payload' | 'payload_too_large';

/** Thrown by `emit()` so callers can branch on `code` instead of string-matching. */
export class WebhookEmitError extends Error {
  readonly code: WebhookEmitErrorCode;
  constructor(code: WebhookEmitErrorCode, message: string) {
    super(message);
    this.name = 'WebhookEmitError';
    this.code = code;
  }
}

// `RetryMode` re-exported above is used by WebhookDeliveryConfig.
export type { StandardSchemaV1 };
